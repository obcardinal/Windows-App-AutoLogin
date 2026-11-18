"""Build the unsigned executable for the macOS release workflow."""

import hashlib
import os
from pathlib import Path
import subprocess


def output(*command):
    return subprocess.check_output(command, text=True).strip()


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def toolchain_hash(roots):
    digest = hashlib.sha256()
    for label, root in roots:
        root = root.resolve(strict=True)
        entries = sorted(root.rglob("*")) if root.is_dir() else [root]
        for path in entries:
            if path.is_symlink():
                value = "link:" + os.readlink(path)
            elif path.is_file():
                value = file_hash(path)
            else:
                continue
            relative = path.relative_to(root)
            digest.update(f"{label}/{relative}\0{value}\0".encode())
    return digest.hexdigest()


def main():
    commit = output("git", "rev-parse", "HEAD")
    if commit != os.environ["GITHUB_SHA"] or output("git", "status", "--porcelain"):
        raise SystemExit("Release builds require a clean checkout of the dispatched commit")

    sysroot = Path(output("rustc", "--print", "sysroot"))
    sdk = Path(output("xcrun", "--sdk", "macosx", "--show-sdk-path"))
    native_tools = [(name, Path(output("xcrun", "--find", name))) for name in ("clang", "ld", "ar")]
    clang = native_tools[0][1]
    native_tools.extend([
        ("clang-resources", Path(output(str(clang), "-print-resource-dir"))),
        ("sdk", sdk),
    ])
    with subprocess.Popen(["git", "archive", "--format=tar", commit], stdout=subprocess.PIPE) as archive:
        materials = hashlib.sha256()
        for chunk in iter(lambda: archive.stdout.read(1024 * 1024), b""):
            materials.update(chunk)
        if archive.wait() != 0:
            raise SystemExit("Could not fingerprint the source tree containing Cargo.lock")

    environment = dict(os.environ, SDKROOT=str(sdk), CC=str(clang))
    environment.update({
        "WAAL_GITHUB_RELEASE_BUILD": "1",
        "WAAL_RELEASE_BUNDLE_ID": "com.obcardinal.WindowsAppAutoLogin",
        "WAAL_MACOS_TEAM_ID": "76C2QW8JV3",
        "WAAL_RELEASE_GIT_COMMIT": commit,
        "WAAL_RELEASE_GIT_TREE": output("git", "rev-parse", "HEAD^{tree}"),
        "WAAL_RELEASE_CARGO_VERSION": output("cargo", "--version").split()[1],
        "WAAL_RELEASE_RUSTC_VERSION": output("rustc", "--version").split()[1],
        "WAAL_RELEASE_CARGO_SHA256": file_hash(sysroot / "bin/cargo"),
        "WAAL_RELEASE_RUSTC_SHA256": file_hash(sysroot / "bin/rustc"),
        "WAAL_RELEASE_RUST_SYSROOT_SHA256": toolchain_hash([("rust", sysroot)]),
        "WAAL_RELEASE_NATIVE_TOOLCHAIN_SHA256": toolchain_hash(native_tools),
        "WAAL_RELEASE_MATERIALS_SHA256": materials.hexdigest(),
    })
    subprocess.run([
        "cargo", "build", "--release", "--frozen", "--target", "aarch64-apple-darwin",
        "--no-default-features", "--bin", "windows-app-autologin",
    ], env=environment, check=True)


if __name__ == "__main__":
    main()
