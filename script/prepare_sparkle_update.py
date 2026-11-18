#!/usr/bin/env python3
"""Prepare, but never publish, an immutable ZIP and signed Sparkle appcast."""

from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import html
import os
from pathlib import Path, PurePosixPath
import plistlib
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
import zipfile


ROOT = Path(__file__).resolve().parents[1]
BASE = "https://obcardinal.com/assets/downloads/windows-app-autologin/macos/"
TEAM = "76C2QW8JV3"
ACCOUNT = "windows-app-autologin"
SPARKLE = "http://www.andymatuschak.org/xml-namespaces/sparkle"
ATOM = "http://www.w3.org/2005/Atom"
CHANNELS = {
    "production": ("com.obcardinal.WindowsAppAutoLogin", BASE, "Windows App AutoLogin"),
    "development": ("obcardinal.windows-app-autologin", BASE + "development/", "Windows App AutoLogin Development"),
}
MAX_ARCHIVE = 1024 * 1024 * 1024
MAX_EXPANDED = 2 * MAX_ARCHIVE
MAX_FEED = 2 * 1024 * 1024
MAX_RELEASE_NOTES = 64 * 1024
ET.register_namespace("sparkle", SPARKLE)
ET.register_namespace("atom", ATOM)


class PreparationError(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PreparationError(message)


def run(args: list[str], *, timeout: int = 180) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    require(result.returncode == 0, f"{Path(args[0]).name} failed: {(result.stderr or result.stdout)[-4000:].strip()}")
    return result.stdout + result.stderr


def read_regular(path: Path, limit: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, f"Expected bounded regular file: {path}")
        data = stream.read(limit + 1)
    require(len(data) <= limit, f"File exceeds limit: {path}")
    return data


def version_tuple(value: str) -> tuple[int, int, int]:
    require(isinstance(value, str) and re.fullmatch(r"[0-9]{1,4}(?:\.[0-9]{1,2}){0,2}", value) is not None,
            "CFBundleVersion must contain one to three numeric components (4/2/2 digits)")
    parts = [int(part) for part in value.split(".")]
    return tuple((parts + [0, 0])[:3])


def validate_zip(path: Path) -> str:
    """Preflight before ditto, including the framework's legitimate symlinks."""
    with zipfile.ZipFile(path) as archive:
        entries = archive.infolist()
        require(0 < len(entries) <= 20000, "Unexpected ZIP member count")
        require(sum(entry.file_size for entry in entries) <= MAX_EXPANDED, "ZIP expands beyond the allowed size")
        names: set[str] = set()
        roots: set[str] = set()
        links: dict[str, str] = {}
        for entry in entries:
            name = entry.filename.rstrip("/")
            parts = name.split("/")
            require(name and "\0" not in name and "\\" not in name and not name.startswith("/")
                    and all(part not in ("", ".", "..") and ":" not in part for part in parts), "Unsafe ZIP member path")
            require(name.casefold() not in names, "ZIP contains duplicate or case-colliding members")
            names.add(name.casefold())
            kind = stat.S_IFMT(entry.external_attr >> 16)
            require(kind in (0, stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK), "ZIP contains a special file")
            require(not entry.flag_bits & 1, "Encrypted ZIP members are unsupported")
            if parts[0] == "__MACOSX":
                require(kind != stat.S_IFLNK, "ZIP metadata must not contain symbolic links")
                continue
            roots.add(parts[0])
            if kind == stat.S_IFLNK:
                require(entry.file_size <= 4096, "Oversized ZIP symbolic link")
                target = archive.read(entry).decode("utf-8")
                framework = parts[0] + "/Contents/Frameworks/Sparkle.framework/"
                resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
                require(name.startswith(framework) and not target.startswith("/") and "\0" not in target
                        and "\\" not in target and resolved.startswith(framework), "ZIP symbolic link escapes Sparkle.framework")
                links[name.casefold()] = resolved
        require(len(roots) == 1 and next(iter(roots)).endswith(".app"), "ZIP must contain exactly one top-level .app")
        for name in names:
            require(not any(str(parent).casefold() in links for parent in PurePosixPath(name).parents),
                    "ZIP contains entries beneath a symbolic link")
        return next(iter(roots))


def parse_metadata(output: str) -> dict[str, str]:
    records = [line for line in output.splitlines() if line.startswith("WAAL_BUILD_METADATA_V1;")]
    require(len(records) == 1, "Executable must contain exactly one WAAL build metadata record")
    fields: dict[str, str] = {}
    for field in records[0].split(";")[1:]:
        if not field:
            continue
        key, separator, value = field.partition("=")
        require(bool(separator) and key not in fields, "Malformed or duplicate build metadata field")
        fields[key] = value
    return fields


def validate_identity(info: dict, metadata: dict[str, str], channel: str, public_key: str) -> tuple[str, str]:
    identity, prefix, _ = CHANNELS[channel]
    require(info.get("CFBundleIdentifier") == identity, "Bundle identity does not match the selected channel")
    require(info.get("CFBundlePackageType") == "APPL" and info.get("CFBundleExecutable") == "windows-app-autologin",
            "Unexpected application executable or package type")
    require(info.get("SUFeedURL") == prefix + "appcast.xml", "Bundle feed does not match the selected channel")
    require(info.get("SUPublicEDKey") == public_key, "Bundle Sparkle public key does not match this project")
    require(info.get("WAALSparkleVersion") == "2.9.4", "Bundle must contain the pinned Sparkle version")
    build, version = info.get("CFBundleVersion"), info.get("CFBundleShortVersionString")
    version_tuple(build)
    require(isinstance(version, str) and re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9.-]+)?", version) is not None,
            "Invalid application marketing version")
    require(metadata.get("macos-bundle-id") == identity and metadata.get("target-os") == "macos"
            and metadata.get("profile") == "release", "Executable identity/platform/profile does not match the bundle")
    for flag in ("debug-assertions", "debug-fill", "dev-tools", "diagnostics-ui", "release-diagnostics"):
        require(metadata.get(flag) == "false", f"Update executable must disable {flag}")
    if channel == "production":
        require(metadata.get("publishable") == "true" and metadata.get("artifact-kind") == "release"
                and metadata.get("non-production-macos-identity") == "false", "Production rejects local or explicitly nonpublishable builds")
        require(metadata.get("macos-team-id") == TEAM, "Production executable has an unexpected Team ID")
        require(metadata.get("attestation", "").strip() not in ("", "none-local-shared-security-context")
                and metadata.get("producer-attribution", "").strip() not in ("", "unavailable-local-shared-security-context"),
                "Production requires separately authenticated build provenance")
        for key, value in info.items():
            if key.startswith("WAAL") and isinstance(value, str):
                require("publishable=false" not in value and "artifact-kind=local" not in value
                        and "artifact-kind=development" not in value, "Signed bundle metadata marks this artifact nonpublishable")
    else:
        require(metadata.get("non-production-macos-identity") == "true", "Development updates require the development runtime identity")
    return version, build


def validate_bundle(bundle: Path, channel: str, public_key: str) -> tuple[str, str]:
    info = plistlib.loads(read_regular(bundle / "Contents/Info.plist", 1024 * 1024))
    executable = bundle / "Contents/MacOS/windows-app-autologin"
    metadata = parse_metadata(run(["/usr/bin/strings", "-a", str(executable)]))
    version, build = validate_identity(info, metadata, channel, public_key)
    framework = bundle / "Contents/Frameworks/Sparkle.framework"
    require(framework.is_dir() and not framework.is_symlink(), "Missing embedded Sparkle.framework")
    for path in framework.rglob("*"):
        if path.is_symlink():
            require(path.resolve().is_relative_to(framework.resolve()) and path.resolve().exists(), "Embedded Sparkle link escapes its framework or is broken")
    for relative in ("Sparkle", "Autoupdate", "Updater.app/Contents/MacOS/Updater",
                     "XPCServices/Installer.xpc/Contents/MacOS/Installer", "XPCServices/Downloader.xpc/Contents/MacOS/Downloader"):
        path = framework / "Versions/B" / relative
        require(path.is_file() and os.access(path, os.X_OK), "Sparkle framework is incomplete")
    framework_info = plistlib.loads(read_regular(framework / "Versions/B/Resources/Info.plist", 1024 * 1024))
    require(framework_info.get("CFBundleShortVersionString") == "2.9.4", "Embedded framework version differs from the pinned distribution")
    requirement = (f'anchor apple generic and certificate leaf[subject.OU] = "{TEAM}" '
                   'and certificate 1[field.1.2.840.113635.100.6.2.6] exists '
                   'and certificate leaf[field.1.2.840.113635.100.6.1.13] exists')
    run(["/usr/bin/codesign", "--verify", "--deep", "--strict", "-R", "=" + requirement, str(bundle)])
    signature = run(["/usr/bin/codesign", "-d", "--verbose=4", str(bundle)])
    require(f"TeamIdentifier={TEAM}" in signature and f"Identifier={CHANNELS[channel][0]}\n" in signature
            and "Authority=Developer ID Application:" in signature,
            "App must carry the project's Developer ID Application signature")
    if channel == "production":
        run(["/usr/bin/xcrun", "stapler", "validate", str(bundle)])
        run(["/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=2", str(bundle)])
    return version, build


def parse_feed(data: bytes, channel: str) -> ET.Element:
    require(len(data) <= MAX_FEED and b"<!DOCTYPE" not in data.upper() and b"<!ENTITY" not in data.upper(), "Unsafe or oversized appcast")
    root = ET.fromstring(data)
    require(root.tag == "rss" and root.get("version") == "2.0" and len(root.findall("channel")) == 1, "Expected one RSS 2.0 channel")
    _, prefix, title = CHANNELS[channel]
    feed = root.find("channel")
    require(feed.findtext("title") == title, "Existing feed title belongs to a different channel")
    self_links = [link for link in feed.findall(f"{{{ATOM}}}link") if link.get("rel") == "self"]
    require(len(self_links) == 1 and self_links[0].get("href") == prefix + "appcast.xml", "Existing feed URL belongs to a different channel")
    seen: set[str] = set()
    for item in feed.findall("item"):
        enclosure = item.find("enclosure")
        require(enclosure is not None, "Existing feed item has no full update archive")
        version = item.findtext(f"{{{SPARKLE}}}version") or enclosure.get(f"{{{SPARKLE}}}version", "")
        version_tuple(version)
        require(version not in seen, "Existing feed contains duplicate build versions")
        seen.add(version)
        url = enclosure.get("url", "")
        suffix = url.removeprefix(prefix)
        require(url.startswith(prefix) and re.fullmatch(r"[A-Za-z0-9._-]+\.zip", suffix) is not None,
                "Existing feed archive leaves its channel")
        require(enclosure.get("length", "").isdigit() and 0 < int(enclosure.get("length")) <= MAX_ARCHIVE,
                "Invalid existing enclosure length")
        require(len(base64.b64decode(enclosure.get(f"{{{SPARKLE}}}edSignature", ""), validate=True)) == 64,
                "Existing feed archive has no valid Ed25519 signature")
    return root


def publish_directory(source: Path, destination: Path) -> None:
    # Darwin RENAME_EXCL publishes the completed directory atomically and
    # refuses even an empty preexisting destination (unlike os.rename).
    library = ctypes.CDLL(None, use_errno=True)
    rename = library.renamex_np
    rename.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(os.fsencode(source), os.fsencode(destination), 4) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(destination))


def read_release_notes(path: Path) -> str:
    text = read_regular(path, MAX_RELEASE_NOTES).decode("utf-8")
    require(not re.search(r"[^\x09\x0a\x0d\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]", text),
            "Release notes contain a character unsupported in XML")
    text = "\n".join(line.strip() for line in text.splitlines()).strip()
    require(bool(text), "Release notes are empty")
    paragraphs = re.split(r"\n{2,}", text)
    return "\n".join("<p>" + html.escape(paragraph).replace("\n", "<br>") + "</p>" for paragraph in paragraphs)


def prepare(archive: Path, output: Path, channel: str, existing: Path | None, release_notes: Path | None = None) -> None:
    require(sys.platform == "darwin", "Sparkle preparation requires macOS")
    require(not os.path.lexists(output), "Output directory already exists; immutable output is never overwritten")
    require(output.parent.is_dir(), "Output parent directory must already exist")
    public_key = read_regular(ROOT / "macos/SparklePublicKey.txt", 256).decode("ascii").strip()
    require(len(base64.b64decode(public_key, validate=True)) == 32, "Invalid project Sparkle public key")
    previous_data = read_regular(existing, MAX_FEED) if existing else None
    previous = parse_feed(previous_data, channel) if previous_data is not None else None
    description_html = read_release_notes(release_notes) if release_notes is not None else None
    with tempfile.TemporaryDirectory(prefix=".waal-update-", dir=output.parent) as temporary:
        work = Path(temporary)
        snapshot = work / "input.zip"
        snapshot.write_bytes(read_regular(archive, MAX_ARCHIVE))
        app_name = validate_zip(snapshot)
        extracted = work / "extracted"
        run(["/usr/bin/ditto", "-xk", str(snapshot), str(extracted)])
        version, build = validate_bundle(extracted / app_name, channel, public_key)
        if previous is not None:
            for item in previous.find("channel").findall("item"):
                old = item.findtext(f"{{{SPARKLE}}}version") or item.find("enclosure").get(f"{{{SPARKLE}}}version", "")
                require(version_tuple(build) > version_tuple(old), "New build must be newer than every existing appcast item")
        archive_hash = hashlib.sha256(snapshot.read_bytes()).hexdigest()
        filename_version = version.replace("+", "-")
        filename = f"WindowsAppAutoLogin-macos-{channel}-{filename_version}-{build}-{archive_hash[:12]}.zip"
        generated = work / "generated"
        generated.mkdir()
        update = generated / filename
        shutil.copyfile(snapshot, update)
        pinned = work / "Sparkle-2.9.4.zip"
        run(["/bin/bash", "-c", 'source "$1"; waal_fetch_sparkle_archive "$2"', "waal-fetch",
             str(ROOT / "script/macos_sparkle.sh"), str(pinned)])
        tools = work / "tools"
        run(["/usr/bin/ditto", "-xk", str(pinned), str(tools)])
        tool = lambda name: str(tools / "bin" / name)
        require(run([tool("generate_keys"), "--account", ACCOUNT, "-p"]).strip() == public_key,
                "Dedicated Keychain signing account does not match the project public key")
        if previous is not None and previous.find("channel").findall("item"):
            old_feed = work / "previous.xml"
            old_feed.write_bytes(previous_data)
            run([tool("sign_update"), "--account", ACCOUNT, "--verify", str(old_feed)])
        _, prefix, title = CHANNELS[channel]
        feed_path = generated / "appcast.xml"
        run([tool("generate_appcast"), "--account", ACCOUNT, "--download-url-prefix", prefix,
             "--maximum-versions", "0", "--maximum-deltas", "0", "--versions", build,
             "-o", str(feed_path), str(generated)], timeout=300)
        feed = ET.fromstring(read_regular(feed_path, MAX_FEED))
        channel_element = feed.find("channel")
        require(channel_element is not None and len(channel_element.findall("item")) == 1, "Generator did not create exactly one update item")
        item = channel_element.find("item")
        enclosure = item.find("enclosure")
        require(enclosure is not None and enclosure.get("url") == prefix + filename
                and enclosure.get("length") == str(update.stat().st_size), "Generated archive URL or length mismatch")
        require(item.findtext(f"{{{SPARKLE}}}version") == build
                and item.findtext(f"{{{SPARKLE}}}shortVersionString") == version, "Generated bundle version mismatch")
        signature = enclosure.get(f"{{{SPARKLE}}}edSignature", "")
        require(len(base64.b64decode(signature, validate=True)) == 64, "Generated archive lacks Ed25519 signature")
        run([tool("sign_update"), "--account", ACCOUNT, "--verify", str(update), signature])
        if description_html is not None:
            description = item.find("description")
            if description is None:
                description = ET.SubElement(item, "description")
            description.set(f"{{{SPARKLE}}}descriptionFormat", "html")
            description.text = description_html
        if previous is not None:
            feed = previous
            channel_element = feed.find("channel")
            channel_element.append(item)
        else:
            channel_element.find("title").text = title
            for link in list(channel_element.findall(f"{{{ATOM}}}link")):
                channel_element.remove(link)
            ET.SubElement(channel_element, f"{{{ATOM}}}link", {"href": prefix + "appcast.xml", "rel": "self", "type": "application/rss+xml"})
        feed_path.write_bytes(ET.tostring(feed, encoding="utf-8", xml_declaration=True))
        run([tool("sign_update"), "--account", ACCOUNT, str(feed_path)])
        run([tool("sign_update"), "--account", ACCOUNT, "--verify", str(feed_path)])
        parse_feed(read_regular(feed_path, MAX_FEED), channel)
        require(hashlib.sha256(update.read_bytes()).hexdigest() == archive_hash, "Generator changed archive bytes")
        deliverable = work / "ready"
        deliverable.mkdir(mode=0o755)
        for path in (update, feed_path):
            shutil.copyfile(path, deliverable / path.name)
            (deliverable / path.name).chmod(0o444)
        publish_directory(deliverable, output)
        print(f"Prepared {channel} update {version} (build {build}): {output}")
        print(f"Archive SHA-256: {archive_hash}")
        print("No remote publication was performed.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="ZIP containing the already signed .app")
    parser.add_argument("output", type=Path, help="New output directory; existing paths are rejected")
    parser.add_argument("--channel", required=True, choices=CHANNELS)
    parser.add_argument("--existing-appcast", type=Path, help="Previous same-channel feed; never modified")
    parser.add_argument("--release-notes", type=Path, help="UTF-8 plain text to display in Sparkle; separate paragraphs with a blank line")
    args = parser.parse_args()
    try:
        prepare(args.archive.absolute(), args.output.absolute(), args.channel, args.existing_appcast, args.release_notes)
    except (PreparationError, OSError, ValueError, RuntimeError, ET.ParseError, zipfile.BadZipFile, subprocess.TimeoutExpired) as error:
        print(f"Update preparation failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
