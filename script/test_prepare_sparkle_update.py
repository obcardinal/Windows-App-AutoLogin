#!/usr/bin/env python3
"""Publication-boundary tests; no network, Keychain, or existing app mutations."""

import base64
import importlib.util
from pathlib import Path
import plistlib
import stat
import sys
import tempfile
import unittest
from unittest import mock
import zipfile

SPEC = importlib.util.spec_from_file_location("prepare_sparkle_update", Path(__file__).with_name("prepare_sparkle_update.py"))
UPDATE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(UPDATE)
KEY = base64.b64encode(bytes(range(32))).decode()


class UpdatePreparationTests(unittest.TestCase):
    def test_release_notes_keep_paragraphs_and_escape_literal_markup(self):
        with tempfile.TemporaryDirectory() as temp:
            notes = Path(temp) / "notes.txt"
            notes.write_bytes(' Accounts & updates\r\nSecond line.\r\n \r\n<em>“Example”</em>\n'.encode("utf-8"))
            self.assertEqual(UPDATE.read_release_notes(notes),
                             "<p>Accounts &amp; updates<br>Second line.</p>\n<p>&lt;em&gt;“Example”&lt;/em&gt;</p>")

    def test_invalid_release_notes_are_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            notes = Path(temp) / "notes.txt"
            for data in (b" \r\n  ", b"x\x00y", b"x" * (UPDATE.MAX_RELEASE_NOTES + 1)):
                with self.subTest(length=len(data)), self.assertRaises(UPDATE.PreparationError):
                    notes.write_bytes(data)
                    UPDATE.read_release_notes(notes)

    def identity(self, channel="development"):
        identity, prefix, _ = UPDATE.CHANNELS[channel]
        return {
            "CFBundleIdentifier": identity, "CFBundleExecutable": "windows-app-autologin",
            "CFBundlePackageType": "APPL", "CFBundleVersion": "0.4.2", "CFBundleShortVersionString": "0.4.2",
            "SUFeedURL": prefix + "appcast.xml", "SUPublicEDKey": KEY, "WAALSparkleVersion": "2.9.4",
        }, {
            "macos-bundle-id": identity, "profile": "release", "target-os": "macos",
            "debug-assertions": "false", "debug-fill": "false", "dev-tools": "false",
            "diagnostics-ui": "false", "release-diagnostics": "false",
            "non-production-macos-identity": "true" if channel == "development" else "false",
            "artifact-kind": "development", "publishable": "false",
            "attestation": "none-local-shared-security-context",
            "producer-attribution": "unavailable-local-shared-security-context", "macos-team-id": UPDATE.TEAM,
        }

    def test_development_identity_cannot_enter_production(self):
        info, metadata = self.identity()
        UPDATE.validate_identity(info, metadata, "development", KEY)
        with self.assertRaisesRegex(UPDATE.PreparationError, "identity"):
            UPDATE.validate_identity(info, metadata, "production", KEY)

    def test_mismatched_feed_and_key_are_rejected(self):
        info, metadata = self.identity()
        for field, value, message in (("SUFeedURL", UPDATE.BASE + "appcast.xml", "feed"),
                                      ("SUPublicEDKey", base64.b64encode(bytes(32)).decode(), "public key")):
            modified = dict(info, **{field: value})
            with self.subTest(field=field), self.assertRaisesRegex(UPDATE.PreparationError, message):
                UPDATE.validate_identity(modified, metadata, "development", KEY)

    def test_production_rejects_nonpublishable_metadata_even_with_production_id(self):
        info, metadata = self.identity("production")
        for artifact in ("development", "local-signed-release", "release"):
            metadata["artifact-kind"] = artifact
            with self.subTest(artifact=artifact), self.assertRaisesRegex(UPDATE.PreparationError, "nonpublishable"):
                UPDATE.validate_identity(info, metadata, "production", KEY)

    def test_ambiguous_build_metadata_is_rejected(self):
        line = "WAAL_BUILD_METADATA_V1;publishable=false;"
        for payload in (line + "publishable=true;", line + "\n" + line, "unrelated"):
            with self.assertRaises(UPDATE.PreparationError):
                UPDATE.parse_metadata(payload)

    def test_existing_output_is_rejected_before_archive_or_keychain_access(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "existing"
            output.mkdir()
            sentinel = output / "keep.txt"
            sentinel.write_text("keep")
            with mock.patch.object(UPDATE.sys, "platform", "darwin"), mock.patch.object(UPDATE, "run") as run:
                with self.assertRaisesRegex(UPDATE.PreparationError, "already exists"):
                    UPDATE.prepare(Path(temp) / "missing.zip", output, "development", None)
                run.assert_not_called()
            self.assertEqual(sentinel.read_text(), "keep")

    def make_zip(self, path, entries):
        with zipfile.ZipFile(path, "w") as archive:
            for name, data, mode in entries:
                entry = zipfile.ZipInfo(name)
                entry.create_system = 3
                entry.external_attr = mode << 16
                archive.writestr(entry, data)

    def test_framework_symlinks_are_allowed_but_escape_and_link_children_are_not(self):
        framework = "Windows App AutoLogin.app/Contents/Frameworks/Sparkle.framework/"
        normal = [(framework + "Versions/B/Sparkle", b"binary", stat.S_IFREG | 0o755),
                  (framework + "Versions/Current", b"B", stat.S_IFLNK | 0o755),
                  (framework + "Sparkle", b"Versions/Current/Sparkle", stat.S_IFLNK | 0o755)]
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "test.zip"
            self.make_zip(archive, normal)
            self.assertEqual(UPDATE.validate_zip(archive), "Windows App AutoLogin.app")
            for extra in [(framework + "escape", b"../../../../outside", stat.S_IFLNK | 0o755),
                          (framework + "Versions/Current/injected", b"bad", stat.S_IFREG | 0o644),
                          ("../outside", b"bad", stat.S_IFREG | 0o644),
                          (framework + "versions/B/SPARKLE", b"bad", stat.S_IFREG | 0o644)]:
                with self.subTest(extra=extra[0]):
                    self.make_zip(archive, normal + [extra])
                    with self.assertRaises(UPDATE.PreparationError):
                        UPDATE.validate_zip(archive)

    def test_cross_channel_appcast_cannot_be_merged(self):
        xml = f'''<rss version="2.0" xmlns:atom="{UPDATE.ATOM}"><channel>
<title>Windows App AutoLogin Development</title>
<atom:link rel="self" href="{UPDATE.BASE}development/appcast.xml" />
</channel></rss>'''.encode()
        UPDATE.parse_feed(xml, "development")
        with self.assertRaises(UPDATE.PreparationError):
            UPDATE.parse_feed(xml, "production")

    @unittest.skipUnless(sys.platform == "darwin", "native codesign/atomic publication requires macOS")
    def test_unsigned_archive_is_rejected_and_existing_directory_is_not_replaced(self):
        info, metadata = self.identity()
        with tempfile.TemporaryDirectory() as temp:
            bundle = Path(temp) / "Unsigned.app"
            contents = bundle / "Contents"
            (contents / "MacOS").mkdir(parents=True)
            (contents / "Info.plist").write_bytes(plistlib.dumps(info))
            binary = contents / "MacOS/windows-app-autologin"
            binary.write_bytes(b"unsigned")
            framework = contents / "Frameworks/Sparkle.framework/Versions/B"
            for name in ("Sparkle", "Autoupdate", "Updater.app/Contents/MacOS/Updater",
                         "XPCServices/Installer.xpc/Contents/MacOS/Installer", "XPCServices/Downloader.xpc/Contents/MacOS/Downloader"):
                path = framework / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"unsigned")
                path.chmod(0o755)
            (framework / "Resources").mkdir()
            (framework / "Resources/Info.plist").write_bytes(plistlib.dumps({"CFBundleShortVersionString": "2.9.4"}))
            with mock.patch.object(UPDATE, "parse_metadata", return_value=metadata):
                with self.assertRaisesRegex(UPDATE.PreparationError, "codesign failed"):
                    UPDATE.validate_bundle(bundle, "development", KEY)
            source, destination = Path(temp) / "source", Path(temp) / "destination"
            source.mkdir()
            destination.mkdir()
            with self.assertRaises(FileExistsError):
                UPDATE.publish_directory(source, destination)
            self.assertTrue(source.is_dir())
            self.assertTrue(destination.is_dir())


if __name__ == "__main__":
    unittest.main()
