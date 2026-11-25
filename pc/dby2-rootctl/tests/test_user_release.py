import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from dby2_rootctl.user_release import (
    UserReleaseError,
    UserReleaseLayout,
)


class UserReleaseLayoutTests(unittest.TestCase):
    def _create_release(self, temporary: str) -> tuple[Path, dict[str, str]]:
        release_directory = Path(temporary) / "release"
        release_directory.mkdir()
        asset_paths = {
            "magisk_apk": "runtime/magisk.apk",
            "rootkit_apk": "runtime/rootkit.apk",
            "nyazygisk_zip": "runtime/nyazygisk.zip",
            "vector_zip": "runtime/vector.zip",
            "root_engine_binary": "runtime/DBY2-GhostLock-arm64",
        }
        checksums = {}
        for asset_name, relative_path in asset_paths.items():
            asset_path = release_directory / relative_path
            asset_path.parent.mkdir(parents=True, exist_ok=True)
            asset_bytes = f"test asset {asset_name}".encode("utf-8")
            asset_path.write_bytes(asset_bytes)
            checksums[asset_name] = hashlib.sha256(asset_bytes).hexdigest()

        adb_path = release_directory / "adb" / "adb.exe"
        adb_path.parent.mkdir()
        adb_path.write_bytes(b"test adb")
        profile_directory = release_directory / "profiles" / "dby2-w00"
        profile_directory.mkdir(parents=True)
        (profile_directory / "verified.json").write_text(
            "{}",
            encoding="utf-8",
        )

        manifest = {
            "schema_version": 1,
            "adb_path": "adb/adb.exe",
            "profile_directory": "profiles/dby2-w00",
            "assets": {
                asset_name: {
                    "path": asset_paths[asset_name],
                    "sha256": checksums[asset_name],
                }
                for asset_name in asset_paths
            },
        }
        (release_directory / "release-manifest.json").write_text(
            json.dumps(manifest),
            encoding="utf-8",
        )
        return release_directory, asset_paths

    def test_loads_and_validates_complete_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release_directory, _ = self._create_release(temporary)

            layout = UserReleaseLayout.load(release_directory)
            layout.validate()

            self.assertEqual(layout.adb_path.name, "adb.exe")
            self.assertEqual(layout.magisk_apk.path.name, "magisk.apk")
            self.assertEqual(
                layout.root_engine_binary.path.name,
                "DBY2-GhostLock-arm64",
            )
            self.assertTrue(layout.profile_directory.is_dir())

    def test_rejects_modified_runtime_asset(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            release_directory, asset_paths = self._create_release(temporary)
            modified_asset = release_directory / asset_paths["magisk_apk"]
            modified_asset.write_bytes(b"modified runtime")
            layout = UserReleaseLayout.load(release_directory)

            with self.assertRaisesRegex(UserReleaseError, "checksum mismatch"):
                layout.validate()


if __name__ == "__main__":
    unittest.main()
