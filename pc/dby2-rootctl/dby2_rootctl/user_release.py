from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class UserReleaseError(RuntimeError):
    pass


@dataclass(frozen=True)
class BundledAsset:
    path: Path
    sha256: str


@dataclass(frozen=True)
class UserReleaseLayout:
    base_directory: Path
    adb_path: Path
    profile_directory: Path
    magisk_apk: BundledAsset
    rootkit_apk: BundledAsset
    nyazygisk_zip: BundledAsset
    vector_zip: BundledAsset
    root_engine_binary: BundledAsset

    @classmethod
    def load(cls, base_directory: Path) -> UserReleaseLayout:
        resolved_base = base_directory.expanduser().resolve()
        manifest_path = resolved_base / "release-manifest.json"
        if not manifest_path.is_file():
            raise UserReleaseError(
                f"Release manifest is missing: {manifest_path}"
            )

        manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest_data.get("schema_version") != 1:
            raise UserReleaseError("Unsupported release manifest schema.")

        try:
            adb_path = resolved_base / manifest_data["adb_path"]
            profile_directory = resolved_base / manifest_data["profile_directory"]
            asset_entries = manifest_data["assets"]
            return cls(
                base_directory=resolved_base,
                adb_path=adb_path,
                profile_directory=profile_directory,
                magisk_apk=cls._load_asset(
                    resolved_base,
                    asset_entries["magisk_apk"],
                ),
                rootkit_apk=cls._load_asset(
                    resolved_base,
                    asset_entries["rootkit_apk"],
                ),
                nyazygisk_zip=cls._load_asset(
                    resolved_base,
                    asset_entries["nyazygisk_zip"],
                ),
                vector_zip=cls._load_asset(
                    resolved_base,
                    asset_entries["vector_zip"],
                ),
                root_engine_binary=cls._load_asset(
                    resolved_base,
                    asset_entries["root_engine_binary"],
                ),
            )
        except KeyError as missing_field:
            raise UserReleaseError(
                f"Release manifest is missing: {missing_field.args[0]}"
            ) from missing_field

    @staticmethod
    def _load_asset(
        base_directory: Path,
        asset_data: dict[str, Any],
    ) -> BundledAsset:
        relative_path = str(asset_data["path"])
        expected_sha256 = str(asset_data["sha256"]).lower()
        return BundledAsset(
            path=base_directory / relative_path,
            sha256=expected_sha256,
        )

    def validate(self) -> None:
        required_paths = (
            ("ADB", self.adb_path),
            ("device profile directory", self.profile_directory),
            ("Magisk APK", self.magisk_apk.path),
            ("RootKit APK", self.rootkit_apk.path),
            ("NyaZygisk ZIP", self.nyazygisk_zip.path),
            ("Vector ZIP", self.vector_zip.path),
            ("ADB Root engine", self.root_engine_binary.path),
        )
        for item_name, item_path in required_paths:
            if not item_path.exists():
                raise UserReleaseError(f"{item_name} is missing: {item_path}")

        assets = (
            ("Magisk APK", self.magisk_apk),
            ("RootKit APK", self.rootkit_apk),
            ("NyaZygisk ZIP", self.nyazygisk_zip),
            ("Vector ZIP", self.vector_zip),
            ("ADB Root engine", self.root_engine_binary),
        )
        for asset_name, asset in assets:
            actual_sha256 = self._calculate_sha256(asset.path)
            if actual_sha256 != asset.sha256:
                raise UserReleaseError(
                    f"{asset_name} checksum mismatch: {asset.path}"
                )

    @staticmethod
    def _calculate_sha256(file_path: Path) -> str:
        digest = hashlib.sha256()
        with file_path.open("rb") as file_handle:
            while True:
                file_chunk = file_handle.read(1024 * 1024)
                if not file_chunk:
                    break
                digest.update(file_chunk)
        return digest.hexdigest()
