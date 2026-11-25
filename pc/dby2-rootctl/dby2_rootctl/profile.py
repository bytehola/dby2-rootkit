from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping


class ProfileError(RuntimeError):
    pass


@dataclass(frozen=True)
class DeviceProfile:
    profile_id: str
    display_name: str
    device: Mapping[str, Any]
    runtime: Mapping[str, Any]
    policy: Mapping[str, Any]
    source_path: Path


@dataclass(frozen=True)
class ProfileCheck:
    name: str
    expected: str
    actual: str
    succeeded: bool


@dataclass(frozen=True)
class ProfileEvaluation:
    profile: DeviceProfile
    checks: tuple[ProfileCheck, ...]

    @property
    def succeeded(self) -> bool:
        return all(check.succeeded for check in self.checks)

    def as_dict(self) -> dict[str, Any]:
        return {
            "profile_id": self.profile.profile_id,
            "display_name": self.profile.display_name,
            "succeeded": self.succeeded,
            "checks": [
                {
                    "name": check.name,
                    "expected": check.expected,
                    "actual": check.actual,
                    "succeeded": check.succeeded,
                }
                for check in self.checks
            ],
        }


DEFAULT_PROFILE_DIRECTORY = (
    Path(__file__).resolve().parents[3] / "profiles" / "dby2-w00"
)


def load_profile(
    profile_directory: Path = DEFAULT_PROFILE_DIRECTORY,
    profile_id: str | None = None,
) -> DeviceProfile:
    if not profile_directory.is_dir():
        raise ProfileError(f"Profile directory does not exist: {profile_directory}")

    profile_paths = sorted(profile_directory.glob("*.json"))
    if profile_id:
        profile_paths = [
            profile_path
            for profile_path in profile_paths
            if profile_path.stem == profile_id
            or profile_path.name == profile_id
        ]

    if not profile_paths:
        requested = profile_id or "any profile"
        raise ProfileError(f"No device profile found for {requested}.")
    if len(profile_paths) > 1:
        profile_names = ", ".join(path.name for path in profile_paths)
        raise ProfileError(
            f"Multiple profiles found ({profile_names}); pass --profile-id."
        )

    profile_path = profile_paths[0]
    profile_data = json.loads(profile_path.read_text(encoding="utf-8"))
    schema_version = profile_data.get("schema_version")
    if schema_version != 1:
        raise ProfileError(
            f"Unsupported profile schema version: {schema_version!r}"
        )

    try:
        return DeviceProfile(
            profile_id=str(profile_data["profile_id"]),
            display_name=str(profile_data["display_name"]),
            device=profile_data["device"],
            runtime=profile_data["runtime"],
            policy=profile_data["policy"],
            source_path=profile_path,
        )
    except KeyError as missing_field:
        raise ProfileError(
            f"Profile is missing required field: {missing_field.args[0]}"
        ) from missing_field


def evaluate_identity(
    profile: DeviceProfile,
    identity: Mapping[str, Any],
) -> ProfileEvaluation:
    expected_device = profile.device
    checks = [
        ProfileCheck(
            name="model",
            expected=str(expected_device["model"]),
            actual=str(identity.get("model", "")),
            succeeded=str(identity.get("model", "")) == str(expected_device["model"]),
        ),
        ProfileCheck(
            name="sdk",
            expected=str(expected_device["sdk"]),
            actual=str(identity.get("sdk", "")),
            succeeded=str(identity.get("sdk", "")) == str(expected_device["sdk"]),
        ),
        ProfileCheck(
            name="abi",
            expected=str(expected_device["abi"]),
            actual=str(identity.get("abi", "")),
            succeeded=str(identity.get("abi", "")) == str(expected_device["abi"]),
        ),
        ProfileCheck(
            name="kernel",
            expected=f"{expected_device['kernel_prefix']}*",
            actual=str(identity.get("kernel", "")),
            succeeded=str(identity.get("kernel", "")).startswith(
                str(expected_device["kernel_prefix"])
            ),
        ),
        ProfileCheck(
            name="display_id",
            expected=str(expected_device["display_id"]),
            actual=str(identity.get("display_id", "")),
            succeeded=str(identity.get("display_id", ""))
            == str(expected_device["display_id"]),
        ),
        ProfileCheck(
            name="incremental",
            expected=str(expected_device["incremental"]),
            actual=str(identity.get("incremental", "")),
            succeeded=str(identity.get("incremental", ""))
            == str(expected_device["incremental"]),
        ),
    ]
    return ProfileEvaluation(profile=profile, checks=tuple(checks))
