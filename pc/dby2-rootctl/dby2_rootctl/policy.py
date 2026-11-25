from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from dby2_rootctl.adb import AdbClient
from dby2_rootctl.redact import stable_hash
from dby2_rootctl.xposed import XposedError, shell_quote


POLICY_NAMES = {
    0: "query",
    1: "deny",
    2: "allow",
    3: "restrict",
}

PACKAGE_UID_PATTERN = re.compile(r"^package:(?P<package>\S+)\s+uid:(?P<uid>\d+)$")


@dataclass(frozen=True)
class MagiskPolicy:
    uid: int
    policy: int
    until: int
    logging: bool
    notification: bool
    packages: tuple[str, ...]

    @property
    def decision(self) -> str:
        return POLICY_NAMES.get(self.policy, f"unknown-{self.policy}")

    def as_dict(self) -> dict[str, Any]:
        return {
            "uid": self.uid,
            "policy": self.policy,
            "decision": self.decision,
            "until": self.until,
            "logging": self.logging,
            "notification": self.notification,
            "packages": list(self.packages),
        }


@dataclass(frozen=True)
class PolicySnapshot:
    boot_id_hash: str
    policies: tuple[MagiskPolicy, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "boot_id_hash": self.boot_id_hash,
            "policies": [policy.as_dict() for policy in self.policies],
        }


@dataclass(frozen=True)
class BootSession:
    current_boot_hash: str
    marker_boot_hash: str
    state: str

    def as_dict(self) -> dict[str, str]:
        return {
            "current_boot_hash": self.current_boot_hash,
            "marker_boot_hash": self.marker_boot_hash,
            "state": self.state,
        }


@dataclass(frozen=True)
class PolicyExpiryPlan:
    state: str
    preserve_uids: tuple[int, ...]
    expiring_uids: tuple[int, ...]
    backup_path: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "state": self.state,
            "preserve_uids": list(self.preserve_uids),
            "expiring_uids": list(self.expiring_uids),
            "backup_path": self.backup_path,
            "will_change": bool(self.expiring_uids),
        }


def classify_boot_session(current_boot_id: str, marker_boot_id: str) -> str:
    if not marker_boot_id:
        return "unmarked"
    if current_boot_id == marker_boot_id:
        return "same-boot"
    return "new-boot"


def parse_package_uid_map(raw_output: str) -> dict[int, list[str]]:
    packages_by_uid: dict[int, list[str]] = {}
    for raw_line in raw_output.splitlines():
        match = PACKAGE_UID_PATTERN.fullmatch(raw_line.strip())
        if match is None:
            continue
        package_name = match.group("package")
        uid = int(match.group("uid"))
        packages_by_uid.setdefault(uid, []).append(package_name)

    for package_names in packages_by_uid.values():
        package_names.sort()
    return packages_by_uid


def parse_policy_rows(raw_output: str) -> list[dict[str, int]]:
    rows: list[dict[str, int]] = []
    required_fields = ("uid", "policy", "until", "logging", "notification")

    for raw_line in raw_output.splitlines():
        stripped_line = raw_line.strip()
        if not stripped_line or "|" not in stripped_line:
            continue

        row: dict[str, int] = {}
        for field in stripped_line.split("|"):
            if "=" not in field:
                continue
            key, value = field.split("=", 1)
            if key in required_fields:
                try:
                    row[key] = int(value)
                except ValueError:
                    continue

        if all(field in row for field in required_fields):
            rows.append(row)

    return rows


class MagiskPolicyInspector:
    def __init__(self, client: AdbClient):
        self.client = client

    def _run_root(self, command: str, timeout_seconds: float = 20.0) -> str:
        result = self.client.shell(
            f"/system/bin/su -c {shell_quote(command)}",
            timeout_seconds=timeout_seconds,
        )
        if not result.succeeded:
            detail = result.stderr.strip() or result.stdout.strip()
            raise XposedError(
                f"Root command failed with exit code {result.returncode}: "
                f"{detail or command}"
            )
        return result.stdout

    def inspect(self) -> PolicySnapshot:
        boot_id = self._run_root(
            "cat /proc/sys/kernel/random/boot_id"
        ).strip()
        policy_output = self._run_root(
            "/system/bin/magisk --sqlite "
            "'select uid,policy,until,logging,notification "
            "from policies order by uid'"
        )
        package_output = self.client.shell(
            "cmd package list packages -U",
            timeout_seconds=20.0,
        )
        if not package_output.succeeded:
            raise XposedError("Could not read installed package UID mappings.")

        packages_by_uid = parse_package_uid_map(package_output.stdout)
        policy_rows = parse_policy_rows(policy_output)
        policies = tuple(
            MagiskPolicy(
                uid=row["uid"],
                policy=row["policy"],
                until=row["until"],
                logging=bool(row["logging"]),
                notification=bool(row["notification"]),
                packages=tuple(packages_by_uid.get(row["uid"], ())),
            )
            for row in policy_rows
        )
        return PolicySnapshot(
            boot_id_hash=stable_hash(boot_id),
            policies=policies,
        )

    def inspect_boot_session(self) -> BootSession:
        current_boot_id = self._run_root(
            "cat /proc/sys/kernel/random/boot_id"
        ).strip()
        marker_output = self._run_root(
            "if [ -f /data/adb/dby2/boot_id ]; "
            "then cat /data/adb/dby2/boot_id; else echo __missing__; fi"
        ).strip()
        marker_boot_id = "" if marker_output == "__missing__" else marker_output
        return BootSession(
            current_boot_hash=stable_hash(current_boot_id),
            marker_boot_hash=stable_hash(marker_boot_id) if marker_boot_id else "",
            state=classify_boot_session(current_boot_id, marker_boot_id),
        )

    def mark_boot_session(self) -> BootSession:
        self._run_root(
            "mkdir -p /data/adb/dby2 && "
            "chmod 700 /data/adb/dby2 && "
            "cat /proc/sys/kernel/random/boot_id > /data/adb/dby2/boot_id && "
            "chmod 600 /data/adb/dby2/boot_id"
        )
        return self.inspect_boot_session()

    def build_expiry_plan(self, preserve_uids: set[int]) -> PolicyExpiryPlan:
        boot_session = self.inspect_boot_session()
        policy_snapshot = self.inspect()
        current_time = datetime.now().strftime("%Y%m%d-%H%M%S")
        backup_path = (
            f"/data/adb/dby2/backups/magisk.db.{current_time}"
        )

        if boot_session.state != "new-boot":
            return PolicyExpiryPlan(
                state=boot_session.state,
                preserve_uids=tuple(sorted(preserve_uids)),
                expiring_uids=(),
                backup_path=backup_path,
            )

        expiring_uids = tuple(
            sorted(
                policy.uid
                for policy in policy_snapshot.policies
                if policy.uid not in preserve_uids
            )
        )
        return PolicyExpiryPlan(
            state=boot_session.state,
            preserve_uids=tuple(sorted(preserve_uids)),
            expiring_uids=expiring_uids,
            backup_path=backup_path,
        )

    def apply_expiry_plan(self, plan: PolicyExpiryPlan) -> BootSession:
        if plan.state != "new-boot" or not plan.expiring_uids:
            return self.inspect_boot_session()

        self._run_root(
            "mkdir -p /data/adb/dby2/backups && "
            f"cp /data/adb/magisk.db {plan.backup_path} && "
            f"chmod 600 {plan.backup_path}"
        )

        protected_uids = ",".join(str(uid) for uid in plan.preserve_uids)
        sql = (
            "delete from policies "
            f"where uid not in ({protected_uids})"
        )
        self._run_root(
            f"/system/bin/magisk --sqlite {shell_quote(sql)}"
        )
        return self.mark_boot_session()
