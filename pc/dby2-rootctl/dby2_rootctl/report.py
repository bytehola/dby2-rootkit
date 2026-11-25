from __future__ import annotations

from typing import Any

from dby2_rootctl.device import DeviceSnapshot
from dby2_rootctl.profile import ProfileEvaluation


def _check(name: str, succeeded: bool, detail: str) -> dict[str, Any]:
    return {
        "name": name,
        "succeeded": succeeded,
        "detail": detail,
    }


def build_report(
    snapshot: DeviceSnapshot,
    evaluation: ProfileEvaluation,
) -> dict[str, Any]:
    system_server_available = bool(snapshot.system_server_pid)
    surfaceflinger_available = bool(snapshot.surfaceflinger_pid)
    magisk_available = bool(snapshot.magisk_version)
    zygisk_available = snapshot.zygisk_status == "injected"
    vector_available = bool(
        snapshot.vector_status
        and snapshot.vector_status.get("success") is True
    )

    checks = [
        _check(
            "profile",
            evaluation.succeeded,
            f"profile={evaluation.profile.profile_id}",
        ),
        _check(
            "root",
            snapshot.root_available,
            "uid 0 broker available"
            if snapshot.root_available
            else "root is not active in this boot",
        ),
        _check(
            "magisk",
            magisk_available,
            snapshot.magisk_version or "Magisk runtime unavailable",
        ),
        _check(
            "zygisk",
            zygisk_available,
            snapshot.zygisk_status,
        ),
        _check(
            "vector",
            vector_available,
            "Vector daemon ready"
            if vector_available
            else snapshot.vector_error or "Vector daemon unavailable",
        ),
        _check(
            "system_server",
            system_server_available,
            snapshot.system_server_pid or "missing",
        ),
        _check(
            "surfaceflinger",
            surfaceflinger_available,
            snapshot.surfaceflinger_pid or "missing",
        ),
        _check(
            "selinux_enforcing",
            snapshot.selinux_mode == "Enforcing",
            snapshot.selinux_mode or "unknown",
        ),
    ]

    warnings: list[str] = []
    if snapshot.boot_adb_port:
        warnings.append(
            "TCP ADB is configured for the current boot "
            f"(port {snapshot.boot_adb_port})."
        )
    if snapshot.root_available and not vector_available:
        warnings.append("Root is active, but the Xposed runtime is degraded.")
    if not snapshot.root_available:
        warnings.append(
            "Temporary root is not active for the current boot."
        )

    if not evaluation.succeeded:
        state = "unsupported"
    elif (
        snapshot.root_available
        and system_server_available
        and surfaceflinger_available
    ):
        state = "root-active"
    elif system_server_available and surfaceflinger_available:
        state = "ready"
    else:
        state = "degraded"

    return {
        "ok": evaluation.succeeded
        and system_server_available
        and surfaceflinger_available,
        "state": state,
        "device": snapshot.public_dict(),
        "profile": evaluation.as_dict(),
        "policy": dict(evaluation.profile.policy),
        "checks": checks,
        "warnings": warnings,
    }


def format_human_report(report: dict[str, Any]) -> str:
    device = report["device"]
    profile = report["profile"]
    lines = [
        "DBY2 RootKit status",
        f"State: {report['state']}",
        f"Device: {device['model']} / Android {device['android_release']} / SDK {device['sdk']}",
        f"Build: {device['display_id']}",
        f"Kernel: {device['kernel']}",
        f"Serial hash: {device['serial_hash']}",
        f"Boot hash: {device['boot_id_hash']}",
        f"Profile: {profile['profile_id']} ({'matched' if profile['succeeded'] else 'mismatch'})",
        "",
        "Checks:",
    ]

    for check in report["checks"]:
        status = "OK" if check["succeeded"] else "FAIL"
        lines.append(f"[{status}] {check['name']}: {check['detail']}")

    if report["warnings"]:
        lines.append("")
        lines.append("Warnings:")
        lines.extend(f"- {warning}" for warning in report["warnings"])

    return "\n".join(lines)
