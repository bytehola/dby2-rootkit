from __future__ import annotations

import json
import re
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any

from dby2_rootctl.adb import AdbClient
from dby2_rootctl.device import DeviceSnapshot
from dby2_rootctl.redact import redact_text


REMOTE_LOG_FILES = (
    "/data/local/tmp/dby2-xposed-activate.log",
    "/data/local/tmp/vector-service-launch.log",
    "/data/local/tmp/magisk-daemon.log",
)
BUILD_VERSION_PATTERN = re.compile(r"(?<![\w.])(?:\d+\.){2,3}\d+(?![\w.])")


def default_diagnostic_path() -> Path:
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path.cwd() / f"dby2-diagnostics-{timestamp}.zip"


def _preserved_identity_values(snapshot: DeviceSnapshot) -> tuple[str, ...]:
    preserved_values = {
        snapshot.model,
        snapshot.android_release,
        snapshot.sdk,
        snapshot.abi,
        snapshot.display_id,
        snapshot.incremental,
        snapshot.kernel,
    }
    preserved_values.update(BUILD_VERSION_PATTERN.findall(snapshot.display_id))
    return tuple(sorted(preserved_values))


def _read_remote_file(client: AdbClient, remote_path: str) -> str:
    root_result = client.shell(
        f"/system/bin/su -c 'cat {remote_path}'",
        timeout_seconds=10.0,
    )
    if root_result.succeeded and root_result.stdout.strip():
        return root_result.stdout

    direct_result = client.shell(
        f"cat {remote_path}",
        timeout_seconds=10.0,
    )
    if direct_result.succeeded:
        return direct_result.stdout

    return (
        f"Unable to read {remote_path}\n"
        f"{direct_result.stderr.strip()}\n"
    )


def create_diagnostic_archive(
    client: AdbClient,
    snapshot: DeviceSnapshot,
    report: dict[str, Any],
    output_path: Path | None = None,
) -> Path:
    destination = output_path or default_diagnostic_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    secrets = [client.serial, snapshot.boot_id]
    preserved_values = _preserved_identity_values(snapshot)

    logcat_result = client.run(
        ["logcat", "-d", "-t", "2000"],
        timeout_seconds=45.0,
    )
    logcat_text = (
        logcat_result.stdout
        if logcat_result.succeeded
        else f"logcat failed: {logcat_result.stderr.strip()}\n"
    )

    summary = {
        "generated_at": datetime.now().astimezone().isoformat(),
        "redaction": [
            "device serial",
            "boot_id",
            "IPv4 address",
            "MAC address",
            "home directory",
            "ADB public key",
        ],
        "report": report,
    }

    with zipfile.ZipFile(destination, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "summary.json",
            redact_text(
                json.dumps(summary, ensure_ascii=False, indent=2),
                secrets,
                preserved_values,
            ),
        )
        archive.writestr(
            "logcat.txt",
            redact_text(logcat_text, secrets, preserved_values),
        )

        for remote_path in REMOTE_LOG_FILES:
            remote_text = _read_remote_file(client, remote_path)
            archive.writestr(
                remote_path.lstrip("/").replace("/", "_"),
                redact_text(remote_text, secrets, preserved_values),
            )

    return destination
