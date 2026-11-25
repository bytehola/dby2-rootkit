from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


class AdbError(RuntimeError):
    pass


@dataclass(frozen=True)
class AdbDevice:
    serial: str
    state: str
    product: str | None = None
    model: str | None = None
    device: str | None = None
    transport_id: str | None = None


@dataclass(frozen=True)
class CommandResult:
    arguments: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def succeeded(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def _candidate_adb_paths() -> list[Path]:
    candidates = [
        Path("/mnt/d/tools/platform-tools/adb.exe"),
        Path("/mnt/c/platform-tools/adb.exe"),
        Path.home() / "Android/Sdk/platform-tools/adb",
        Path.home() / "Library/Android/sdk/platform-tools/adb",
    ]

    mount_root = Path("/mnt")
    if mount_root.is_dir():
        candidates.extend(mount_root.glob("*/platform-tools/adb.exe"))
        candidates.extend(mount_root.glob("*/tools/platform-tools/adb.exe"))

    return candidates


def _hidden_subprocess_options() -> dict[str, int]:
    if os.name == "nt" and hasattr(subprocess, "CREATE_NO_WINDOW"):
        return {"creationflags": subprocess.CREATE_NO_WINDOW}
    return {}


def find_adb(
    explicit_path: str | None = None,
    environment: Mapping[str, str] | None = None,
) -> Path:
    active_environment = os.environ if environment is None else environment

    if explicit_path:
        requested_path = Path(explicit_path).expanduser()
        if not requested_path.is_file():
            raise AdbError(f"ADB path does not exist: {requested_path}")
        return requested_path.resolve()

    environment_path = active_environment.get("ADB", "").strip()
    if environment_path:
        requested_path = Path(environment_path).expanduser()
        if requested_path.is_file():
            return requested_path.resolve()

    path_entry = shutil.which("adb")
    if path_entry:
        return Path(path_entry).resolve()

    for candidate_path in _candidate_adb_paths():
        if candidate_path.is_file():
            return candidate_path.resolve()

    raise AdbError(
        "Could not find adb. Pass --adb PATH or set the ADB environment variable."
    )


def parse_devices_output(output: str) -> list[AdbDevice]:
    devices: list[AdbDevice] = []

    for raw_line in output.splitlines():
        stripped_line = raw_line.strip()
        if not stripped_line:
            continue
        if stripped_line.startswith("List of devices attached"):
            continue
        if stripped_line.startswith("* daemon"):
            continue

        columns = stripped_line.split()
        if len(columns) < 2:
            continue

        serial = columns[0]
        state = columns[1]
        metadata: dict[str, str] = {}
        for column in columns[2:]:
            if ":" not in column:
                continue
            key, value = column.split(":", 1)
            metadata[key] = value

        devices.append(
            AdbDevice(
                serial=serial,
                state=state,
                product=metadata.get("product"),
                model=metadata.get("model"),
                device=metadata.get("device"),
                transport_id=metadata.get("transport_id"),
            )
        )

    return devices


def _local_path_for_adb(
    adb_path: Path,
    local_path: Path,
) -> str:
    resolved_local_path = local_path.expanduser().resolve()
    if os.name == "nt" or adb_path.suffix.lower() != ".exe":
        return str(resolved_local_path)

    wslpath_command = shutil.which("wslpath")
    if wslpath_command is None:
        return str(resolved_local_path)

    completed_process = subprocess.run(
        [wslpath_command, "-w", str(resolved_local_path)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=10,
        check=False,
    )
    windows_path = completed_process.stdout.strip()
    if completed_process.returncode != 0 or not windows_path:
        raise AdbError(
            "Could not convert a WSL path for Windows ADB: "
            f"{resolved_local_path}: "
            f"{completed_process.stderr.strip()}"
        )
    return windows_path


class AdbClient:
    def __init__(self, adb_path: Path, serial: str):
        self.adb_path = adb_path
        self.serial = serial

    def run(
        self,
        arguments: Sequence[str],
        timeout_seconds: float = 30.0,
    ) -> CommandResult:
        command = [
            str(self.adb_path),
            "-s",
            self.serial,
            *arguments,
        ]

        try:
            completed_process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                check=False,
            **_hidden_subprocess_options(),
            )
        except subprocess.TimeoutExpired as timeout_error:
            stdout = timeout_error.stdout or ""
            stderr = timeout_error.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode("utf-8", errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode("utf-8", errors="replace")
            return CommandResult(
                arguments=tuple(command),
                returncode=124,
                stdout=stdout,
                stderr=stderr,
                timed_out=True,
            )

        return CommandResult(
            arguments=tuple(command),
            returncode=completed_process.returncode,
            stdout=completed_process.stdout,
            stderr=completed_process.stderr,
        )

    def shell(
        self,
        command: str,
        timeout_seconds: float = 30.0,
    ) -> CommandResult:
        return self.run(["shell", command], timeout_seconds=timeout_seconds)

    def shell_text(
        self,
        command: str,
        timeout_seconds: float = 30.0,
    ) -> str:
        result = self.shell(command, timeout_seconds=timeout_seconds)
        if not result.succeeded:
            raise AdbError(
                f"ADB shell command failed ({result.returncode}): {command}\n"
                f"{result.stderr.strip()}"
            )
        return result.stdout.replace("\r\n", "\n").strip()

    def install(
        self,
        apk_path: Path,
        replace_existing: bool = True,
        timeout_seconds: float = 180.0,
    ) -> CommandResult:
        install_arguments = ["install", "--no-incremental"]
        if replace_existing:
            install_arguments.append("-r")
        install_arguments.append(
            _local_path_for_adb(self.adb_path, apk_path)
        )
        return self.run(install_arguments, timeout_seconds=timeout_seconds)

    def push(
        self,
        local_path: Path,
        remote_path: str,
        timeout_seconds: float = 120.0,
    ) -> CommandResult:
        return self.run(
            [
                "push",
                _local_path_for_adb(self.adb_path, local_path),
                remote_path,
            ],
            timeout_seconds=timeout_seconds,
        )


def list_devices(adb_path: Path) -> list[AdbDevice]:
    completed_process = subprocess.run(
        [str(adb_path), "devices", "-l"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=15,
        check=False,
        **_hidden_subprocess_options(),
    )
    if completed_process.returncode != 0:
        raise AdbError(
            "ADB device listing failed: "
            f"{completed_process.stderr.strip() or completed_process.stdout.strip()}"
        )
    return parse_devices_output(completed_process.stdout)


def start_adb_server(
    adb_path: Path,
    timeout_seconds: float = 15.0,
) -> CommandResult:
    command = [str(adb_path), "start-server"]
    completed_process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        check=False,
        **_hidden_subprocess_options(),
    )
    return CommandResult(
        arguments=tuple(command),
        returncode=completed_process.returncode,
        stdout=completed_process.stdout,
        stderr=completed_process.stderr,
    )


def restart_adb_server(
    adb_path: Path,
    timeout_seconds: float = 15.0,
) -> CommandResult:
    kill_command = [str(adb_path), "kill-server"]
    subprocess.run(
        kill_command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        check=False,
        **_hidden_subprocess_options(),
    )
    return start_adb_server(adb_path, timeout_seconds)


def stop_adb_server(
    adb_path: Path,
    timeout_seconds: float = 10.0,
) -> CommandResult:
    command = [str(adb_path), "kill-server"]
    completed_process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout_seconds,
        check=False,
        **_hidden_subprocess_options(),
    )
    return CommandResult(
        arguments=tuple(command),
        returncode=completed_process.returncode,
        stdout=completed_process.stdout,
        stderr=completed_process.stderr,
    )


def select_device(
    adb_path: Path,
    requested_serial: str | None = None,
) -> AdbDevice:
    devices = list_devices(adb_path)
    online_devices = [device for device in devices if device.state == "device"]

    if requested_serial:
        for device in online_devices:
            if device.serial == requested_serial:
                return device
        raise AdbError(
            f"Requested device is not online: {requested_serial}"
        )

    if not online_devices:
        raise AdbError("No online ADB device found.")
    if len(online_devices) > 1:
        serials = ", ".join(device.serial for device in online_devices)
        raise AdbError(
            f"Multiple online devices found ({serials}); pass --serial SERIAL."
        )

    return online_devices[0]
