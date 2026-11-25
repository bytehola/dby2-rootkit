from __future__ import annotations

import json
import shlex
import time
from dataclasses import dataclass
from typing import Any

from dby2_rootctl.adb import AdbClient, AdbError, CommandResult
from dby2_rootctl.redact import stable_hash


ROOT_BROKER_CLIENT = "/data/local/tmp/dfroot-su"
VECTOR_MODULE_DIRECTORY = "/data/adb/modules/zygisk_vector"


@dataclass(frozen=True)
class DeviceSnapshot:
    serial_hash: str
    model: str
    android_release: str
    sdk: str
    abi: str
    display_id: str
    incremental: str
    kernel: str
    boot_id: str
    boot_id_hash: str
    selinux_mode: str
    shell_identity: str
    root_available: bool
    root_identity: str
    magisk_version: str
    zygisk_status: str
    vector_status: dict[str, Any] | None
    vector_error: str
    system_server_pid: str
    surfaceflinger_pid: str
    boot_adb_port: str

    def identity(self) -> dict[str, str]:
        return {
            "model": self.model,
            "android_release": self.android_release,
            "sdk": self.sdk,
            "abi": self.abi,
            "display_id": self.display_id,
            "incremental": self.incremental,
            "kernel": self.kernel,
        }

    def public_dict(self) -> dict[str, Any]:
        return {
            "serial_hash": self.serial_hash,
            "model": self.model,
            "android_release": self.android_release,
            "sdk": self.sdk,
            "abi": self.abi,
            "display_id": self.display_id,
            "incremental": self.incremental,
            "kernel": self.kernel,
            "boot_id_hash": self.boot_id_hash,
            "selinux_mode": self.selinux_mode,
            "shell_identity": self.shell_identity,
            "root_available": self.root_available,
            "root_identity": self.root_identity,
            "magisk_version": self.magisk_version,
            "zygisk_status": self.zygisk_status,
            "vector_status": self.vector_status,
            "vector_error": self.vector_error,
            "system_server_pid": self.system_server_pid,
            "surfaceflinger_pid": self.surfaceflinger_pid,
            "boot_adb_port": self.boot_adb_port,
        }


def _shell_text_or_empty(
    client: AdbClient,
    command: str,
    timeout_seconds: float = 8.0,
) -> str:
    result = client.shell(command, timeout_seconds=timeout_seconds)
    if not result.succeeded:
        return ""
    return result.stdout.replace("\r\n", "\n").strip()


def _read_property(client: AdbClient, property_name: str) -> str:
    return _shell_text_or_empty(client, f"getprop {property_name}")


def _read_identity_values(client: AdbClient) -> dict[str, str]:
    command = """
printf 'model=%s\n' "$(getprop ro.product.model)"
printf 'android_release=%s\n' "$(getprop ro.build.version.release)"
printf 'sdk=%s\n' "$(getprop ro.build.version.sdk)"
printf 'abi=%s\n' "$(getprop ro.product.cpu.abi)"
printf 'display_id=%s\n' "$(getprop ro.build.display.id)"
printf 'incremental=%s\n' "$(getprop ro.build.version.incremental)"
printf 'kernel=%s\n' "$(uname -r)"
printf 'boot_id=%s\n' "$(cat /proc/sys/kernel/random/boot_id)"
printf 'selinux_mode=%s\n' "$(getenforce)"
printf 'shell_identity=%s\n' "$(id)"
printf 'boot_adb_port=%s\n' "$(getprop service.adb.tcp.port)"
printf 'system_server_pid=%s\n' "$(pidof system_server | awk '{ print $1 }')"
printf 'surfaceflinger_pid=%s\n' "$(pidof surfaceflinger | awk '{ print $1 }')"
""".strip()
    raw_output = _shell_text_or_empty(client, command)
    values: dict[str, str] = {}
    for line in raw_output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def _probe_root(client: AdbClient) -> CommandResult:
    candidate_commands = [
        f"{ROOT_BROKER_CLIENT} -c id",
        "/system/bin/su -c id",
        "su -c id",
    ]
    last_result: CommandResult | None = None
    transient_failure = False

    for attempt_index in range(2):
        for candidate_command in candidate_commands:
            result = client.shell(candidate_command, timeout_seconds=6.0)
            last_result = result
            if "uid=0(root)" in result.stdout:
                return result
            if result.timed_out or result.returncode in {124, 125}:
                transient_failure = True
        if attempt_index == 0 and transient_failure:
            time.sleep(0.5)
            continue
        break

    if last_result is None:
        raise AdbError("Root probe did not run.")
    return last_result


def _run_root_command(
    client: AdbClient,
    command: str,
    timeout_seconds: float = 8.0,
) -> CommandResult:
    broker_result = client.shell(
        f"{ROOT_BROKER_CLIENT} -c {shlex.quote(command)}",
        timeout_seconds=timeout_seconds,
    )
    if broker_result.succeeded or broker_result.stdout.strip():
        return broker_result
    return client.shell(
        f"/system/bin/su -c {shlex.quote(command)}",
        timeout_seconds=timeout_seconds,
    )


def _vector_cli_status_command() -> str:
    return f"""
zygote_pid="$(pidof zygote64 | awk '{{ print $1 }}')"
if [ -z "$zygote_pid" ]; then
  echo "zygote64 is not running" >&2
  exit 1
fi
for android_env_name in \\
  ANDROID_ROOT \\
  ANDROID_DATA \\
  ANDROID_ART_ROOT \\
  ANDROID_I18N_ROOT \\
  ANDROID_TZDATA_ROOT \\
  BOOTCLASSPATH \\
  DEX2OATBOOTCLASSPATH; do
  android_env_value="$(
    tr '\\0' '\\n' <"/proc/$zygote_pid/environ" |
      sed -n "s/^$android_env_name=//p" |
      head -n 1
  )"
  if [ -n "$android_env_value" ]; then
    export "$android_env_name=$android_env_value"
  fi
done
exec /debug_ramdisk/busybox nsenter -t 1 -m -w{VECTOR_MODULE_DIRECTORY} \\
  /system/bin/app_process \\
  -Djava.class.path={VECTOR_MODULE_DIRECTORY}/daemon.apk \\
  -Duser.dir={VECTOR_MODULE_DIRECTORY} \\
  -Djava.io.tmpdir=/data/local/tmp \\
  /system/bin org.matrix.vector.daemon.Cli --json status
""".strip()


def _parse_vector_status(raw_output: str) -> dict[str, Any] | None:
    stripped_output = raw_output.strip()
    if not stripped_output:
        return None

    opening_brace = stripped_output.find("{")
    if opening_brace < 0:
        return None

    try:
        parsed_output = json.loads(stripped_output[opening_brace:])
    except json.JSONDecodeError:
        return None

    if not isinstance(parsed_output, dict):
        return None
    return parsed_output


def _read_zygisk_status(client: AdbClient, root_available: bool) -> str:
    module_property_path = "/data/system_de/nyazygisk/module.prop"
    if root_available:
        root_result = _run_root_command(
            client,
            f"cat {module_property_path}",
        )
        raw_output = (
            root_result.stdout.replace("\r\n", "\n").strip()
            if root_result.succeeded or root_result.stdout.strip()
            else ""
        )
    else:
        raw_output = _shell_text_or_empty(
            client,
            f"cat {module_property_path}",
            timeout_seconds=8.0,
        )

    status_values: dict[str, str] = {}
    for line in raw_output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        status_values[key.strip()] = value.strip()

    if not status_values:
        return "unavailable"
    if status_values.get("zygote_64_status") == "injected":
        return "injected"
    return status_values.get("zygote_64_status", "unknown")


def _read_vector_status(
    client: AdbClient,
    root_available: bool,
) -> tuple[dict[str, Any] | None, str]:
    if not root_available:
        return None, "root is not active"

    result = client.shell(
        f"{ROOT_BROKER_CLIENT} -c "
        f"{shlex.quote(_vector_cli_status_command())}",
        timeout_seconds=15.0,
    )
    if not result.succeeded and not result.stdout.strip():
        vector_cli = f"{VECTOR_MODULE_DIRECTORY}/cli"
        result = client.shell(
            f"/system/bin/su -c {shlex.quote(f'{vector_cli} --json status')}",
            timeout_seconds=10.0,
        )
    if not result.succeeded and not result.stdout.strip():
        return None, result.stderr.strip() or "Vector status command failed"

    parsed_status = _parse_vector_status(result.stdout)
    if parsed_status is None:
        return None, "Vector status output is not valid JSON"
    if parsed_status.get("success") is not True:
        return parsed_status, "Vector reported a failed status"
    return parsed_status, ""


def collect_snapshot(client: AdbClient) -> DeviceSnapshot:
    identity_values = _read_identity_values(client)
    model = identity_values.get("model", "")
    android_release = identity_values.get("android_release", "")
    sdk = identity_values.get("sdk", "")
    abi = identity_values.get("abi", "")
    display_id = identity_values.get("display_id", "")
    incremental = identity_values.get("incremental", "")
    kernel = identity_values.get("kernel", "")
    boot_id = identity_values.get("boot_id", "")
    selinux_mode = identity_values.get("selinux_mode", "")
    shell_identity = identity_values.get("shell_identity", "")
    boot_adb_port = identity_values.get("boot_adb_port", "")
    system_server_pid = identity_values.get("system_server_pid", "")
    surfaceflinger_pid = identity_values.get("surfaceflinger_pid", "")

    root_probe_result = _probe_root(client)
    root_identity = root_probe_result.stdout.replace("\r\n", "\n").strip()
    root_available = "uid=0(root)" in root_identity

    magisk_version = ""
    if root_available:
        magisk_result = _run_root_command(
            client,
            "/debug_ramdisk/magisk -v",
        )
        if magisk_result.succeeded or magisk_result.stdout.strip():
            magisk_version = magisk_result.stdout.strip()

    zygisk_status = _read_zygisk_status(client, root_available)
    vector_status, vector_error = _read_vector_status(client, root_available)

    return DeviceSnapshot(
        serial_hash=stable_hash(client.serial),
        model=model,
        android_release=android_release,
        sdk=sdk,
        abi=abi,
        display_id=display_id,
        incremental=incremental,
        kernel=kernel,
        boot_id=boot_id,
        boot_id_hash=stable_hash(boot_id),
        selinux_mode=selinux_mode,
        shell_identity=shell_identity,
        root_available=root_available,
        root_identity=root_identity,
        magisk_version=magisk_version,
        zygisk_status=zygisk_status,
        vector_status=vector_status,
        vector_error=vector_error,
        system_server_pid=system_server_pid,
        surfaceflinger_pid=surfaceflinger_pid,
        boot_adb_port=boot_adb_port,
    )
