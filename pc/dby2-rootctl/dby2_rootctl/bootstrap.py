from __future__ import annotations

import re
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from dby2_rootctl.adb import AdbClient, CommandResult
from dby2_rootctl.xposed import XposedError, shell_quote


MAGISK_PACKAGE = "com.topjohnwu.magisk"
ROOT_BROKER_CLIENT = "/data/local/tmp/dfroot-su"

APK_ASSET_MAPPINGS = {
    "assets/one_tap_root/setup-magisk.sh": "/data/local/tmp/one-tap-setup-magisk.sh",
    "assets/one_tap_root/magisk-wrapper.sh": "/data/local/tmp/one-tap-magisk-wrapper.sh",
    "assets/one_tap_root/su-wrapper.sh": "/data/local/tmp/one-tap-su-wrapper.sh",
    "assets/one_tap_root/activate-xposed.sh": "/data/local/tmp/one-tap-activate-xposed.sh",
    "assets/one_tap_root/vector-service-compat.sh": "/data/local/tmp/one-tap-vector-service.sh",
    "assets/util_functions.sh": "/data/local/tmp/one-tap-util_functions.sh",
    "assets/boot_patch.sh": "/data/local/tmp/one-tap-boot_patch.sh",
}


@dataclass(frozen=True)
class MagiskAppInfo:
    uid: int
    code_path: str
    native_directory: str
    version_name: str


def parse_magisk_package_info(raw_output: str) -> MagiskAppInfo:
    uid_match = re.search(r"^\s*userId=(\d+)\s*$", raw_output, re.MULTILINE)
    code_path_match = re.search(
        r"^\s*codePath=(.+?)\s*$",
        raw_output,
        re.MULTILINE,
    )
    version_match = re.search(
        r"^\s*versionName=(\S+)\s*$",
        raw_output,
        re.MULTILINE,
    )
    if uid_match is None or code_path_match is None or version_match is None:
        raise XposedError("Could not parse Magisk package information.")

    code_path = code_path_match.group(1).strip()
    return MagiskAppInfo(
        uid=int(uid_match.group(1)),
        code_path=code_path,
        native_directory=f"{code_path}/lib/arm64",
        version_name=version_match.group(1),
    )


class MagiskBootstrap:
    def __init__(self, client: AdbClient):
        self.client = client

    def run_root(
        self,
        command: str,
        timeout_seconds: float = 180.0,
    ) -> CommandResult:
        broker_probe = self.client.shell(
            f"test -x {ROOT_BROKER_CLIENT}",
            timeout_seconds=5.0,
        )
        if broker_probe.succeeded:
            return self.client.shell(
                f"{ROOT_BROKER_CLIENT} -c {shell_quote(command)}",
                timeout_seconds=timeout_seconds,
            )

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
        return result

    def install_apk(self, apk_path: Path) -> None:
        install_result = self.client.install(apk_path)
        if not install_result.succeeded:
            raise XposedError(
                f"Magisk APK install failed: "
                f"{install_result.stderr.strip() or install_result.stdout.strip()}"
            )

    def read_package_info(self) -> MagiskAppInfo:
        result = self.client.shell(
            f"dumpsys package {MAGISK_PACKAGE}",
            timeout_seconds=20.0,
        )
        if not result.succeeded:
            raise XposedError("Could not inspect the installed Magisk package.")
        return parse_magisk_package_info(result.stdout)

    def stage_apk_assets(self, apk_path: Path) -> None:
        with tempfile.TemporaryDirectory(prefix="dby2-magisk-assets-") as temporary:
            temporary_path = Path(temporary)
            with zipfile.ZipFile(apk_path) as apk:
                for asset_name, remote_path in APK_ASSET_MAPPINGS.items():
                    try:
                        asset_bytes = apk.read(asset_name)
                    except KeyError as error:
                        raise XposedError(
                            f"Magisk APK is missing required asset: {asset_name}"
                        ) from error

                    local_path = temporary_path / Path(asset_name).name
                    local_path.write_bytes(asset_bytes)
                    push_result = self.client.push(local_path, remote_path)
                    if not push_result.succeeded:
                        raise XposedError(
                            f"Failed to stage {asset_name}: "
                            f"{push_result.stderr.strip() or push_result.stdout.strip()}"
                        )

    def install_magisk(
        self,
        apk_path: Path,
        app_info: MagiskAppInfo,
    ) -> str:
        self.stage_apk_assets(apk_path)
        setup_command = (
            f"sh /data/local/tmp/one-tap-setup-magisk.sh "
            f"{app_info.uid} {shell_quote(app_info.native_directory)} "
            f"{shell_quote(app_info.version_name)}"
        )
        result = self.run_root(setup_command, timeout_seconds=180.0)
        output = result.stdout.strip()
        if "MAGISK_READY" not in output:
            raise XposedError(
                f"Magisk environment setup did not complete: {output}"
            )
        return output

    def install_module(
        self,
        module_zip: Path,
        replace_existing: bool = False,
    ) -> str:
        module_id = self._read_module_id(module_zip)
        remote_path = f"/data/local/tmp/{module_zip.name}"
        push_result = self.client.push(module_zip, remote_path)
        if not push_result.succeeded:
            raise XposedError(
                f"Failed to push module {module_zip.name}: "
                f"{push_result.stderr.strip() or push_result.stdout.strip()}"
            )

        install_result = self.run_root(
            f"/system/bin/magisk --install-module {remote_path}",
            timeout_seconds=180.0,
        )
        if not install_result.succeeded:
            raise XposedError(
                f"Magisk module install failed for {module_zip.name}: "
                f"{install_result.stderr.strip() or install_result.stdout.strip()}"
            )

        if replace_existing:
            activation_command = (
                "mkdir -p /data/local/tmp/dby2-module-backup && "
                f"if [ ! -d /data/adb/modules_update/{module_id} ]; then "
                "echo MODULE_UPDATE_MISSING; exit 4; fi; "
                f"if [ -d /data/adb/modules/{module_id} ]; then "
                f"mv /data/adb/modules/{module_id} "
                f"/data/local/tmp/dby2-module-backup/{module_id}.$(date +%s); "
                "fi; "
                f"mv /data/adb/modules_update/{module_id} "
                f"/data/adb/modules/{module_id}"
            )
        else:
            activation_command = (
                "if [ -d /data/adb/modules_update/"
                f"{module_id} ] && [ ! -e /data/adb/modules/{module_id} ]; "
                f"then mv /data/adb/modules_update/{module_id} "
                f"/data/adb/modules/{module_id}; fi"
            )

        install = self.run_root(activation_command)
        if not install.succeeded:
            raise XposedError(
                f"Could not activate fresh module {module_id}: "
                f"{install.stderr.strip() or install.stdout.strip()}"
            )
        if "MODULE_UPDATE_MISSING" in install.stdout:
            raise XposedError(
                f"Magisk did not stage the module update for {module_id}."
            )
        return install_result.stdout.strip()

    def activate_runtime(self) -> str:
        log_size_result = self.run_root(
            "if [ -f /data/local/tmp/dby2-xposed-activate.log ]; "
            "then wc -c < /data/local/tmp/dby2-xposed-activate.log; "
            "else echo 0; fi"
        )
        try:
            previous_log_size = int(log_size_result.stdout.strip())
        except ValueError:
            previous_log_size = 0

        result = self.run_root(
            "sh /data/local/tmp/one-tap-activate-xposed.sh",
            timeout_seconds=240.0,
        )
        output = result.stdout.strip()
        if "DBY2_XPOSED_READY" in output:
            return output

        log_result = self.run_root(
            "tail -c "
            f"+{previous_log_size + 1} "
            "/data/local/tmp/dby2-xposed-activate.log"
        )
        current_activation_log = log_result.stdout.strip()
        if "DBY2_XPOSED_READY" in current_activation_log:
            return current_activation_log
        raise XposedError(
            "Vector activation did not complete: "
            f"{output or current_activation_log}"
        )

    @staticmethod
    def _read_module_id(module_zip: Path) -> str:
        with zipfile.ZipFile(module_zip) as archive:
            try:
                module_prop = archive.read("module.prop").decode("utf-8")
            except KeyError as error:
                raise XposedError(
                    f"Module ZIP has no module.prop: {module_zip}"
                ) from error

        for line in module_prop.splitlines():
            if line.startswith("id="):
                module_id = line.removeprefix("id=").strip()
                if module_id:
                    return module_id
        raise XposedError(f"Module ZIP has no module id: {module_zip}")
