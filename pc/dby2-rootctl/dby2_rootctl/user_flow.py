from __future__ import annotations

import contextlib
import io
import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from dby2_rootctl.adb import (
    AdbClient,
    list_devices,
    select_device,
    start_adb_server,
)
from dby2_rootctl.cli import main as command_main
from dby2_rootctl.device import DeviceSnapshot, collect_snapshot
from dby2_rootctl.profile import (
    DeviceProfile,
    ProfileEvaluation,
    evaluate_identity,
    load_profile,
)
from dby2_rootctl.user_release import UserReleaseLayout


class UserFlowError(RuntimeError):
    pass


ONE_TAP_ROOT_SERVICE = (
    "com.topjohnwu.magisk/.core.root.OneTapRootService"
)
SERVICE_START_TIMEOUT_SECONDS = 20.0
SERVICE_COMPLETE_TIMEOUT_SECONDS = 150.0
RUNTIME_READY_TIMEOUT_SECONDS = 30.0
LOCAL_ADB_PORT = "5555"
TIMEOUT_CLEANUP_PACKAGES = (
    "com.topjohnwu.magisk",
    "org.matrix.vector.manager",
    "dev.dby2.rootkit",
)


class DeviceAccessError(UserFlowError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class DeviceConnection:
    client: AdbClient
    snapshot: DeviceSnapshot
    profile: DeviceProfile
    evaluation: ProfileEvaluation


class _CallbackWriter(io.TextIOBase):
    def __init__(self, callback: Callable[[str], None]):
        self.callback = callback

    def write(self, text: str) -> int:
        if text:
            self.callback(text)
        return len(text)

    def flush(self) -> None:
        return None


class UserFlow:
    def __init__(
        self,
        layout: UserReleaseLayout,
        log_callback: Callable[[str], None] | None = None,
    ):
        self.layout = layout
        self.log_callback = log_callback or (lambda message: None)

    def _log(self, message: str) -> None:
        self.log_callback(message)

    def connect(
        self,
        serial: str | None = None,
        wait_seconds: float = 8.0,
    ) -> DeviceConnection:
        self.layout.validate()

        server_result = start_adb_server(self.layout.adb_path)
        if not server_result.succeeded:
            raise DeviceAccessError(
                "adb_server_failed",
                "无法启动发行包内的 ADB 服务。"
                f"{server_result.stderr.strip() or server_result.stdout.strip()}",
            )

        online_devices = []
        unauthorized_devices = []
        deadline = time.monotonic() + wait_seconds
        while time.monotonic() < deadline:
            devices = list_devices(self.layout.adb_path)
            online_devices = [
                device
                for device in devices
                if device.state == "device"
                and (serial is None or device.serial == serial)
            ]
            unauthorized_devices = [
                device
                for device in devices
                if device.state == "unauthorized"
                and (serial is None or device.serial == serial)
            ]
            if online_devices:
                break
            if unauthorized_devices:
                break
            time.sleep(0.5)

        if not online_devices and unauthorized_devices:
            raise DeviceAccessError(
                "device_unauthorized",
                "平板已连接，但尚未允许这台电脑进行 USB 调试。",
            )
        if not online_devices:
            raise DeviceAccessError(
                "device_not_found",
                "未检测到 ADB 调试接口。请在开发者选项中同时开启"
                "“USB 调试”和“仅充电模式下允许 ADB 调试”，"
                "USB 连接方式选择“传输文件”，然后重新插拔数据线。",
            )

        selected_device = select_device(
            self.layout.adb_path,
            requested_serial=serial,
        )
        client = AdbClient(
            self.layout.adb_path,
            selected_device.serial,
        )
        snapshot = collect_snapshot(client)
        profile = load_profile(self.layout.profile_directory)
        evaluation = evaluate_identity(profile, snapshot.identity())
        if not evaluation.succeeded:
            failed_checks = [
                check.name
                for check in evaluation.checks
                if not check.succeeded
            ]
            raise DeviceAccessError(
                "device_mismatch",
                "设备不匹配，已停止 Root。未通过检查："
                + ", ".join(failed_checks)
            )
        return DeviceConnection(
            client=client,
            snapshot=snapshot,
            profile=profile,
            evaluation=evaluation,
        )

    def one_click_root(
        self,
        serial: str | None = None,
    ) -> dict[str, object]:
        self._log("检查设备连接和系统版本...")
        connection = self.connect(serial)
        self._log(
            "设备已通过检查："
            f"{connection.snapshot.model} / "
            f"{connection.snapshot.display_id}"
        )

        self._install_magisk(connection.client)
        connection = self._run_one_tap_installation(connection)
        rootkit_installed = self._package_installed(
            connection.client,
            "dev.dby2.rootkit",
        )
        if not rootkit_installed:
            self._install_rootkit(connection.client)

        self._log("执行 Root、Zygisk 和 Vector 完整验证...")
        result = self._run_command(
            self._common_arguments(connection)
            + ["verify", "--require-xposed"],
            accepted_exit_codes=frozenset({9}),
            log_output=False,
        )
        if result.get("ok") is not True:
            failed_checks = result.get("failed_checks", [])
            detail = ", ".join(str(check) for check in failed_checks)
            raise UserFlowError(
                "完整验证未通过"
                + (f"：{detail}" if detail else "")
            )

        self._persist_adb_tcp_port(connection.client)
        self._launch_rootkit(connection.client)
        self._log("完整验证通过。")
        self._log(
            "Root 环境已启动。请在平板弹窗中点击“允许”，"
            "然后点击“验证状态”。"
        )
        return result

    def schedule_framework_restart(
        self,
        connection: DeviceConnection,
        delay_seconds: float = 10.0,
        completion_callback: Callable[[bool, str], None] | None = None,
    ) -> None:
        self._log(f"系统框架将在 {delay_seconds:g} 秒后软重启。")
        threading.Thread(
            target=self._restart_framework_after_delay,
            args=(connection, delay_seconds, completion_callback),
            daemon=True,
            name="dby2-soft-reboot",
        ).start()

    def _restart_framework_after_delay(
        self,
        connection: DeviceConnection,
        delay_seconds: float,
        completion_callback: Callable[[bool, str], None] | None,
    ) -> None:
        if delay_seconds > 0:
            time.sleep(delay_seconds)

        try:
            result = connection.client.shell(
                "/data/local/tmp/dfroot-su -c "
                "'setprop ctl.restart zygote'",
                timeout_seconds=15.0,
            )
        except Exception as error:
            message = f"软重启命令执行失败：{error}"
            self._log(message)
            if completion_callback is not None:
                completion_callback(False, message)
            return

        if result.succeeded:
            message = "已触发系统框架软重启，等待平板恢复。"
            self._log(message)
            if completion_callback is not None:
                completion_callback(True, message)
            return

        detail = result.stderr.strip() or result.stdout.strip() or "未知错误"
        message = f"软重启命令执行失败：{detail}"
        self._log(message)
        if completion_callback is not None:
            completion_callback(False, message)

    def _run_one_tap_installation(
        self,
        connection: DeviceConnection,
    ) -> DeviceConnection:
        client = connection.client
        current_port_result = client.shell(
            "getprop service.adb.tcp.port",
            timeout_seconds=8.0,
        )
        if (
            not current_port_result.succeeded
            or current_port_result.stdout.strip() != "5555"
        ):
            self._log("启用本机 ADB Root 通道...")
            tcpip_result = client.run(["tcpip", "5555"], timeout_seconds=45.0)
            if not tcpip_result.succeeded:
                detail = tcpip_result.stderr.strip() or tcpip_result.stdout.strip()
                raise UserFlowError(f"本机 ADB Root 通道启动失败：{detail}")
            self._wait_for_pc_adb_connection(client.serial)

        service_result = client.shell(
            "am start-foreground-service "
            "-n com.topjohnwu.magisk/"
            "com.topjohnwu.magisk.core.root.OneTapRootService "
            "-a com.topjohnwu.magisk.action.ONE_TAP_ROOT",
            timeout_seconds=20.0,
        )
        if not service_result.succeeded:
            detail = (
                service_result.stderr.strip()
                or service_result.stdout.strip()
            )
            raise UserFlowError(f"Magisk Root 服务启动失败：{detail}")

        self._log(
            "Magisk 正在后台执行完整 Root、模块安装与 Vector 激活；"
            "首次使用请在平板允许 Magisk 的本机 ADB 调试请求..."
        )
        self._wait_for_one_tap_root_service(client)
        return self._wait_for_ready_runtime(connection)

    def _persist_adb_tcp_port(self, client: AdbClient) -> None:
        self._log("配置后续启动的本机 ADB Root 通道...")
        set_command = (
            f"/data/local/tmp/dfroot-su -c "
            f"'setprop persist.adb.tcp.port {LOCAL_ADB_PORT}'"
        )
        set_result = client.shell(set_command, timeout_seconds=15.0)
        if not set_result.succeeded:
            fallback_command = (
                f"/system/bin/su -c "
                f"'setprop persist.adb.tcp.port {LOCAL_ADB_PORT}'"
            )
            set_result = client.shell(
                fallback_command,
                timeout_seconds=15.0,
            )
        if not set_result.succeeded:
            detail = set_result.stderr.strip() or set_result.stdout.strip()
            raise UserFlowError(f"持久化本机 ADB 端口失败：{detail}")

        verify_result = client.shell(
            "getprop persist.adb.tcp.port",
            timeout_seconds=8.0,
        )
        actual_port = verify_result.stdout.strip()
        if not verify_result.succeeded or actual_port != LOCAL_ADB_PORT:
            raise UserFlowError(
                "持久化本机 ADB 端口校验失败："
                f"expected={LOCAL_ADB_PORT}, actual={actual_port}"
            )

    def _wait_for_one_tap_root_service(self, client: AdbClient) -> None:
        start_deadline = (
            time.monotonic() + SERVICE_START_TIMEOUT_SECONDS
        )
        service_started = False
        while time.monotonic() < start_deadline:
            service_state = self._one_tap_service_state(client)
            if service_state is True:
                service_started = True
                break
            time.sleep(0.5)

        if not service_started:
            raise UserFlowError(
                "Magisk 后台服务未能启动。"
                "请确认平板已允许 Magisk 的本机 ADB 调试请求。"
            )

        complete_deadline = (
            time.monotonic() + SERVICE_COMPLETE_TIMEOUT_SECONDS
        )
        next_status_log = time.monotonic() + 15.0
        while time.monotonic() < complete_deadline:
            service_state = self._one_tap_service_state(client)
            if service_state is False:
                self._log("Magisk 后台安装与 Vector 激活已完成。")
                return

            current_time = time.monotonic()
            if current_time >= next_status_log:
                self._log("等待 Magisk 完成组件安装与 Vector 激活...")
                next_status_log = current_time + 15.0
            time.sleep(1.0)

        self._log("等待超过 150 秒，正在卸载 Magisk、Vector 和 DBY2 RootKit...")
        for package_name in TIMEOUT_CLEANUP_PACKAGES:
            client.shell(
                f"pm uninstall --user 0 {package_name}",
                timeout_seconds=45.0,
            )

        self._log("正在通过 ADB 重启平板...")
        client.shell("reboot", timeout_seconds=15.0)
        raise UserFlowError(
            "等待 Magisk 后台安装与 Vector 激活超过 150 秒。"
            "已卸载 Magisk、Vector 和 DBY2 RootKit，"
            "并执行 adb shell reboot。"
            "请在平板重启完成后重新点击“一键 Root”。"
        )

    def _wait_for_ready_runtime(
        self,
        connection: DeviceConnection,
    ) -> DeviceConnection:
        deadline = (
            time.monotonic() + RUNTIME_READY_TIMEOUT_SECONDS
        )
        latest_snapshot: DeviceSnapshot | None = None
        while time.monotonic() < deadline:
            latest_snapshot = collect_snapshot(connection.client)
            vector_ready = bool(
                latest_snapshot.vector_status
                and latest_snapshot.vector_status.get("success") is True
            )
            if (
                latest_snapshot.root_available
                and latest_snapshot.magisk_version
                and latest_snapshot.zygisk_status == "injected"
                and vector_ready
            ):
                return DeviceConnection(
                    client=connection.client,
                    snapshot=latest_snapshot,
                    profile=connection.profile,
                    evaluation=connection.evaluation,
                )
            time.sleep(1.0)

        if latest_snapshot is None:
            raise UserFlowError("Magisk 后台服务已退出，但无法读取运行状态。")
        raise UserFlowError(
            "Magisk 后台服务已退出，但运行环境未就绪："
            f"root={latest_snapshot.root_available}, "
            f"magisk={latest_snapshot.magisk_version or 'unavailable'}, "
            f"zygisk={latest_snapshot.zygisk_status}, "
            f"vector={latest_snapshot.vector_error or 'unavailable'}"
        )

    @staticmethod
    def _one_tap_service_state(client: AdbClient) -> bool | None:
        result = client.shell(
            "dumpsys activity services com.topjohnwu.magisk",
            timeout_seconds=10.0,
        )
        if not result.succeeded:
            return None
        return ONE_TAP_ROOT_SERVICE in result.stdout

    def _install_magisk(self, client: AdbClient) -> None:
        self._log("安装或更新发行包内的移植 Magisk...")
        install_result = client.install(self.layout.magisk_apk.path)
        if not install_result.succeeded:
            detail = install_result.stderr.strip() or install_result.stdout.strip()
            raise UserFlowError(f"Magisk APK 安装失败：{detail}")

    def _wait_for_pc_adb_connection(self, serial: str) -> None:
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            devices = list_devices(self.layout.adb_path)
            if any(
                device.serial == serial and device.state == "device"
                for device in devices
            ):
                return
            time.sleep(0.5)
        raise UserFlowError("设备重启 ADB 后未重新连接，请保持 USB 数据线连接。")

    def verify(self, serial: str | None = None) -> dict[str, object]:
        connection = self.connect(serial)
        self._log("执行 Root、Zygisk 和 Vector 完整验证...")
        return self._run_command(
            self._common_arguments(connection)
            + ["verify", "--require-xposed"],
            accepted_exit_codes=frozenset({9}),
            log_output=False,
        )

    def export_diagnostics(
        self,
        output_path: Path,
        serial: str | None = None,
    ) -> Path:
        connection = self.connect(serial)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        self._log("生成脱敏诊断包...")
        self._run_command(
            self._common_arguments(connection)
            + [
                "logs",
                "--output",
                str(output_path),
            ]
        )
        return output_path

    def _common_arguments(
        self,
        connection: DeviceConnection,
    ) -> list[str]:
        return [
            "--adb",
            str(self.layout.adb_path),
            "--serial",
            connection.client.serial,
            "--profile-dir",
            str(self.layout.profile_directory),
            "--json",
        ]

    def _run_command(
        self,
        arguments: list[str],
        accepted_exit_codes: frozenset[int] = frozenset(),
        log_output: bool = True,
    ) -> dict[str, object]:
        output = io.StringIO()
        error_output = io.StringIO()
        callback_writer = _CallbackWriter(self._log)
        with (
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(error_output),
        ):
            exit_code = command_main(arguments)
        captured_output = output.getvalue()
        captured_error = error_output.getvalue()
        if log_output and captured_output:
            callback_writer.write(captured_output)
        if captured_error:
            callback_writer.write(captured_error)

        json_start = captured_output.find("{")
        parsed_result: dict[str, object] | None = None
        if json_start >= 0:
            try:
                candidate_result = json.loads(captured_output[json_start:])
            except json.JSONDecodeError:
                candidate_result = None
            if isinstance(candidate_result, dict):
                parsed_result = candidate_result

        if exit_code != 0 and exit_code not in accepted_exit_codes:
            raise UserFlowError(
                f"操作失败，退出码 {exit_code}。"
                f"{captured_error.strip() or captured_output.strip()}"
            )

        if parsed_result is not None:
            return parsed_result
        return {
            "ok": exit_code == 0,
            "output": captured_output.strip(),
        }

    @staticmethod
    def _package_installed(client: AdbClient, package_name: str) -> bool:
        package_result = client.shell(
            f"pm path {package_name}",
            timeout_seconds=10.0,
        )
        return (
            package_result.succeeded
            and "package:" in package_result.stdout
        )

    def _launch_rootkit(self, client: AdbClient) -> None:
        client.shell(
            "input keyevent KEYCODE_WAKEUP",
            timeout_seconds=5.0,
        )
        client.shell(
            "wm dismiss-keyguard",
            timeout_seconds=5.0,
        )
        client.shell(
            "am force-stop dev.dby2.rootkit",
            timeout_seconds=5.0,
        )
        client.shell(
            "monkey -p dev.dby2.rootkit "
            "-c android.intent.category.LAUNCHER 1",
            timeout_seconds=15.0,
        )
        time.sleep(2.0)

    def _install_rootkit(self, client: AdbClient) -> None:
        self._log("安装 RootKit 管理应用...")
        install_result = client.install(self.layout.rootkit_apk.path)
        if not install_result.succeeded:
            detail = install_result.stderr.strip() or install_result.stdout.strip()
            raise UserFlowError(f"RootKit APK 安装失败：{detail}")
