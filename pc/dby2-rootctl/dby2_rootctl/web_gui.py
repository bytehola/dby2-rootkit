from __future__ import annotations

import atexit
import json
import os
import sys
import threading
from pathlib import Path
from typing import Any

from dby2_rootctl import __version__
from dby2_rootctl.adb import (
    AdbError,
    stop_adb_server,
)
from dby2_rootctl.user_flow import (
    DeviceAccessError,
    DeviceConnection,
    UserFlow,
    UserFlowError,
)
from dby2_rootctl.user_release import (
    UserReleaseError,
    UserReleaseLayout,
)


APP_TITLE = "DBY2 RootKit"
APP_VERSION = __version__
SOFT_REBOOT_DELAY_SECONDS = 10.0


def ensure_standard_streams() -> None:
    if sys.stdout is None:
        sys.stdout = open(
            os.devnull,
            "w",
            encoding="utf-8",
        )
    if sys.stderr is None:
        sys.stderr = open(
            os.devnull,
            "w",
            encoding="utf-8",
        )


# PyInstaller windowed mode leaves standard streams unset for pythonnet.
ensure_standard_streams()

import webview


def application_base_directory() -> Path:
    configured_directory = os.environ.get("DBY2_RELEASE_DIR", "").strip()
    if configured_directory:
        return Path(configured_directory)
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[3]


def web_directory() -> Path:
    configured_directory = os.environ.get("DBY2_WEB_DIR", "").strip()
    if configured_directory:
        return Path(configured_directory).resolve()
    return application_base_directory() / "ui"


class WebViewApi:
    def __init__(self, layout: UserReleaseLayout):
        self._layout = layout
        self._window = None
        self._flow = UserFlow(layout, log_callback=self._forward_log)
        self._operation_started = False
        self._operation_lock = threading.Lock()
        self._shutdown_started = False

    def _attach_window(self, window) -> None:
        self._window = window

    def get_initial_state(self) -> dict[str, Any]:
        return {
            "ok": True,
            "product": APP_TITLE,
            "version": APP_VERSION,
            "device_guide_version": "HarmonyOS 4.2",
        }

    def probe_device(self) -> dict[str, Any]:
        try:
            connection = self._flow.connect(wait_seconds=2.5)
            return {
                "ok": True,
                "device": self._device_payload(connection),
            }
        except (AdbError, UserFlowError, UserReleaseError) as error:
            return {
                "ok": False,
                "error": self._error_payload(error),
            }

    def stop_adb(self) -> None:
        if self._shutdown_started:
            return
        self._shutdown_started = True
        try:
            stop_adb_server(self._layout.adb_path)
        except (AdbError, OSError, TimeoutError):
            return

    def start_one_click(self) -> dict[str, Any]:
        if not self._acquire_operation():
            return {
                "started": False,
                "message": "已经有一个操作正在执行。",
            }

        threading.Thread(
            target=self._run_one_click,
            daemon=True,
            name="dby2-web-root",
        ).start()
        return {"started": True}

    def start_verification(self) -> dict[str, Any]:
        if not self._acquire_operation():
            return {
                "started": False,
                "message": "已经有一个操作正在执行。",
            }

        threading.Thread(
            target=self._run_verification,
            daemon=True,
            name="dby2-web-verify",
        ).start()
        return {"started": True}

    def save_diagnostics(self) -> dict[str, Any]:
        default_name = "DBY2-RootKit-diagnostics.zip"
        selected_path = self._window.create_file_dialog(
            webview.SAVE_DIALOG,
            save_filename=default_name,
            file_types=("ZIP 压缩包 (*.zip)",),
        )
        if not selected_path:
            return {"ok": False, "cancelled": True}
        if isinstance(selected_path, (list, tuple)):
            selected_path = selected_path[0]
        output_path = Path(selected_path)
        try:
            self._flow.export_diagnostics(output_path)
            return {
                "ok": True,
                "path": str(output_path),
            }
        except (AdbError, UserFlowError, UserReleaseError) as error:
            return {
                "ok": False,
                "error": self._error_payload(error),
            }

    def _run_one_click(self) -> None:
        self._emit("busy", {"busy": True})
        self._emit("progress", {"text": "正在检查设备并准备 Root 环境"})
        self._emit("summary", {"text": "正在获取 Root"})
        try:
            self._flow.one_click_root()
            connection = self._flow.connect(wait_seconds=2.0)
            self._emit("device", self._device_payload(connection))
            self._flow.schedule_framework_restart(
                connection,
                delay_seconds=SOFT_REBOOT_DELAY_SECONDS,
                completion_callback=self._handle_soft_reboot_completion,
            )
            self._emit(
                "soft_reboot",
                {
                    "delay_seconds": SOFT_REBOOT_DELAY_SECONDS,
                    "title": "Root 环境已启动",
                    "message": (
                        "请在平板弹窗中点击“允许”。"
                        "系统框架将在倒计时结束后软重启。"
                    ),
                },
            )
            self._emit(
                "success",
                {"text": "Root 已准备完成，请在平板中确认超级用户授权"},
            )
            self._emit("summary", {"text": "操作完成"})
        except (
            AdbError,
            UserFlowError,
            UserReleaseError,
        ) as error:
            self._emit("error", self._error_payload(error))
        except Exception as error:
            self._emit(
                "error",
                {
                    "code": "unexpected_error",
                    "title": "操作出现异常",
                    "message": str(error),
                    "show_guide": False,
                },
            )
        finally:
            self._release_operation()

    def _handle_soft_reboot_completion(
        self,
        succeeded: bool,
        message: str,
    ) -> None:
        self._emit(
            "soft_reboot_result",
            {
                "ok": succeeded,
                "message": message,
            },
        )

    def _run_verification(self) -> None:
        self._emit("busy", {"busy": True})
        self._emit("progress", {"text": "正在验证 Root、Zygisk 和 Vector"})
        self._emit("summary", {"text": "正在验证状态"})
        try:
            verification_result = self._flow.verify()
            if verification_result.get("ok") is not True:
                self._emit_verification_failure(verification_result)
                return
            connection = self._flow.connect(wait_seconds=2.0)
            self._emit("device", self._device_payload(connection))
            self._emit("success", {"text": "完整验证通过"})
            self._emit("summary", {"text": "验证通过"})
        except (AdbError, UserFlowError, UserReleaseError) as error:
            self._emit("error", self._error_payload(error))
        finally:
            self._release_operation()

    def _emit_verification_failure(
        self,
        verification_result: dict[str, Any],
    ) -> None:
        failed_checks = [
            str(check_name)
            for check_name in verification_result.get("failed_checks", [])
        ]
        if "root" in failed_checks:
            title = "Root 未激活"
            message = (
                "当前启动周期没有 Root。请先点击“一键 Root”，"
                "再到平板 Magisk 首页点击“一键 Root”。"
            )
        elif "magisk" in failed_checks:
            title = "Magisk 未运行"
            message = "请重新执行一键 Root，等待 Magisk 初始化完成。"
        elif "zygisk" in failed_checks:
            title = "Zygisk 未注入"
            message = "Root 已激活，但 NyaZygisk 未完成注入，请重新执行一键 Root。"
        elif "vector" in failed_checks:
            title = "Vector 未运行"
            message = "Root 已激活，但 Vector 服务未就绪，请重新执行一键 Root。"
        else:
            title = "验证未通过"
            check_names = "、".join(failed_checks) or "未知项目"
            message = f"未通过检查：{check_names}。请重新执行一键 Root。"

        try:
            connection = self._flow.connect(wait_seconds=2.0)
            self._emit("device", self._device_payload(connection))
        except (AdbError, UserFlowError, UserReleaseError):
            pass

        self._emit("log", {"message": message})
        self._emit(
            "error",
            {
                "code": "verification_failed",
                "title": title,
                "message": message,
                "show_guide": False,
            },
        )
        self._emit("summary", {"text": "验证未通过"})

    def _device_payload(self, connection: DeviceConnection) -> dict[str, Any]:
        snapshot = connection.snapshot
        vector_data: dict[str, Any] = {}
        if (
            snapshot.vector_status
            and isinstance(snapshot.vector_status.get("data"), dict)
        ):
            vector_data = snapshot.vector_status["data"]
        return {
            "model": snapshot.model,
            "display_id": snapshot.display_id,
            "android_release": snapshot.android_release,
            "root_available": snapshot.root_available,
            "magisk_version": snapshot.magisk_version,
            "zygisk_status": snapshot.zygisk_status,
            "vector_version": vector_data.get("Framework Version", ""),
            "vector_api": vector_data.get("API Version"),
            "boot_id_hash": snapshot.boot_id_hash,
        }

    def _error_payload(self, error: Exception) -> dict[str, Any]:
        error_message = str(error)
        if isinstance(error, DeviceAccessError):
            if error.code == "device_not_found":
                return {
                    "code": error.code,
                    "title": "没有检测到平板",
                    "message": (
                        "Windows 未检测到 ADB 调试接口。请确认使用支持数据传输的 "
                        "USB 线，并在开发者选项中同时开启“USB 调试”和"
                        "“仅充电模式下允许 ADB 调试”。USB 连接方式选择"
                        "“传输文件”后重新插拔数据线。"
                    ),
                    "show_guide": True,
                }
            if error.code == "device_unauthorized":
                return {
                    "code": error.code,
                    "title": "平板还没有授权这台电脑",
                    "message": (
                        "请解锁平板，查看屏幕上的 USB 调试授权弹窗，"
                        "选择“始终允许使用这台计算机进行调试”并点击确定。"
                    ),
                    "show_guide": True,
                }
            if error.code == "device_mismatch":
                return {
                    "code": error.code,
                    "title": "设备型号或系统版本不匹配",
                    "message": error_message,
                    "show_guide": False,
                }
            return {
                "code": error.code,
                "title": "ADB 连接失败",
                "message": error_message,
                "show_guide": True,
            }

        if "runtime engine does not exist" in error_message.lower():
            return {
                "code": "internal_root_broker_error",
                "title": "Root 辅助服务未就绪",
                "message": (
                    "Windows 一键流程不会调用外部 root-engine/engine.sh。"
                    "请重新连接设备后重试；如果仍失败，请导出诊断包。"
                ),
                "show_guide": False,
            }
        if isinstance(error, UserReleaseError):
            return {
                "code": "incomplete_release",
                "title": "发行包文件不完整",
                "message": error_message,
                "show_guide": False,
            }
        return {
            "code": "operation_failed",
            "title": "操作失败",
            "message": error_message,
            "show_guide": False,
        }

    def _forward_log(self, message: str) -> None:
        self._emit("log", {"message": message})

    def _emit(self, event_type: str, data: dict[str, Any]) -> None:
        if self._window is None:
            return
        payload = json.dumps(
            {"type": event_type, "data": data},
            ensure_ascii=False,
        )
        try:
            self._window.evaluate_js(
                f"window.DBY2_UI && window.DBY2_UI.onEvent({payload});"
            )
        except Exception:
            return

    def _acquire_operation(self) -> bool:
        acquired = self._operation_lock.acquire(blocking=False)
        self._operation_started = acquired
        return acquired

    def _release_operation(self) -> None:
        if self._operation_started:
            self._operation_started = False
            self._operation_lock.release()
        self._emit("busy", {"busy": False})


def show_native_error(message: str) -> None:
    if os.name == "nt":
        import ctypes

        ctypes.windll.user32.MessageBoxW(
            None,
            message,
            APP_TITLE,
            0x10,
        )
    else:
        print(message, file=sys.stderr)


def hide_console_if_owned() -> None:
    if os.name != "nt":
        return
    import ctypes

    process_ids = (ctypes.c_uint * 2)()
    process_count = ctypes.windll.kernel32.GetConsoleProcessList(
        process_ids,
        len(process_ids),
    )
    if process_count == 1:
        console_window = ctypes.windll.kernel32.GetConsoleWindow()
        if console_window:
            ctypes.windll.user32.ShowWindow(console_window, 0)


def main() -> int:
    hide_console_if_owned()
    try:
        layout = UserReleaseLayout.load(application_base_directory())
        layout.validate()
    except (UserReleaseError, OSError, ValueError) as error:
        show_native_error(
            "程序文件不完整，请重新解压完整 release 压缩包。\n\n"
            f"{error}"
        )
        return 2

    index_path = web_directory() / "index.html"
    if not index_path.is_file():
        show_native_error(f"WebView 页面不存在：{index_path}")
        return 3

    api = WebViewApi(layout)
    atexit.register(api.stop_adb)
    window = webview.create_window(
        f"{APP_TITLE} {APP_VERSION}",
        url=index_path.as_uri(),
        js_api=api,
        width=1180,
        height=820,
        min_size=(920, 680),
        background_color="#F2F5F5",
    )
    api._attach_window(window)
    window.events.closed += api.stop_adb

    try:
        webview.start(
            gui="edgechromium",
            debug=False,
            private_mode=False,
        )
    except Exception as error:
        show_native_error(
            "无法启动 Microsoft Edge WebView2。\n"
            "请安装 Microsoft Edge WebView2 Runtime 后重试。\n\n"
            f"{error}"
        )
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
