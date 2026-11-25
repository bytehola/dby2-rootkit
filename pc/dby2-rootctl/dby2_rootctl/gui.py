from __future__ import annotations

import os
import queue
import sys
import threading
import traceback
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from dby2_rootctl import __version__
from dby2_rootctl.adb import AdbError
from dby2_rootctl.device import DeviceSnapshot
from dby2_rootctl.user_flow import DeviceConnection, UserFlow, UserFlowError
from dby2_rootctl.user_release import (
    UserReleaseError,
    UserReleaseLayout,
)


APP_TITLE = "DBY2 RootKit"
APP_VERSION = __version__

BACKGROUND_COLOR = "#F3F6F7"
SURFACE_COLOR = "#FFFFFF"
TEXT_COLOR = "#1B2730"
MUTED_TEXT_COLOR = "#65727D"
ACCENT_COLOR = "#0B7A75"
SUCCESS_COLOR = "#167A48"
WARNING_COLOR = "#A56412"
ERROR_COLOR = "#B13C3C"
LOG_BACKGROUND = "#202A31"
LOG_TEXT = "#E7EDF0"


def application_base_directory() -> Path:
    configured_directory = os.environ.get("DBY2_RELEASE_DIR", "").strip()
    if configured_directory:
        return Path(configured_directory)
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parents[3]


class RootKitGraphicalApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.flow: UserFlow | None = None
        self.busy = False
        self._configure_window()
        self._configure_styles()
        self._build_interface()
        self._load_release()
        self.root.after(100, self._process_events)
        if self.flow is not None:
            self.root.after(400, self.check_device)

    def _configure_window(self) -> None:
        self.root.title(f"{APP_TITLE} {APP_VERSION}")
        self.root.geometry("1040x760")
        self.root.minsize(920, 680)
        self.root.configure(background=BACKGROUND_COLOR)

    def _configure_styles(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure(
            "Primary.TButton",
            background=ACCENT_COLOR,
            foreground="#FFFFFF",
            borderwidth=0,
            padding=(22, 14),
            font=("Segoe UI", 12, "bold"),
        )
        style.map(
            "Primary.TButton",
            background=[
                ("disabled", "#8AA9A7"),
                ("active", "#096661"),
            ],
        )
        style.configure(
            "Secondary.TButton",
            background="#E7ECEF",
            foreground=TEXT_COLOR,
            borderwidth=0,
            padding=(14, 10),
            font=("Segoe UI", 10),
        )
        style.map(
            "Secondary.TButton",
            background=[
                ("disabled", "#F0F2F3"),
                ("active", "#D9E1E5"),
            ],
        )
        style.configure(
            "Status.Horizontal.TProgressbar",
            troughcolor="#DFE6E9",
            background=ACCENT_COLOR,
            borderwidth=0,
            thickness=8,
        )

    def _build_interface(self) -> None:
        page = tk.Frame(self.root, background=BACKGROUND_COLOR)
        page.pack(fill="both", expand=True, padx=32, pady=24)

        header = tk.Frame(page, background=BACKGROUND_COLOR)
        header.pack(fill="x")
        title = tk.Label(
            header,
            text=APP_TITLE,
            background=BACKGROUND_COLOR,
            foreground=TEXT_COLOR,
            font=("Segoe UI Semibold", 25),
            anchor="w",
        )
        title.pack(side="left")
        version = tk.Label(
            header,
            text=f"v{APP_VERSION}",
            background=BACKGROUND_COLOR,
            foreground=MUTED_TEXT_COLOR,
            font=("Segoe UI", 10),
        )
        version.pack(side="left", padx=(10, 0), pady=(10, 0))

        subtitle = tk.Label(
            page,
            text="HUAWEI MatePad Air 11.5 · DBY2-W00",
            background=BACKGROUND_COLOR,
            foreground=MUTED_TEXT_COLOR,
            font=("Segoe UI", 10),
            anchor="w",
        )
        subtitle.pack(fill="x", pady=(2, 18))

        status_panel = tk.Frame(
            page,
            background=SURFACE_COLOR,
            highlightbackground="#DCE3E7",
            highlightthickness=1,
        )
        status_panel.pack(fill="x")

        status_content = tk.Frame(status_panel, background=SURFACE_COLOR)
        status_content.pack(fill="x", padx=22, pady=18)

        self.device_status = self._create_status_block(
            status_content,
            "设备",
            "等待连接",
            0,
        )
        self.root_status = self._create_status_block(
            status_content,
            "Root",
            "未检查",
            1,
        )
        self.runtime_status = self._create_status_block(
            status_content,
            "运行环境",
            "未检查",
            2,
        )
        self.build_status = self._create_status_block(
            status_content,
            "系统版本",
            "等待设备信息",
            3,
        )

        action_panel = tk.Frame(page, background=BACKGROUND_COLOR)
        action_panel.pack(fill="x", pady=(20, 16))

        self.primary_button = ttk.Button(
            action_panel,
            text="一键获取 Root",
            style="Primary.TButton",
            command=self.one_click_root,
        )
        self.primary_button.pack(side="left")

        self.check_button = ttk.Button(
            action_panel,
            text="检查设备",
            style="Secondary.TButton",
            command=self.check_device,
        )
        self.check_button.pack(side="left", padx=(12, 0))

        self.verify_button = ttk.Button(
            action_panel,
            text="验证状态",
            style="Secondary.TButton",
            command=self.verify_device,
        )
        self.verify_button.pack(side="left", padx=(8, 0))

        self.diagnostics_button = ttk.Button(
            action_panel,
            text="导出诊断",
            style="Secondary.TButton",
            command=self.export_diagnostics,
        )
        self.diagnostics_button.pack(side="left", padx=(8, 0))

        self.progress = ttk.Progressbar(
            page,
            mode="indeterminate",
            style="Status.Horizontal.TProgressbar",
        )
        self.progress.pack(fill="x", pady=(0, 14))

        log_header = tk.Frame(page, background=BACKGROUND_COLOR)
        log_header.pack(fill="x")
        tk.Label(
            log_header,
            text="运行日志",
            background=BACKGROUND_COLOR,
            foreground=TEXT_COLOR,
            font=("Segoe UI Semibold", 11),
            anchor="w",
        ).pack(side="left")
        self.summary_label = tk.Label(
            log_header,
            text="准备就绪",
            background=BACKGROUND_COLOR,
            foreground=MUTED_TEXT_COLOR,
            font=("Segoe UI", 9),
        )
        self.summary_label.pack(side="right")

        log_frame = tk.Frame(page, background=LOG_BACKGROUND)
        log_frame.pack(fill="both", expand=True, pady=(8, 14))
        self.log_text = tk.Text(
            log_frame,
            background=LOG_BACKGROUND,
            foreground=LOG_TEXT,
            insertbackground=LOG_TEXT,
            selectbackground="#34515E",
            borderwidth=0,
            wrap="word",
            padx=16,
            pady=14,
            font=("Cascadia Mono", 9),
            state="disabled",
        )
        log_scrollbar = ttk.Scrollbar(
            log_frame,
            orient="vertical",
            command=self.log_text.yview,
        )
        self.log_text.configure(yscrollcommand=log_scrollbar.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scrollbar.pack(side="right", fill="y")

        tk.Label(
            page,
            text=(
                "仅支持 DBY2-W00 / HarmonyOS 4.2.0.252(C00E100R3P5)。"
                "临时 Root 会在完整重启后失效。"
            ),
            background=BACKGROUND_COLOR,
            foreground=MUTED_TEXT_COLOR,
            font=("Segoe UI", 9),
            anchor="w",
        ).pack(fill="x")

    def _create_status_block(
        self,
        parent: tk.Frame,
        title: str,
        initial_value: str,
        column: int,
    ) -> tk.Label:
        parent.grid_columnconfigure(column, weight=1)
        block = tk.Frame(parent, background=SURFACE_COLOR)
        block.grid(
            row=0,
            column=column,
            sticky="nsew",
            padx=(0 if column == 0 else 18, 0),
        )
        tk.Label(
            block,
            text=title,
            background=SURFACE_COLOR,
            foreground=MUTED_TEXT_COLOR,
            font=("Segoe UI", 9),
            anchor="w",
        ).pack(fill="x")
        value_label = tk.Label(
            block,
            text=initial_value,
            background=SURFACE_COLOR,
            foreground=TEXT_COLOR,
            font=("Segoe UI Semibold", 11),
            anchor="w",
        )
        value_label.pack(fill="x", pady=(5, 0))
        return value_label

    def _load_release(self) -> None:
        try:
            layout = UserReleaseLayout.load(application_base_directory())
            layout.validate()
            self.flow = UserFlow(
                layout,
                log_callback=lambda message: self.events.put(
                    ("log", message)
                ),
            )
            self._append_log("终端用户运行文件校验通过。")
        except (UserReleaseError, OSError, ValueError) as error:
            self._append_log(f"启动检查失败：{error}")
            self.summary_label.configure(
                text="安装文件不完整",
                foreground=ERROR_COLOR,
            )
            self._set_busy(True)
            messagebox.showerror(
                APP_TITLE,
                "程序文件不完整，请重新解压完整 release 压缩包。\n\n"
                f"{error}",
                parent=self.root,
            )

    def check_device(self) -> None:
        if self.flow is None:
            return

        def task() -> None:
            connection = self.flow.connect()
            self.events.put(("connection", connection))
            self.events.put(("summary", "设备已连接"))

        self._run_task(task)

    def one_click_root(self) -> None:
        if self.flow is None:
            return

        def task() -> None:
            self.events.put(("summary", "正在获取 Root"))
            self.flow.one_click_root()
            connection = self.flow.connect()
            self.events.put(("connection", connection))
            self.events.put(("summary", "Root 已准备完成"))
            self.events.put(("success", "操作完成"))

        self._run_task(task)

    def verify_device(self) -> None:
        if self.flow is None:
            return

        def task() -> None:
            self.events.put(("summary", "正在验证"))
            self.flow.verify()
            connection = self.flow.connect()
            self.events.put(("connection", connection))
            self.events.put(("summary", "验证通过"))
            self.events.put(("success", "完整验证通过"))

        self._run_task(task)

    def export_diagnostics(self) -> None:
        if self.flow is None:
            return
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_path = filedialog.asksaveasfilename(
            parent=self.root,
            title="保存诊断包",
            defaultextension=".zip",
            filetypes=[("ZIP archive", "*.zip")],
            initialfile=f"DBY2-RootKit-diagnostics-{timestamp}.zip",
        )
        if not output_path:
            return

        def task() -> None:
            self.flow.export_diagnostics(Path(output_path))
            self.events.put(("summary", "诊断包已导出"))
            self.events.put(
                ("info", f"诊断包已保存：\n{output_path}")
            )

        self._run_task(task)

    def _run_task(self, task: Callable[[], None]) -> None:
        if self.busy:
            return
        self._set_busy(True)

        def run_with_error_handling() -> None:
            try:
                task()
            except (AdbError, UserFlowError, UserReleaseError) as error:
                self.events.put(("error", str(error)))
            except Exception as error:
                self.events.put(
                    ("log", traceback.format_exc())
                )
                self.events.put(
                    ("error", f"发生未预期错误：{error}")
                )
            finally:
                self.events.put(("busy", False))

        threading.Thread(
            target=run_with_error_handling,
            daemon=True,
            name="dby2-root-operation",
        ).start()

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        button_state = "disabled" if busy else "normal"
        for button in (
            self.primary_button,
            self.check_button,
            self.verify_button,
            self.diagnostics_button,
        ):
            button.configure(state=button_state)
        if busy:
            self.progress.start(12)
        else:
            self.progress.stop()

    def _process_events(self) -> None:
        while True:
            try:
                event_name, event_value = self.events.get_nowait()
            except queue.Empty:
                break

            if event_name == "log":
                self._append_log(str(event_value))
            elif event_name == "summary":
                self.summary_label.configure(
                    text=str(event_value),
                    foreground=MUTED_TEXT_COLOR,
                )
            elif event_name == "connection":
                self._update_connection(event_value)
            elif event_name == "busy":
                self._set_busy(bool(event_value))
            elif event_name == "success":
                messagebox.showinfo(
                    APP_TITLE,
                    str(event_value),
                    parent=self.root,
                )
            elif event_name == "info":
                messagebox.showinfo(
                    APP_TITLE,
                    str(event_value),
                    parent=self.root,
                )
            elif event_name == "error":
                self.summary_label.configure(
                    text="操作失败",
                    foreground=ERROR_COLOR,
                )
                self._append_log(f"错误：{event_value}")
                messagebox.showerror(
                    APP_TITLE,
                    str(event_value),
                    parent=self.root,
                )

        self.root.after(100, self._process_events)

    def _update_connection(self, event_value: object) -> None:
        if not isinstance(event_value, DeviceConnection):
            return
        snapshot = event_value.snapshot
        self._update_snapshot(snapshot)

    def _update_snapshot(self, snapshot: DeviceSnapshot) -> None:
        self.device_status.configure(
            text=f"{snapshot.model} · Android {snapshot.android_release}",
            foreground=SUCCESS_COLOR,
        )
        self.build_status.configure(
            text=snapshot.display_id,
            foreground=TEXT_COLOR,
        )
        if snapshot.root_available:
            self.root_status.configure(
                text="临时 Root 已激活",
                foreground=SUCCESS_COLOR,
            )
        else:
            self.root_status.configure(
                text="当前 boot 未 Root",
                foreground=WARNING_COLOR,
            )

        if (
            snapshot.zygisk_status == "injected"
            and snapshot.vector_status
            and snapshot.vector_status.get("success") is True
        ):
            vector_data = snapshot.vector_status.get("data", {})
            vector_version = (
                vector_data.get("Framework Version", "ready")
                if isinstance(vector_data, dict)
                else "ready"
            )
            self.runtime_status.configure(
                text=(
                    "Zygisk 已注入 · Vector "
                    f"{vector_version}"
                ),
                foreground=SUCCESS_COLOR,
            )
        else:
            self.runtime_status.configure(
                text="运行环境未启动",
                foreground=WARNING_COLOR,
            )

    def _append_log(self, message: str) -> None:
        cleaned_message = message.replace("\r\n", "\n").strip()
        if not cleaned_message:
            return
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = "\n".join(
            f"[{timestamp}] {line}"
            for line in cleaned_message.splitlines()
        )
        self.log_text.configure(state="normal")
        self.log_text.insert("end", formatted + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")


def main() -> int:
    root = tk.Tk()
    RootKitGraphicalApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
