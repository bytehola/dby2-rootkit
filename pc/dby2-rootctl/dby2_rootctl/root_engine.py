from __future__ import annotations

import shlex
import time
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Callable
from uuid import uuid4

from dby2_rootctl.adb import AdbClient, CommandResult


class RootEngineError(RuntimeError):
    pass


class GhostLockRootEngine:
    BROKER_CLIENT_PATH = "/data/local/tmp/dfroot-su"

    def __init__(
        self,
        client: AdbClient,
        root_binary_path: Path,
        log_callback: Callable[[str], None] | None = None,
        timeout_seconds: float = 360.0,
        poll_interval_seconds: float = 2.0,
    ):
        self.client = client
        self.root_binary_path = root_binary_path
        self.log_callback = log_callback or (lambda message: None)
        self.timeout_seconds = timeout_seconds
        self.poll_interval_seconds = poll_interval_seconds
        run_token = uuid4().hex[:10]
        self.remote_binary_path = (
            f"/data/local/tmp/ghostlock_dby2_{run_token}"
        )
        self.staged_broker_client_path = (
            f"/data/local/tmp/dfroot-su.staged.{run_token}"
        )
        self.slot_path = f"/data/local/tmp/gl-{run_token}.slot"
        self.root_log_path = f"/data/local/tmp/dby2-root-{run_token}.log"

    def ensure_root(self) -> str:
        if not self.root_binary_path.is_file():
            raise RootEngineError(
                f"发行包中的 ADB Root 引擎不存在：{self.root_binary_path}"
            )

        existing_status = self._root_status()
        if "euid=0" not in existing_status:
            self._deploy_root_engine()
            self._start_root_broker()
            self._wait_for_root()

        identity_result = self._wait_for_root_identity()

        self._enable_full_capabilities()
        self._ensure_magisk_runtime_mount()
        self._stage_broker_client()
        return identity_result.stdout.strip()

    def _ensure_magisk_runtime_mount(self) -> None:
        mount_check = self.client.shell(
            "grep -q ' /debug_ramdisk ' /proc/mounts "
            "&& echo MOUNTED || echo UNMOUNTED",
            timeout_seconds=10.0,
        )
        if "MOUNTED" in mount_check.stdout:
            return

        mount_result = self._run_root_command(
            "GLMOUNT|-|/debug_ramdisk|tmpfs|0|mode=0755",
            timeout_seconds=20.0,
        )
        if "rc=0" not in mount_result.stdout:
            detail = mount_result.stderr.strip() or mount_result.stdout.strip()
            raise RootEngineError(f"Magisk 运行时挂载失败：{detail}")

    def _enable_full_capabilities(self) -> None:
        capability_result = self._run_root_command(
            "GLCAPGRANT",
            timeout_seconds=20.0,
        )
        if (
            not capability_result.succeeded
            or "capgrant=1" not in capability_result.stdout
        ):
            detail = (
                capability_result.stderr.strip()
                or capability_result.stdout.strip()
            )
            raise RootEngineError(f"Root capability 授权失败：{detail}")

    def _wait_for_root_identity(self) -> CommandResult:
        deadline = time.monotonic() + 15.0
        last_result = CommandResult(
            arguments=(),
            returncode=1,
            stdout="",
            stderr="",
        )
        while time.monotonic() < deadline:
            last_result = self._run_root_command("id", timeout_seconds=20.0)
            if "uid=0(root)" in last_result.stdout:
                return last_result
            time.sleep(0.5)

        detail = last_result.stderr.strip() or last_result.stdout.strip()
        raise RootEngineError(f"ADB Root broker 未返回 UID 0：{detail}")

    def _root_status(self) -> str:
        result = self._run_root_command("STATUS", timeout_seconds=12.0)
        if not result.succeeded:
            return ""
        return result.stdout

    def _deploy_root_engine(self) -> None:
        self.log_callback("正在通过 ADB 部署 Root 引擎...")
        push_result = self.client.push(
            self.root_binary_path,
            self.remote_binary_path,
        )
        if not push_result.succeeded:
            detail = push_result.stderr.strip() or push_result.stdout.strip()
            raise RootEngineError(f"Root 引擎推送失败：{detail}")

        preparation_result = self.client.shell(
            (
                f"chmod 755 {self.remote_binary_path}; "
                f"touch {self.slot_path}; "
                f"chmod 666 {self.slot_path}"
            ),
            timeout_seconds=20.0,
        )
        if not preparation_result.succeeded:
            detail = (
                preparation_result.stderr.strip()
                or preparation_result.stdout.strip()
            )
            raise RootEngineError(f"Root 引擎初始化失败：{detail}")

    def _start_root_broker(self) -> None:
        self.log_callback("正在通过 ADB 触发本次启动的 Root...")
        vold_pid_result = self.client.shell("pidof vold", timeout_seconds=10.0)
        vold_pids = vold_pid_result.stdout.split()
        if not vold_pids or not vold_pids[0].isdigit():
            raise RootEngineError("无法定位 vold 进程，不能建立挂载 broker")
        vold_pid = vold_pids[0]

        root_result = self.client.shell(
            (
                f"{self.remote_binary_path} --simple-root --su-server "
                f"--serve-target-domain {vold_pid} "
                "--target-domain-comm vold "
                "--detach --probe-cycle --spin-park --no-rt "
                "--runtime-cpu 6 --attempts 1 --leak-timeout 60 --fsync "
                "--task-period 100000 --task-iters 20000 --task-rounds 4 "
                f"--slot-file {self.slot_path} "
                f"--log-file {self.root_log_path} "
                "</dev/null >/dev/null 2>&1 &"
            ),
            timeout_seconds=30.0,
        )
        if not root_result.succeeded:
            detail = root_result.stderr.strip() or root_result.stdout.strip()
            raise RootEngineError(f"Root broker 启动失败：{detail}")

    def _wait_for_root(self) -> None:
        deadline = time.monotonic() + self.timeout_seconds
        next_status_time = 0.0
        while time.monotonic() < deadline:
            status = self._root_status()
            if "euid=0" in status:
                self.log_callback("ADB Root 已就绪。")
                return

            current_time = time.monotonic()
            if current_time >= next_status_time:
                recent_log = self.client.shell(
                    f"tail -n 80 {self.root_log_path}",
                    timeout_seconds=15.0,
                ).stdout
                failed_markers = (
                    "slide attempt 1 timed out",
                    "read8: failed",
                    "simple-root: failed",
                )
                if any(marker in recent_log for marker in failed_markers):
                    raise RootEngineError(
                        "本次 Root 尝试失败，内核状态需要重新初始化。"
                        "请完整重启平板后再次点击一键 Root。"
                    )
                self.log_callback("正在等待 ADB Root broker 就绪...")
                next_status_time = current_time + 15.0
            time.sleep(self.poll_interval_seconds)

        recent_log = self.client.shell(
            f"tail -n 80 {self.root_log_path}",
            timeout_seconds=15.0,
        )
        detail = recent_log.stdout.strip() or "没有可读取的 Root 日志"
        raise RootEngineError(f"ADB Root 超时。最近日志：\n{detail}")

    def _stage_broker_client(self) -> None:
        broker_client = (
            "#!/system/bin/sh\n"
            "set -u\n"
            'if [ "${1:-}" = "-c" ]; then\n'
            "  shift\n"
            "fi\n"
            f'exec {self.remote_binary_path} --rsh "$*"\n'
        )
        with TemporaryDirectory(prefix="dby2-broker-client-") as temporary:
            client_path = Path(temporary) / "dfroot-su"
            client_path.write_bytes(broker_client.encode("utf-8"))
            push_result = self.client.push(
                client_path,
                self.staged_broker_client_path,
            )
            if not push_result.succeeded:
                detail = push_result.stderr.strip() or push_result.stdout.strip()
                raise RootEngineError(f"Root 客户端部署失败：{detail}")

        chmod_result = self.client.shell(
            f"chmod 755 {self.staged_broker_client_path}",
            timeout_seconds=15.0,
        )
        if not chmod_result.succeeded:
            detail = chmod_result.stderr.strip() or chmod_result.stdout.strip()
            raise RootEngineError(f"Root 客户端权限设置失败：{detail}")

        shell_install_result = self.client.shell(
            (
                f"rm -f {self.BROKER_CLIENT_PATH}; "
                f"cp {self.staged_broker_client_path} {self.BROKER_CLIENT_PATH} && "
                f"chmod 755 {self.BROKER_CLIENT_PATH} && "
                f"rm -f {self.staged_broker_client_path}"
            ),
            timeout_seconds=20.0,
        )
        if not shell_install_result.succeeded:
            install_result = self._run_root_command(
                (
                    f"rm -f {self.BROKER_CLIENT_PATH} && "
                    f"cp {self.staged_broker_client_path} "
                    f"{self.BROKER_CLIENT_PATH} && "
                    f"chmod 755 {self.BROKER_CLIENT_PATH} && "
                    f"rm -f {self.staged_broker_client_path}"
                ),
                timeout_seconds=20.0,
            )
            if not install_result.succeeded:
                detail = (
                    install_result.stderr.strip()
                    or install_result.stdout.strip()
                )
                raise RootEngineError(f"Root 客户端安装失败：{detail}")

        self._run_root_command(
            (
                f"chcon u:object_r:shell_data_file:s0 "
                f"{self.BROKER_CLIENT_PATH} 2>/dev/null || true"
            ),
            timeout_seconds=15.0,
        )

    def _run_root_command(
        self,
        command: str,
        timeout_seconds: float,
    ) -> CommandResult:
        return self.client.shell(
            f"{self.remote_binary_path} --rsh {shlex.quote(command)}",
            timeout_seconds=timeout_seconds,
        )
