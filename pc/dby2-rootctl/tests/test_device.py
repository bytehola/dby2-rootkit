import unittest
from unittest.mock import patch

from dby2_rootctl.adb import CommandResult
from dby2_rootctl.device import (
    _probe_root,
    _read_identity_values,
    _read_vector_status,
    _run_root_command,
)


class _FakeClient:
    def shell(
        self,
        command: str,
        timeout_seconds: float = 30.0,
    ) -> CommandResult:
        if command == "/data/local/tmp/dfroot-su -c id":
            return CommandResult(
                arguments=("shell", command),
                returncode=0,
                stdout="uid=0(root)",
                stderr="",
            )
        return CommandResult(
            arguments=("shell", command),
            returncode=1,
            stdout="",
            stderr="not available",
        )


class RootProbeTests(unittest.TestCase):
    def test_reads_device_identity_in_one_shell_command(self) -> None:
        class _IdentityClient:
            def __init__(self) -> None:
                self.shell_calls = 0

            def shell(
                self,
                command: str,
                timeout_seconds: float = 30.0,
            ) -> CommandResult:
                self.shell_calls += 1
                return CommandResult(
                    arguments=("shell", command),
                    returncode=0,
                    stdout=(
                        "model=DBY2-W00\n"
                        "android_release=12\n"
                        "sdk=31\n"
                        "abi=arm64-v8a\n"
                        "display_id=DBY2-W00 4.2.0.252\n"
                        "incremental=104.2.0.252C00\n"
                        "kernel=5.4.86-qgki\n"
                        "boot_id=boot-test\n"
                        "selinux_mode=Enforcing\n"
                        "shell_identity=uid=2000(shell)\n"
                        "boot_adb_port=5555\n"
                        "system_server_pid=123\n"
                        "surfaceflinger_pid=456\n"
                    ),
                    stderr="",
                )

        client = _IdentityClient()
        identity = _read_identity_values(client)

        self.assertEqual(client.shell_calls, 1)
        self.assertEqual(identity["model"], "DBY2-W00")
        self.assertEqual(identity["kernel"], "5.4.86-qgki")
        self.assertEqual(identity["system_server_pid"], "123")

    def test_recognizes_packaged_root_broker(self) -> None:
        result = _probe_root(_FakeClient())

        self.assertTrue(result.succeeded)
        self.assertIn("uid=0(root)", result.stdout)

    def test_root_output_wins_over_nonzero_exit(self) -> None:
        class _NonzeroRootClient:
            def shell(
                self,
                command: str,
                timeout_seconds: float = 30.0,
            ) -> CommandResult:
                return CommandResult(
                    arguments=("shell", command),
                    returncode=1,
                    stdout="uid=0(root) gid=0(root)",
                    stderr="broker cleanup warning",
                )

        result = _probe_root(_NonzeroRootClient())

        self.assertFalse(result.succeeded)
        self.assertIn("uid=0(root)", result.stdout)

    def test_retries_transient_broker_timeout(self) -> None:
        class _TransientBrokerClient:
            def __init__(self) -> None:
                self.dfroot_calls = 0

            def shell(
                self,
                command: str,
                timeout_seconds: float = 30.0,
            ) -> CommandResult:
                if command == "/data/local/tmp/dfroot-su -c id":
                    self.dfroot_calls += 1
                    if self.dfroot_calls == 1:
                        return CommandResult(
                            arguments=("shell", command),
                            returncode=124,
                            stdout="",
                            stderr="BROKER_TIMEOUT",
                            timed_out=True,
                        )
                    return CommandResult(
                        arguments=("shell", command),
                        returncode=0,
                        stdout="uid=0(root)",
                        stderr="",
                    )
                return CommandResult(
                    arguments=("shell", command),
                    returncode=1,
                    stdout="",
                    stderr="not available",
                )

        client = _TransientBrokerClient()
        with patch("dby2_rootctl.device.time.sleep"):
            result = _probe_root(client)

        self.assertEqual(client.dfroot_calls, 2)
        self.assertIn("uid=0(root)", result.stdout)

    def test_root_command_prefers_broker_when_su_is_denied(self) -> None:
        class _BrokerOnlyClient:
            def shell(
                self,
                command: str,
                timeout_seconds: float = 30.0,
            ) -> CommandResult:
                if command.startswith("/data/local/tmp/dfroot-su -c "):
                    return CommandResult(
                        arguments=("shell", command),
                        returncode=0,
                        stdout="31.1:MAGISK:D",
                        stderr="",
                    )
                raise AssertionError(f"Unexpected fallback command: {command}")

        result = _run_root_command(
            _BrokerOnlyClient(),
            "/debug_ramdisk/magisk -v",
        )

        self.assertEqual(result.stdout, "31.1:MAGISK:D")

    def test_root_command_falls_back_to_su(self) -> None:
        class _SuFallbackClient:
            def shell(
                self,
                command: str,
                timeout_seconds: float = 30.0,
            ) -> CommandResult:
                if command.startswith("/data/local/tmp/dfroot-su -c "):
                    return CommandResult(
                        arguments=("shell", command),
                        returncode=1,
                        stdout="",
                        stderr="broker unavailable",
                    )
                return CommandResult(
                    arguments=("shell", command),
                    returncode=0,
                    stdout="31.1:MAGISK:D",
                    stderr="",
                )

        result = _run_root_command(
            _SuFallbackClient(),
            "/debug_ramdisk/magisk -v",
        )

        self.assertEqual(result.stdout, "31.1:MAGISK:D")

    def test_vector_json_survives_nonzero_wrapper_exit(self) -> None:
        class _VectorClient:
            def shell(
                self,
                command: str,
                timeout_seconds: float = 30.0,
            ) -> CommandResult:
                if (
                    command.startswith("/data/local/tmp/dfroot-su -c ")
                    and "test -x" in command
                ):
                    return CommandResult(
                        arguments=("shell", command),
                        returncode=0,
                        stdout="",
                        stderr="",
                    )
                if command.startswith("/data/local/tmp/dfroot-su -c "):
                    return CommandResult(
                        arguments=("shell", command),
                        returncode=1,
                        stdout='{"success": true, "data": {}}',
                        stderr="cleanup warning",
                    )
                raise AssertionError(f"Unexpected fallback command: {command}")

        status, error = _read_vector_status(_VectorClient(), root_available=True)

        self.assertEqual(error, "")
        self.assertEqual(status, {"success": True, "data": {}})


if __name__ == "__main__":
    unittest.main()
