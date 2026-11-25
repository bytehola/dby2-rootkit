import tempfile
import unittest
from pathlib import Path

from dby2_rootctl.adb import CommandResult
from dby2_rootctl.root_engine import GhostLockRootEngine, RootEngineError


def successful_result(stdout: str = "") -> CommandResult:
    return CommandResult(
        arguments=(),
        returncode=0,
        stdout=stdout,
        stderr="",
    )


class FakeAdbClient:
    def __init__(self) -> None:
        self.shell_commands: list[str] = []
        self.pushes: list[tuple[Path, str]] = []
        self.pushed_contents: list[bytes] = []
        self.broker_started = False
        self.simulate_root_failure = False
        self.root_log_output = ""

    def shell(self, command: str, timeout_seconds: float = 30.0) -> CommandResult:
        self.shell_commands.append(command)
        if command.endswith("--rsh STATUS"):
            if self.broker_started:
                return successful_result("uid=0 euid=0 gid=0 egid=0")
            return successful_result("root broker is not running")
        if command.endswith("--rsh id"):
            return successful_result("uid=0(root) gid=0(root)")
        if command.startswith("tail -n 80 "):
            return successful_result(self.root_log_output)
        if command == "pidof vold":
            return successful_result("744\n")
        if "GLMOUNT|" in command:
            return successful_result("rc=0 errno=0")
        if command.endswith("--rsh GLCAPGRANT"):
            return successful_result(
                "capgrant=1 cap_eff=0000007fffffffff "
                "cap_prm=0000007fffffffff cap_bnd=0000007fffffffff"
            )
        if "--simple-root" in command:
            if self.simulate_root_failure:
                self.root_log_output = (
                    "slide attempt 1 timed out\n"
                    "read8: failed to restore boot_id ctl_table.data\n"
                )
            else:
                self.broker_started = True
        return successful_result()

    def push(
        self,
        local_path: Path,
        remote_path: str,
        timeout_seconds: float = 120.0,
    ) -> CommandResult:
        self.pushes.append((Path(local_path), remote_path))
        self.pushed_contents.append(Path(local_path).read_bytes())
        return successful_result()


class GhostLockRootEngineTests(unittest.TestCase):
    def test_uses_existing_broker_without_repeating_exploit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_binary = Path(temporary) / "ghostlock"
            root_binary.write_bytes(b"root binary")
            client = FakeAdbClient()
            client.broker_started = True
            engine = GhostLockRootEngine(client, root_binary)

            identity = engine.ensure_root()

        self.assertIn("uid=0(root)", identity)
        self.assertFalse(
            any("--simple-root" in command for command in client.shell_commands)
        )
        self.assertFalse(
            any("GLPERMISSIVE" in command for command in client.shell_commands)
        )
        self.assertEqual(
            [remote_path for _, remote_path in client.pushes],
            [engine.staged_broker_client_path],
        )
        self.assertNotIn(b"\r", client.pushed_contents[0])

    def test_starts_broker_directly_over_adb_when_root_is_inactive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_binary = Path(temporary) / "ghostlock"
            root_binary.write_bytes(b"root binary")
            client = FakeAdbClient()
            engine = GhostLockRootEngine(
                client,
                root_binary,
                poll_interval_seconds=0.0,
            )

            identity = engine.ensure_root()

        self.assertIn("uid=0(root)", identity)
        self.assertFalse(
            any("--harden" in command for command in client.shell_commands)
        )
        self.assertTrue(
            any("--simple-root" in command for command in client.shell_commands)
        )
        self.assertFalse(
            any("--kernel-domain" in command for command in client.shell_commands)
        )
        self.assertTrue(
            any("GLCAPGRANT" in command for command in client.shell_commands)
        )
        self.assertTrue(
            any(
                "--serve-target-domain 744" in command
                for command in client.shell_commands
            )
        )
        self.assertTrue(
            any("GLMOUNT|" in command for command in client.shell_commands)
        )
        self.assertEqual(
            [remote_path for _, remote_path in client.pushes],
            [
                engine.remote_binary_path,
                engine.staged_broker_client_path,
            ],
        )

    def test_reports_exploit_failure_without_waiting_for_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root_binary = Path(temporary) / "ghostlock"
            root_binary.write_bytes(b"root binary")
            client = FakeAdbClient()
            client.simulate_root_failure = True
            engine = GhostLockRootEngine(
                client,
                root_binary,
                poll_interval_seconds=0.0,
            )

            with self.assertRaisesRegex(RootEngineError, "完整重启平板"):
                engine.ensure_root()


if __name__ == "__main__":
    unittest.main()
