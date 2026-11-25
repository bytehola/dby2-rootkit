import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from dby2_rootctl.adb import CommandResult
from dby2_rootctl.user_flow import UserFlow


class UserFlowOneClickTests(unittest.TestCase):
    def setUp(self) -> None:
        bundled_asset = lambda name: SimpleNamespace(
            path=f"/test/{name}",
            sha256="a" * 64,
        )
        self.flow = UserFlow(
            layout=SimpleNamespace(
                adb_path="/test/adb",
                profile_directory="/test/profile",
                magisk_apk=bundled_asset("magisk.apk"),
                rootkit_apk=bundled_asset("rootkit.apk"),
                nyazygisk_zip=bundled_asset("nyazygisk.zip"),
                vector_zip=bundled_asset("vector.zip"),
                root_engine_binary=bundled_asset("DBY2-GhostLock-arm64"),
            )
        )
        self.client = SimpleNamespace(serial="DBY2-TEST")
        self.connection = SimpleNamespace(
            client=self.client,
            snapshot=SimpleNamespace(
                root_available=True,
                model="DBY2-W00",
                display_id="DBY2-W00 4.2.0.252",
            ),
            profile=object(),
            evaluation=object(),
        )
        self.flow.connect = Mock(return_value=self.connection)
        self.flow._acquire_root_over_adb = Mock(return_value=self.connection)
        self.flow._package_installed = Mock(side_effect=[True, False])
        self.flow._runtime_modules_installed = Mock(return_value=True)
        self.flow._install_magisk = Mock()
        self.flow._install_rootkit = Mock()
        self.flow._run_command = Mock(return_value={"ok": True})
        self.flow._launch_rootkit = Mock()

    def test_installs_rootkit_before_resuming_complete_magisk_runtime(
        self,
    ) -> None:
        result = self.flow.one_click_root()

        self.assertEqual(result, {"ok": True})
        self.flow._install_magisk.assert_called_once_with(self.client)
        self.flow._install_rootkit.assert_called_once_with(self.client)
        command_arguments = self.flow._run_command.call_args.args[0]
        self.assertIn("resume", command_arguments)
        self.assertNotIn("bootstrap", command_arguments)
        self.flow._launch_rootkit.assert_called_once_with(self.client)

    def test_uses_bootstrap_when_runtime_modules_are_missing(self) -> None:
        self.flow._runtime_modules_installed.return_value = False
        self.flow.one_click_root()

        self.flow._install_magisk.assert_called_once_with(self.client)
        self.flow._install_rootkit.assert_not_called()
        command_arguments = self.flow._run_command.call_args.args[0]
        self.assertIn("bootstrap", command_arguments)
        self.assertNotIn("resume", command_arguments)

    def test_waits_for_root_snapshot_to_synchronize(self) -> None:
        self.connection.snapshot.root_available = False
        self.connection.snapshot.persistent_adb_port = "5555"

        def shell(
            command: str,
            timeout_seconds: float = 30.0,
        ) -> CommandResult:
            if command.startswith("am start-foreground-service"):
                return CommandResult(
                    arguments=("shell", command),
                    returncode=0,
                    stdout="",
                    stderr="",
                )
            if command == "/data/local/tmp/dfroot-su -c id":
                return CommandResult(
                    arguments=("shell", command),
                    returncode=0,
                    stdout="uid=0(root)",
                    stderr="",
                )
            raise AssertionError(f"Unexpected command: {command}")

        self.client.shell = Mock(side_effect=shell)
        synchronized_snapshot = SimpleNamespace(
            root_available=True,
            root_identity="uid=0(root)",
            kernel="5.4.86-qgki",
        )
        snapshots = Mock(
            side_effect=[
                SimpleNamespace(
                    root_available=False,
                    root_identity="permission denied",
                    kernel="",
                ),
                synchronized_snapshot,
            ]
        )

        with (
            patch("dby2_rootctl.user_flow.collect_snapshot", snapshots),
            patch("dby2_rootctl.user_flow.time.sleep"),
        ):
            result = UserFlow._acquire_root_over_adb(
                self.flow,
                self.connection,
            )

        self.assertIs(result.snapshot, synchronized_snapshot)
        self.assertIs(result.profile, self.connection.profile)
        self.assertEqual(snapshots.call_count, 2)

    def test_restarts_framework_through_root_broker(self) -> None:
        self.client.shell = Mock(
            return_value=CommandResult(
                arguments=("shell", "restart"),
                returncode=0,
                stdout="",
                stderr="",
            )
        )
        completion_callback = Mock()

        with patch("dby2_rootctl.user_flow.time.sleep") as sleep:
            self.flow._restart_framework_after_delay(
                self.connection,
                10.0,
                completion_callback,
            )

        sleep.assert_called_once_with(10.0)
        self.client.shell.assert_called_once_with(
            "/data/local/tmp/dfroot-su -c 'setprop ctl.restart zygote'",
            timeout_seconds=15.0,
        )
        completion_callback.assert_called_once_with(
            True,
            "已触发系统框架软重启，等待平板恢复。",
        )


class UserFlowVerificationTests(unittest.TestCase):
    def test_returns_failed_report_without_logging_raw_json(self) -> None:
        log_messages: list[str] = []
        flow = UserFlow(
            layout=SimpleNamespace(
                adb_path="/test/adb",
                profile_directory="/test/profile",
            ),
            log_callback=log_messages.append,
        )
        connection = SimpleNamespace(
            client=SimpleNamespace(serial="DBY2-TEST"),
        )
        flow.connect = Mock(return_value=connection)
        verification_result = {
            "ok": False,
            "failed_checks": ["root", "magisk"],
            "report": {"state": "ready"},
        }

        def fake_command_main(arguments: list[str]) -> int:
            print(json.dumps(verification_result))
            return 9

        with patch(
            "dby2_rootctl.user_flow.command_main",
            side_effect=fake_command_main,
        ):
            result = flow.verify()

        self.assertEqual(result, verification_result)
        self.assertEqual(
            log_messages,
            ["执行 Root、Zygisk 和 Vector 完整验证..."],
        )


if __name__ == "__main__":
    unittest.main()
