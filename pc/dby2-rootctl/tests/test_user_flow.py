import json
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from dby2_rootctl.adb import CommandResult
from dby2_rootctl.user_flow import (
    SERVICE_COMPLETE_TIMEOUT_SECONDS,
    UserFlow,
    UserFlowError,
)


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
        self.flow._run_one_tap_installation = Mock(
            return_value=self.connection
        )
        self.flow._package_installed = Mock(return_value=False)
        self.flow._install_magisk = Mock()
        self.flow._install_rootkit = Mock()
        self.flow._persist_adb_tcp_port = Mock()
        self.flow._run_command = Mock(return_value={"ok": True})
        self.flow._launch_rootkit = Mock()

    def test_runs_one_tap_then_verifies_before_launching_rootkit(
        self,
    ) -> None:
        result = self.flow.one_click_root()

        self.assertEqual(result, {"ok": True})
        self.flow._install_magisk.assert_called_once_with(self.client)
        self.flow._run_one_tap_installation.assert_called_once_with(
            self.connection
        )
        self.flow._install_rootkit.assert_called_once_with(self.client)
        command_arguments = self.flow._run_command.call_args.args[0]
        self.assertIn("verify", command_arguments)
        self.assertNotIn("bootstrap", command_arguments)
        self.assertNotIn("resume", command_arguments)
        self.flow._persist_adb_tcp_port.assert_called_once_with(self.client)
        self.flow._launch_rootkit.assert_called_once_with(self.client)

    def test_skips_rootkit_install_when_already_present(self) -> None:
        self.flow._package_installed.return_value = True

        self.flow.one_click_root()

        self.flow._install_rootkit.assert_not_called()

    def test_stops_before_launch_when_full_verification_fails(self) -> None:
        self.flow._run_command.return_value = {
            "ok": False,
            "failed_checks": ["vector"],
        }

        with self.assertRaisesRegex(UserFlowError, "vector"):
            self.flow.one_click_root()

        self.flow._launch_rootkit.assert_not_called()

    def test_waits_for_one_tap_service_to_finish(self) -> None:
        running_output = (
            "ServiceRecord{test u0 "
            "com.topjohnwu.magisk/.core.root.OneTapRootService}"
        )
        stopped_output = "ACTIVITY MANAGER SERVICES"
        self.client.shell = Mock(
            side_effect=[
                CommandResult(
                    arguments=("shell", "dumpsys"),
                    returncode=0,
                    stdout=running_output,
                    stderr="",
                ),
                CommandResult(
                    arguments=("shell", "dumpsys"),
                    returncode=0,
                    stdout=running_output,
                    stderr="",
                ),
                CommandResult(
                    arguments=("shell", "dumpsys"),
                    returncode=0,
                    stdout=stopped_output,
                    stderr="",
                ),
            ]
        )

        with patch("dby2_rootctl.user_flow.time.sleep"):
            UserFlow._wait_for_one_tap_root_service(self.flow, self.client)

        self.assertEqual(self.client.shell.call_count, 3)

    def test_persists_and_verifies_local_adb_port(self) -> None:
        self.client.shell = Mock(
            side_effect=[
                CommandResult(
                    arguments=("shell", "setprop"),
                    returncode=0,
                    stdout="",
                    stderr="",
                ),
                CommandResult(
                    arguments=("shell", "getprop"),
                    returncode=0,
                    stdout="5555\n",
                    stderr="",
                ),
            ]
        )

        UserFlow._persist_adb_tcp_port(self.flow, self.client)

        self.assertEqual(self.client.shell.call_count, 2)
        self.assertEqual(
            self.client.shell.call_args_list[0].args[0],
            "/data/local/tmp/dfroot-su -c "
            "'setprop persist.adb.tcp.port 5555'",
        )
        self.client.shell.assert_called_with(
            "getprop persist.adb.tcp.port",
            timeout_seconds=8.0,
        )

    def test_timeout_cleans_packages_reboots_and_requests_retry(self) -> None:
        self.assertEqual(SERVICE_COMPLETE_TIMEOUT_SECONDS, 150.0)
        self.client.shell = Mock(
            return_value=CommandResult(
                arguments=("shell", "command"),
                returncode=0,
                stdout="Success",
                stderr="",
            )
        )

        with (
            patch.object(
                self.flow,
                "_one_tap_service_state",
                return_value=True,
            ),
            patch(
                "dby2_rootctl.user_flow.time.monotonic",
                side_effect=[0.0, 0.0, 0.0, 151.0, 151.0],
            ),
            self.assertRaisesRegex(
                UserFlowError,
                "adb shell reboot.*重新点击",
            ),
        ):
            UserFlow._wait_for_one_tap_root_service(self.flow, self.client)

        uninstall_calls = self.client.shell.call_args_list[:3]
        self.assertEqual(
            [call.args[0] for call in uninstall_calls],
            [
                "pm uninstall --user 0 com.topjohnwu.magisk",
                "pm uninstall --user 0 org.matrix.vector.manager",
                "pm uninstall --user 0 dev.dby2.rootkit",
            ],
        )
        self.client.shell.assert_called_with(
            "reboot",
            timeout_seconds=15.0,
        )

    def test_starts_boot_local_adb_before_one_tap(self) -> None:
        service_client = SimpleNamespace(
            serial="DBY2-TEST",
            shell=Mock(
                side_effect=[
                    CommandResult(
                        arguments=("shell", "getprop"),
                        returncode=0,
                        stdout="",
                        stderr="",
                    ),
                    CommandResult(
                        arguments=("shell", "start-service"),
                        returncode=0,
                        stdout="",
                        stderr="",
                    ),
                ]
            ),
            run=Mock(
                return_value=CommandResult(
                    arguments=("tcpip", "5555"),
                    returncode=0,
                    stdout="restarting in TCP mode port: 5555",
                    stderr="",
                )
            ),
        )
        connection = SimpleNamespace(client=service_client)
        self.flow._wait_for_pc_adb_connection = Mock()
        self.flow._wait_for_one_tap_root_service = Mock()
        self.flow._wait_for_ready_runtime = Mock(
            return_value=self.connection
        )

        result = UserFlow._run_one_tap_installation(
            self.flow,
            connection,
        )

        self.assertIs(result, self.connection)
        service_client.run.assert_called_once_with(
            ["tcpip", "5555"],
            timeout_seconds=45.0,
        )
        self.flow._wait_for_pc_adb_connection.assert_called_once_with(
            "DBY2-TEST"
        )
        self.flow._wait_for_one_tap_root_service.assert_called_once_with(
            service_client
        )

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
