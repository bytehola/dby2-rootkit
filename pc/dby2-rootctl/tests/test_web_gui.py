import sys
import types
import unittest
from unittest.mock import Mock

from dby2_rootctl.user_flow import DeviceAccessError, UserFlowError


if "webview" not in sys.modules:
    webview_module = types.ModuleType("webview")
    webview_module.SAVE_DIALOG = 1
    sys.modules["webview"] = webview_module

from dby2_rootctl.web_gui import SOFT_REBOOT_DELAY_SECONDS, WebViewApi


class WebViewOneClickTests(unittest.TestCase):
    def test_schedules_soft_reboot_after_root_flow(self) -> None:
        api = object.__new__(WebViewApi)
        api._flow = Mock()
        api._emit = Mock()
        api._release_operation = Mock()
        api._device_payload = Mock(return_value={"model": "DBY2-W00"})
        connection = Mock()
        api._flow.connect.return_value = connection

        api._run_one_click()

        api._flow.schedule_framework_restart.assert_called_once()
        schedule_call = api._flow.schedule_framework_restart.call_args
        self.assertIs(schedule_call.args[0], connection)
        self.assertEqual(
            schedule_call.kwargs["delay_seconds"],
            SOFT_REBOOT_DELAY_SECONDS,
        )
        event_types = [
            call.args[0]
            for call in api._emit.call_args_list
        ]
        self.assertIn("soft_reboot", event_types)
        self.assertIn("success", event_types)
        api._release_operation.assert_called_once()


class WebViewVerificationMessageTests(unittest.TestCase):
    def test_device_not_found_explains_charge_only_adb_setting(self) -> None:
        api = object.__new__(WebViewApi)

        payload = api._error_payload(
            DeviceAccessError("device_not_found", "missing adb interface")
        )

        self.assertEqual(payload["title"], "没有检测到平板")
        self.assertIn("仅充电模式下允许 ADB 调试", payload["message"])
        self.assertIn("传输文件", payload["message"])

    def test_reports_inactive_root_without_raw_json(self) -> None:
        api = object.__new__(WebViewApi)
        api._flow = Mock()
        api._flow.connect.side_effect = UserFlowError("device unavailable")
        api._emit = Mock()

        api._emit_verification_failure(
            {
                "ok": False,
                "failed_checks": ["root", "magisk", "zygisk", "vector"],
                "report": {"large": "diagnostic payload"},
            }
        )

        error_events = [
            call.args
            for call in api._emit.call_args_list
            if call.args[0] == "error"
        ]
        self.assertEqual(len(error_events), 1)
        error_payload = error_events[0][1]
        self.assertEqual(error_payload["title"], "Root 未激活")
        self.assertIn("一键 Root", error_payload["message"])
        self.assertNotIn("diagnostic payload", error_payload["message"])


if __name__ == "__main__":
    unittest.main()
