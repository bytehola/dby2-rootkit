import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from dby2_rootctl.adb import (
    AdbError,
    _local_path_for_adb,
    parse_devices_output,
)


class AdbParsingTests(unittest.TestCase):
    def test_parses_online_device_metadata(self) -> None:
        raw_output = (
            "List of devices attached\r\n"
            "DBY2-TEST-SERIAL        device "
            "product:DBY2-W00 model:DBY2_W00 device:HWDBY2 transport_id:12\r\n"
        )

        devices = parse_devices_output(raw_output)

        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].serial, "DBY2-TEST-SERIAL")
        self.assertEqual(devices[0].state, "device")
        self.assertEqual(devices[0].model, "DBY2_W00")
        self.assertEqual(devices[0].transport_id, "12")

    def test_ignores_disconnected_entries_without_metadata(self) -> None:
        raw_output = "List of devices attached\n1234567890\toffline\n"

        devices = parse_devices_output(raw_output)

        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].state, "offline")
        self.assertIsNone(devices[0].model)


class AdbPathTests(unittest.TestCase):
    def test_keeps_linux_path_for_linux_adb(self) -> None:
        local_path = Path("/home/example/DBY2-Magisk-OneTap.apk")

        converted_path = _local_path_for_adb(
            Path("/usr/bin/adb"),
            local_path,
        )

        self.assertEqual(converted_path, str(local_path))

    @patch(
        "dby2_rootctl.adb.shutil.which",
        return_value="/usr/bin/wslpath",
    )
    @patch(
        "dby2_rootctl.adb.subprocess.run",
        return_value=SimpleNamespace(
            returncode=0,
            stdout="C:\\Users\\example\\DBY2-Magisk-OneTap.apk\n",
            stderr="",
        ),
    )
    def test_converts_wsl_path_for_windows_adb(
        self,
        run_command,
        find_command,
    ) -> None:
        local_path = Path("/home/example/DBY2-Magisk-OneTap.apk")

        converted_path = _local_path_for_adb(
            Path("/mnt/d/tools/platform-tools/adb.exe"),
            local_path,
        )

        self.assertEqual(
            converted_path,
            "C:\\Users\\example\\DBY2-Magisk-OneTap.apk",
        )
        find_command.assert_called_once_with("wslpath")
        run_command.assert_called_once()

    @patch(
        "dby2_rootctl.adb.shutil.which",
        return_value="/usr/bin/wslpath",
    )
    @patch(
        "dby2_rootctl.adb.subprocess.run",
        return_value=SimpleNamespace(
            returncode=1,
            stdout="",
            stderr="conversion failed",
        ),
    )
    def test_rejects_failed_wsl_path_conversion(
        self,
        run_command,
        find_command,
    ) -> None:
        with self.assertRaisesRegex(AdbError, "Could not convert"):
            _local_path_for_adb(
                Path("/mnt/d/tools/platform-tools/adb.exe"),
                Path("/home/example/DBY2-Magisk-OneTap.apk"),
            )

        find_command.assert_called_once_with("wslpath")
        run_command.assert_called_once()


if __name__ == "__main__":
    unittest.main()
