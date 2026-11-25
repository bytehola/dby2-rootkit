import unittest

from dby2_rootctl.device import DeviceSnapshot
from dby2_rootctl.profile import DEFAULT_PROFILE_DIRECTORY, evaluate_identity, load_profile
from dby2_rootctl.report import build_report


def build_snapshot() -> DeviceSnapshot:
    return DeviceSnapshot(
        serial_hash="serial-hash",
        model="DBY2-W00",
        android_release="12",
        sdk="31",
        abi="arm64-v8a",
        display_id="DBY2-W00 4.2.0.252(C00E100R3P5)",
        incremental="104.2.0.252C00",
        kernel="5.4.86-qgki-test",
        boot_id="boot-id",
        boot_id_hash="boot-hash",
        selinux_mode="Enforcing",
        shell_identity="uid=2000(shell)",
        root_available=True,
        root_identity="uid=0(root)",
        magisk_version="31.1:MAGISK:D",
        zygisk_status="injected",
        vector_status={"success": True},
        vector_error="",
        system_server_pid="100",
        surfaceflinger_pid="200",
        persistent_adb_port="5555",
    )


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = load_profile(DEFAULT_PROFILE_DIRECTORY)

    def test_active_root_and_xposed_produce_warning_for_persistent_adb(self) -> None:
        snapshot = build_snapshot()
        evaluation = evaluate_identity(self.profile, snapshot.identity())

        report = build_report(snapshot, evaluation)

        self.assertEqual(report["state"], "root-active")
        self.assertTrue(report["profile"]["succeeded"])
        self.assertTrue(
            any("Persistent TCP ADB" in warning for warning in report["warnings"])
        )

    def test_wrong_build_is_reported_as_unsupported(self) -> None:
        snapshot = build_snapshot()
        wrong_identity = snapshot.identity()
        wrong_identity["display_id"] = "DBY2-W00 other build"
        evaluation = evaluate_identity(self.profile, wrong_identity)

        report = build_report(snapshot, evaluation)

        self.assertEqual(report["state"], "unsupported")
        self.assertFalse(report["ok"])


if __name__ == "__main__":
    unittest.main()
