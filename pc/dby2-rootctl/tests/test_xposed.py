import unittest

from dby2_rootctl.xposed import (
    XposedError,
    normalize_scope_target,
    parse_json_payload,
    validate_package_name,
)


class XposedParsingTests(unittest.TestCase):
    def test_scope_target_defaults_to_primary_user(self) -> None:
        self.assertEqual(
            normalize_scope_target("com.android.gpstest.osmdroid"),
            "com.android.gpstest.osmdroid/0",
        )

    def test_scope_target_preserves_explicit_user(self) -> None:
        self.assertEqual(
            normalize_scope_target("com.android.settings/10"),
            "com.android.settings/10",
        )

    def test_invalid_scope_target_is_rejected(self) -> None:
        with self.assertRaises(XposedError):
            normalize_scope_target("com.android.settings; rm -rf /")

    def test_invalid_package_is_rejected(self) -> None:
        with self.assertRaises(XposedError):
            validate_package_name("module package")

    def test_parses_json_payload_with_leading_noise(self) -> None:
        payload = parse_json_payload(
            "warning line\n{\"success\": true, \"data\": []}"
        )

        self.assertTrue(payload["success"])
        self.assertEqual(payload["data"], [])


if __name__ == "__main__":
    unittest.main()
