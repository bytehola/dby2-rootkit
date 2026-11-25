import unittest

from dby2_rootctl.redact import redact_text, stable_hash


class RedactionTests(unittest.TestCase):
    def test_redacts_device_network_and_home_identifiers(self) -> None:
        raw_text = (
            "serial DBY2-TEST-SERIAL "
            "ip 203.0.113.7 "
            "mac 12:34:56:78:9a:bc "
            "path /home/example-user/project "
            "boot ded092c1-765b-4b99-88c5-a6c215fcb073"
        )

        redacted_text = redact_text(
            raw_text,
            secrets=[
                "DBY2-TEST-SERIAL",
                "ded092c1-765b-4b99-88c5-a6c215fcb073",
            ],
        )

        self.assertNotIn("DBY2-TEST-SERIAL", redacted_text)
        self.assertNotIn("203.0.113.7", redacted_text)
        self.assertNotIn("12:34:56:78:9a:bc", redacted_text)
        self.assertNotIn("/home/example-user", redacted_text)
        self.assertNotIn("ded092c1-765b-4b99-88c5-a6c215fcb073", redacted_text)

    def test_stable_hash_is_deterministic(self) -> None:
        self.assertEqual(stable_hash("example"), stable_hash("example"))
        self.assertNotEqual(stable_hash("example"), stable_hash("other"))

    def test_preserves_known_build_version_while_redacting_ip(self) -> None:
        raw_text = "build 4.2.0.252 ip 203.0.113.7"

        redacted_text = redact_text(
            raw_text,
            preserved_values=["4.2.0.252"],
        )

        self.assertIn("4.2.0.252", redacted_text)
        self.assertNotIn("203.0.113.7", redacted_text)
        self.assertIn("<ip>", redacted_text)


if __name__ == "__main__":
    unittest.main()
