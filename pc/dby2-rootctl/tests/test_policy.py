import unittest

from dby2_rootctl.policy import (
    classify_boot_session,
    parse_package_uid_map,
    parse_policy_rows,
)


class PolicyParsingTests(unittest.TestCase):
    def test_parses_package_uid_map(self) -> None:
        raw_output = (
            "package:com.example.one uid:10200\n"
            "package:com.example.two uid:10200\n"
            "package:com.example.three uid:10201\n"
        )

        packages_by_uid = parse_package_uid_map(raw_output)

        self.assertEqual(
            packages_by_uid[10200],
            ["com.example.one", "com.example.two"],
        )
        self.assertEqual(packages_by_uid[10201], ["com.example.three"])

    def test_parses_policy_rows(self) -> None:
        raw_output = (
            "uid=2000|policy=2|until=0|logging=1|notification=1\n"
            "uid=10200|policy=1|until=123|logging=0|notification=0\n"
        )

        rows = parse_policy_rows(raw_output)

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["uid"], 2000)
        self.assertEqual(rows[1]["policy"], 1)
        self.assertEqual(rows[1]["until"], 123)

    def test_classifies_boot_session(self) -> None:
        self.assertEqual(classify_boot_session("boot-a", ""), "unmarked")
        self.assertEqual(classify_boot_session("boot-a", "boot-a"), "same-boot")
        self.assertEqual(classify_boot_session("boot-a", "boot-b"), "new-boot")


if __name__ == "__main__":
    unittest.main()
