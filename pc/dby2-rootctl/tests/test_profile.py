import unittest

from dby2_rootctl.profile import DEFAULT_PROFILE_DIRECTORY, evaluate_identity, load_profile


class ProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profile = load_profile(DEFAULT_PROFILE_DIRECTORY)

    def test_matching_identity_passes(self) -> None:
        identity = {
            "model": "DBY2-W00",
            "sdk": "31",
            "abi": "arm64-v8a",
            "kernel": "5.4.86-qgki-g95ef09c54a40-dirty",
            "display_id": "DBY2-W00 4.2.0.252(C00E100R3P5)",
            "incremental": "104.2.0.252C00",
        }

        evaluation = evaluate_identity(self.profile, identity)

        self.assertTrue(evaluation.succeeded)

    def test_kernel_mismatch_fails(self) -> None:
        identity = {
            "model": "DBY2-W00",
            "sdk": "31",
            "abi": "arm64-v8a",
            "kernel": "5.10.1-other",
            "display_id": "DBY2-W00 4.2.0.252(C00E100R3P5)",
            "incremental": "104.2.0.252C00",
        }

        evaluation = evaluate_identity(self.profile, identity)

        self.assertFalse(evaluation.succeeded)
        failed_names = {
            check.name for check in evaluation.checks if not check.succeeded
        }
        self.assertEqual(failed_names, {"kernel"})


if __name__ == "__main__":
    unittest.main()
