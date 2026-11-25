import argparse
import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from dby2_rootctl.adb import AdbError
from dby2_rootctl.cli import (
    _build_parser,
    _calculate_sha256,
    _run_resume,
    _resolve_artifact,
)


class ArtifactValidationTests(unittest.TestCase):
    def test_resolves_artifact_with_matching_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_path = Path(temporary) / "artifact.apk"
            artifact_path.write_bytes(b"DBY2 test artifact")
            expected_sha256 = hashlib.sha256(
                artifact_path.read_bytes()
            ).hexdigest()

            resolved_path = _resolve_artifact(
                artifact_path,
                "Test APK",
                expected_sha256,
            )

            self.assertEqual(resolved_path, artifact_path.resolve())
            self.assertEqual(
                _calculate_sha256(resolved_path),
                expected_sha256,
            )

    def test_rejects_artifact_with_mismatched_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_path = Path(temporary) / "artifact.apk"
            artifact_path.write_bytes(b"DBY2 test artifact")

            with self.assertRaisesRegex(AdbError, "SHA-256 mismatch"):
                _resolve_artifact(
                    artifact_path,
                    "Test APK",
                    "0" * 64,
                )

    def test_rejects_invalid_expected_sha256(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            artifact_path = Path(temporary) / "artifact.apk"
            artifact_path.write_bytes(b"DBY2 test artifact")

            with self.assertRaisesRegex(AdbError, "64 hexadecimal"):
                _resolve_artifact(
                    artifact_path,
                    "Test APK",
                    "not-a-sha256",
                )


class CommandParserTests(unittest.TestCase):
    def test_resume_accepts_magisk_artifact_and_sha256(self) -> None:
        arguments = _build_parser().parse_args(
            [
                "resume",
                "--magisk-apk",
                "DBY2-Magisk-OneTap.apk",
                "--magisk-sha256",
                "a" * 64,
                "--require-existing-root",
                "--yes",
            ]
        )

        self.assertEqual(arguments.command, "resume")
        self.assertEqual(
            arguments.magisk_apk,
            Path("DBY2-Magisk-OneTap.apk"),
        )
        self.assertEqual(arguments.magisk_sha256, "a" * 64)
        self.assertTrue(arguments.require_existing_root)
        self.assertTrue(arguments.yes)

    def test_bootstrap_accepts_all_optional_sha256_arguments(self) -> None:
        arguments = _build_parser().parse_args(
            [
                "bootstrap",
                "--magisk-apk",
                "magisk.apk",
                "--magisk-sha256",
                "1" * 64,
                "--rootkit-apk",
                "rootkit.apk",
                "--rootkit-sha256",
                "2" * 64,
                "--nyazygisk-zip",
                "nyazygisk.zip",
                "--nyazygisk-sha256",
                "3" * 64,
                "--vector-zip",
                "vector.zip",
                "--vector-sha256",
                "4" * 64,
                "--require-existing-root",
            ]
        )

        self.assertEqual(arguments.command, "bootstrap")
        self.assertEqual(arguments.magisk_sha256, "1" * 64)
        self.assertEqual(arguments.rootkit_sha256, "2" * 64)
        self.assertEqual(arguments.nyazygisk_sha256, "3" * 64)
        self.assertEqual(arguments.vector_sha256, "4" * 64)
        self.assertTrue(arguments.require_existing_root)


class ResumeFlowTests(unittest.TestCase):
    @staticmethod
    def _state(root_available: bool, checks: dict[str, bool]) -> SimpleNamespace:
        return SimpleNamespace(
            client=object(),
            snapshot=SimpleNamespace(
                root_available=root_available,
                root_identity="uid=0(root)" if root_available else "",
                magisk_version="31.1:MAGISK:D" if root_available else "",
                vector_status={} if not root_available else {"success": True},
            ),
            profile=SimpleNamespace(profile_id="dby2-w00-test"),
            evaluation=SimpleNamespace(succeeded=True),
            report={
                "checks": [
                    {"name": check_name, "succeeded": succeeded}
                    for check_name, succeeded in checks.items()
                ]
            },
        )

    def test_resume_reacquires_root_and_activates_installed_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            magisk_apk = Path(temporary) / "magisk.apk"
            magisk_apk.write_bytes(b"test Magisk artifact")
            initial_state = self._state(
                root_available=False,
                checks={
                    "profile": True,
                    "root": False,
                    "magisk": False,
                },
            )
            rooted_state = self._state(
                root_available=True,
                checks={
                    "profile": True,
                    "root": True,
                    "magisk": False,
                },
            )
            final_state = self._state(
                root_available=True,
                checks={
                    "profile": True,
                    "root": True,
                    "magisk": True,
                    "zygisk": True,
                    "vector": True,
                },
            )
            arguments = argparse.Namespace(
                magisk_apk=magisk_apk,
                magisk_sha256=None,
                engine=Path("/test/engine.sh"),
                require_existing_root=False,
                dry_run=False,
                yes=True,
                json=True,
            )
            app_info = SimpleNamespace(
                uid=10245,
                native_directory="/data/app/magisk/lib/arm64",
                version_name="31.1",
            )
            bootstrap = SimpleNamespace(
                read_package_info=lambda: app_info,
                install_magisk=lambda apk_path, package_info: "MAGISK_READY",
                activate_runtime=lambda: "DBY2_XPOSED_READY",
            )

            with (
                patch(
                    "dby2_rootctl.cli._collect",
                    side_effect=[initial_state, rooted_state, final_state],
                ),
                patch(
                    "dby2_rootctl.cli._run_runtime_engine",
                    return_value=SimpleNamespace(returncode=0),
                ) as run_engine,
                patch(
                    "dby2_rootctl.cli.MagiskBootstrap",
                    return_value=bootstrap,
                ),
                redirect_stdout(io.StringIO()) as output,
            ):
                exit_code = _run_resume(arguments)

        result = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertTrue(result["ok"])
        self.assertEqual(result["magisk_setup"], "MAGISK_READY")
        self.assertEqual(result["activation"], "DBY2_XPOSED_READY")
        run_engine.assert_called_once_with(initial_state, arguments.engine)


if __name__ == "__main__":
    unittest.main()
