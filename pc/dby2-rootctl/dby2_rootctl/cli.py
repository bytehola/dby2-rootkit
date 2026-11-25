from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dby2_rootctl.adb import AdbClient, AdbError, find_adb, select_device
from dby2_rootctl.bootstrap import MagiskBootstrap
from dby2_rootctl.device import DeviceSnapshot, collect_snapshot
from dby2_rootctl.logs import create_diagnostic_archive
from dby2_rootctl.policy import MagiskPolicyInspector, PolicySnapshot
from dby2_rootctl.profile import (
    DEFAULT_PROFILE_DIRECTORY,
    DeviceProfile,
    ProfileEvaluation,
    ProfileError,
    evaluate_identity,
    load_profile,
)
from dby2_rootctl.report import build_report, format_human_report
from dby2_rootctl.xposed import XposedError, XposedManager, XposedModule, XposedScope


DEFAULT_RUNTIME_ENGINE = (
    Path(__file__).resolve().parents[3] / "runtime" / "root-engine" / "engine.sh"
)


def _calculate_sha256(file_path: Path) -> str:
    digest = hashlib.sha256()
    with file_path.open("rb") as file_handle:
        while True:
            file_chunk = file_handle.read(1024 * 1024)
            if not file_chunk:
                break
            digest.update(file_chunk)
    return digest.hexdigest()


def _resolve_artifact(
    artifact_path: Path,
    label: str,
    expected_sha256: str | None,
) -> Path:
    resolved_path = artifact_path.expanduser().resolve()
    if not resolved_path.is_file():
        raise AdbError(f"{label} does not exist: {resolved_path}")

    if expected_sha256 is None:
        return resolved_path

    normalized_expected = expected_sha256.strip().lower()
    if len(normalized_expected) != 64:
        raise AdbError(
            f"{label} SHA-256 must contain exactly 64 hexadecimal characters."
        )
    try:
        bytes.fromhex(normalized_expected)
    except ValueError as error:
        raise AdbError(
            f"{label} SHA-256 is not valid hexadecimal."
        ) from error

    actual_sha256 = _calculate_sha256(resolved_path)
    if actual_sha256 != normalized_expected:
        raise AdbError(
            f"{label} SHA-256 mismatch: "
            f"expected {normalized_expected}, actual {actual_sha256}"
        )
    return resolved_path


@dataclass(frozen=True)
class CollectedState:
    client: AdbClient
    snapshot: DeviceSnapshot
    profile: DeviceProfile
    evaluation: ProfileEvaluation
    report: dict[str, Any]


def _add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--adb",
        help="Path to adb or adb.exe. The ADB environment variable is also supported.",
    )
    parser.add_argument(
        "--serial",
        help="ADB serial. Required when multiple devices are online.",
    )
    parser.add_argument(
        "--profile-dir",
        type=Path,
        default=DEFAULT_PROFILE_DIRECTORY,
        help="Directory containing device profile JSON files.",
    )
    parser.add_argument(
        "--profile-id",
        help="Profile file stem or file name when multiple profiles exist.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON.",
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="dby2-rootctl",
        description="PC companion for DBY2-W00 temporary root.",
    )
    _add_common_arguments(parser)

    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("doctor", help="Check device compatibility and runtime state.")
    subparsers.add_parser("status", help="Print current device state.")

    verify_parser = subparsers.add_parser(
        "verify",
        help="Run read-only acceptance checks.",
    )
    verify_parser.add_argument(
        "--require-xposed",
        action="store_true",
        help="Fail unless Zygisk and Vector are both ready.",
    )

    logs_parser = subparsers.add_parser(
        "logs",
        help="Export a redacted diagnostic archive.",
    )
    logs_parser.add_argument(
        "--output",
        type=Path,
        help="Destination zip path.",
    )

    install_parser = subparsers.add_parser(
        "install",
        help="Install an APK after profile validation.",
    )
    install_parser.add_argument("apk", type=Path, help="APK to install.")
    install_parser.add_argument(
        "--sha256",
        help="Expected APK SHA-256.",
    )
    install_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate the APK and device without installing.",
    )

    root_parser = subparsers.add_parser(
        "root",
        help="Run an external runtime engine after safety checks.",
    )
    root_parser.add_argument(
        "--engine",
        type=Path,
        default=DEFAULT_RUNTIME_ENGINE,
        help="Runtime engine entrypoint. Defaults to runtime/root-engine/engine.sh.",
    )
    root_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would run without starting the engine.",
    )
    root_parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm starting the external root engine.",
    )

    xposed_parser = subparsers.add_parser(
        "xposed",
        help="Inspect and modify the Vector Xposed runtime.",
    )
    xposed_subparsers = xposed_parser.add_subparsers(
        dest="xposed_command",
        required=True,
    )
    xposed_subparsers.add_parser("status", help="Show Vector framework status.")
    xposed_subparsers.add_parser("modules", help="List installed Xposed modules.")

    for action_name, action_help in (
        ("enable", "Enable one Xposed module."),
        ("disable", "Disable one Xposed module."),
    ):
        module_parser = xposed_subparsers.add_parser(
            action_name,
            help=action_help,
        )
        module_parser.add_argument("package", help="Xposed module package name.")

    scope_parser = xposed_subparsers.add_parser(
        "scope",
        help="Inspect or modify module injection scopes.",
    )
    scope_subparsers = scope_parser.add_subparsers(
        dest="scope_command",
        required=True,
    )
    scope_list_parser = scope_subparsers.add_parser(
        "list",
        help="List scopes for one module.",
    )
    scope_list_parser.add_argument("package", help="Xposed module package name.")

    scope_add_parser = scope_subparsers.add_parser(
        "add",
        help="Add one target to a module scope.",
    )
    scope_add_parser.add_argument("package", help="Xposed module package name.")
    scope_add_parser.add_argument(
        "target",
        help="Target package as pkg or pkg/user_id.",
    )

    scope_remove_parser = scope_subparsers.add_parser(
        "remove",
        help="Remove one target from a module scope.",
    )
    scope_remove_parser.add_argument(
        "package",
        help="Xposed module package name.",
    )
    scope_remove_parser.add_argument(
        "target",
        help="Target package as pkg or pkg/user_id.",
    )

    policy_parser = subparsers.add_parser(
        "policy",
        help="Inspect Magisk superuser policies without changing them.",
    )
    policy_subparsers = policy_parser.add_subparsers(
        dest="policy_command",
        required=True,
    )
    policy_subparsers.add_parser(
        "list",
        help="List Magisk UID policies and package mappings.",
    )
    policy_subparsers.add_parser(
        "session",
        help="Show whether the persistent boot marker matches this boot.",
    )
    policy_mark_parser = policy_subparsers.add_parser(
        "mark",
        help="Write the current boot_id marker without changing policies.",
    )
    policy_mark_parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm writing the boot session marker.",
    )
    policy_expire_parser = policy_subparsers.add_parser(
        "expire",
        help="Plan or apply removal of stale policies after a boot change.",
    )
    policy_expire_parser.add_argument(
        "--preserve",
        type=int,
        action="append",
        default=[],
        help="UID to preserve; repeat for multiple UIDs.",
    )
    policy_expire_parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm backup and removal of stale policies.",
    )

    bootstrap_parser = subparsers.add_parser(
        "bootstrap",
        help="Install the ported Magisk APK, modules, and Vector runtime.",
    )
    bootstrap_parser.add_argument(
        "--magisk-apk",
        type=Path,
        required=True,
        help="DBY2 Magisk OneTap APK to install.",
    )
    bootstrap_parser.add_argument(
        "--magisk-sha256",
        help="Expected SHA-256 for the Magisk APK.",
    )
    bootstrap_parser.add_argument(
        "--rootkit-apk",
        type=Path,
        help="DBY2 RootKit manager APK to install.",
    )
    bootstrap_parser.add_argument(
        "--rootkit-sha256",
        help="Expected SHA-256 for the RootKit APK.",
    )
    bootstrap_parser.add_argument(
        "--nyazygisk-zip",
        type=Path,
        help="Source-built NyaZygisk module ZIP.",
    )
    bootstrap_parser.add_argument(
        "--nyazygisk-sha256",
        help="Expected SHA-256 for the NyaZygisk module ZIP.",
    )
    bootstrap_parser.add_argument(
        "--vector-zip",
        type=Path,
        help="Source-built Vector module ZIP.",
    )
    bootstrap_parser.add_argument(
        "--vector-sha256",
        help="Expected SHA-256 for the Vector module ZIP.",
    )
    bootstrap_parser.add_argument(
        "--engine",
        type=Path,
        default=DEFAULT_RUNTIME_ENGINE,
        help="Root engine used when the device is not rooted yet.",
    )
    bootstrap_parser.add_argument(
        "--require-existing-root",
        action="store_true",
        help="Fail instead of invoking an external runtime engine.",
    )
    bootstrap_parser.add_argument(
        "--skip-modules",
        action="store_true",
        help="Do not install module ZIPs.",
    )
    bootstrap_parser.add_argument(
        "--skip-activation",
        action="store_true",
        help="Do not start Zygisk/Vector after setup.",
    )
    bootstrap_parser.add_argument(
        "--replace-modules",
        action="store_true",
        help="Backup active modules and activate the newly installed module ZIPs.",
    )
    bootstrap_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate inputs and print the bootstrap plan.",
    )
    bootstrap_parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm installation and runtime changes.",
    )

    resume_parser = subparsers.add_parser(
        "resume",
        help="Restore root and the installed Zygisk/Vector runtime after a reboot.",
    )
    resume_parser.add_argument(
        "--magisk-apk",
        type=Path,
        required=True,
        help="Matching DBY2 Magisk OneTap APK used to stage runtime assets.",
    )
    resume_parser.add_argument(
        "--magisk-sha256",
        help="Expected SHA-256 for the Magisk APK.",
    )
    resume_parser.add_argument(
        "--engine",
        type=Path,
        default=DEFAULT_RUNTIME_ENGINE,
        help="Root engine used when the device is not rooted yet.",
    )
    resume_parser.add_argument(
        "--require-existing-root",
        action="store_true",
        help="Fail instead of invoking an external runtime engine.",
    )
    resume_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate inputs and print the resume plan.",
    )
    resume_parser.add_argument(
        "--yes",
        action="store_true",
        help="Confirm root and runtime changes.",
    )

    return parser


def _collect(
    arguments: argparse.Namespace,
) -> CollectedState:
    adb_path = find_adb(arguments.adb)
    adb_device = select_device(adb_path, arguments.serial)
    client = AdbClient(adb_path, adb_device.serial)
    snapshot = collect_snapshot(client)
    profile = load_profile(arguments.profile_dir, arguments.profile_id)
    evaluation = evaluate_identity(profile, snapshot.identity())
    report = build_report(snapshot, evaluation)
    return CollectedState(
        client=client,
        snapshot=snapshot,
        profile=profile,
        evaluation=evaluation,
        report=report,
    )


def _print_report(report: dict[str, Any], json_output: bool) -> None:
    if json_output:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print(format_human_report(report))


def _profile_exit_code(report: dict[str, Any]) -> int:
    return 0 if report["profile"]["succeeded"] else 5


def _run_runtime_engine(
    collected_state: CollectedState,
    engine_path: Path,
) -> subprocess.CompletedProcess[str]:
    resolved_engine = engine_path.expanduser().resolve()
    if not resolved_engine.is_file():
        raise AdbError(f"Runtime engine does not exist: {resolved_engine}")

    environment = os.environ.copy()
    environment["ADB"] = str(collected_state.client.adb_path)
    environment["SERIAL"] = collected_state.client.serial
    environment["DBY2_PROFILE_ID"] = collected_state.profile.profile_id
    return subprocess.run(
        ["bash", str(resolved_engine)],
        cwd=str(resolved_engine.parent),
        env=environment,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )


def _run_doctor(arguments: argparse.Namespace) -> int:
    collected_state = _collect(arguments)
    _print_report(collected_state.report, arguments.json)
    return _profile_exit_code(collected_state.report)


def _run_status(arguments: argparse.Namespace) -> int:
    collected_state = _collect(arguments)
    _print_report(collected_state.report, arguments.json)
    return _profile_exit_code(collected_state.report)


def _run_verify(arguments: argparse.Namespace) -> int:
    collected_state = _collect(arguments)
    report = collected_state.report
    checks = {check["name"]: check["succeeded"] for check in report["checks"]}
    required_checks = [
        "profile",
        "root",
        "magisk",
        "system_server",
        "surfaceflinger",
    ]
    if arguments.require_xposed:
        required_checks.extend(["zygisk", "vector"])

    failed_checks = [
        name
        for name in required_checks
        if checks.get(name) is not True
    ]
    verification_result = {
        "ok": not failed_checks,
        "failed_checks": failed_checks,
        "report": report,
    }

    if arguments.json:
        print(json.dumps(verification_result, ensure_ascii=False, indent=2))
    else:
        print(format_human_report(report))
        print()
        if failed_checks:
            print(f"Verification failed: {', '.join(failed_checks)}")
        else:
            print("Verification passed.")

    if report["profile"]["succeeded"] is not True:
        return 5
    return 0 if not failed_checks else 9


def _run_logs(arguments: argparse.Namespace) -> int:
    collected_state = _collect(arguments)
    archive_path = create_diagnostic_archive(
        client=collected_state.client,
        snapshot=collected_state.snapshot,
        report=collected_state.report,
        output_path=arguments.output,
    )
    result = {
        "ok": True,
        "archive": str(archive_path),
    }
    if arguments.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(f"Diagnostic archive: {archive_path}")
    return 0


def _run_install(arguments: argparse.Namespace) -> int:
    apk_path = arguments.apk.expanduser().resolve()
    if not apk_path.is_file():
        raise AdbError(f"APK does not exist: {apk_path}")

    actual_sha256 = hashlib.sha256(apk_path.read_bytes()).hexdigest()
    if arguments.sha256 and actual_sha256.lower() != arguments.sha256.lower():
        raise AdbError(
            "APK SHA-256 mismatch: "
            f"expected {arguments.sha256}, actual {actual_sha256}"
        )

    collected_state = _collect(arguments)
    if not collected_state.evaluation.succeeded:
        raise AdbError("Device does not match the selected profile.")

    if arguments.dry_run:
        result = {
            "ok": True,
            "dry_run": True,
            "apk": str(apk_path),
            "sha256": actual_sha256,
            "profile_id": collected_state.profile.profile_id,
            "serial_hash": collected_state.snapshot.serial_hash,
        }
        if arguments.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(
                "APK validation passed: "
                f"{apk_path} ({actual_sha256})"
            )
        return 0

    install_result = collected_state.client.install(apk_path)
    result = {
        "ok": install_result.succeeded,
        "apk": str(apk_path),
        "sha256": actual_sha256,
        "output": install_result.stdout.strip(),
        "error": install_result.stderr.strip(),
    }
    if arguments.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(result["output"] or result["error"])
    return 0 if install_result.succeeded else 8


def _run_root(arguments: argparse.Namespace) -> int:
    collected_state = _collect(arguments)
    snapshot = collected_state.snapshot
    if not collected_state.evaluation.succeeded:
        _print_report(collected_state.report, arguments.json)
        return 5
    if snapshot.root_available:
        result = {
            "ok": True,
            "message": "Temporary root is already active for this boot.",
            "root_identity": snapshot.root_identity,
        }
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0

    engine_path = arguments.engine.expanduser().resolve()
    if not engine_path.is_file():
        raise AdbError(f"Runtime engine does not exist: {engine_path}")
    if arguments.dry_run:
        print(
            json.dumps(
                {
                    "ok": True,
                    "dry_run": True,
                    "adb": str(collected_state.client.adb_path),
                    "serial_hash": snapshot.serial_hash,
                    "profile_id": collected_state.profile.profile_id,
                    "engine": str(engine_path),
                    "payload_engine": os.environ.get(
                        "DBY2_RUNTIME_ENGINE",
                        "",
                    ),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 0
    if not arguments.yes:
        print(
            "Refusing to run the root engine without --yes.",
            file=sys.stderr,
        )
        return 10

    completed_process = _run_runtime_engine(collected_state, engine_path)
    return completed_process.returncode


def _print_xposed_status(status: dict[str, Any], json_output: bool) -> None:
    if json_output:
        print(json.dumps({"ok": True, "status": status}, ensure_ascii=False, indent=2))
        return

    print(f"Framework: {status['framework_version']}")
    print(f"API: {status['api_version']}")
    print(f"Enabled modules: {status['enabled_modules']}")


def _print_xposed_modules(
    modules: list[XposedModule],
    json_output: bool,
) -> None:
    if json_output:
        print(
            json.dumps(
                {
                    "ok": True,
                    "modules": [
                        {
                            "package": module.package_name,
                            "uid": module.uid,
                            "status": module.status,
                        }
                        for module in modules
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    for module in modules:
        print(f"{module.package_name}  uid={module.uid}  {module.status}")


def _print_xposed_scopes(
    scopes: list[XposedScope],
    json_output: bool,
) -> None:
    if json_output:
        print(
            json.dumps(
                {
                    "ok": True,
                    "scopes": [
                        {
                            "package": scope.package_name,
                            "user_id": scope.user_id,
                            "target": scope.target,
                        }
                        for scope in scopes
                    ],
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    for scope in scopes:
        print(scope.target)


def _run_xposed(arguments: argparse.Namespace) -> int:
    collected_state = _collect(arguments)
    if not collected_state.evaluation.succeeded:
        raise XposedError("Device does not match the selected profile.")
    if not collected_state.snapshot.root_available:
        raise XposedError("Temporary root is not active in this boot.")

    xposed_manager = XposedManager(collected_state.client)

    if arguments.xposed_command == "status":
        _print_xposed_status(xposed_manager.status(), arguments.json)
        return 0

    if arguments.xposed_command == "modules":
        _print_xposed_modules(xposed_manager.modules(), arguments.json)
        return 0

    if arguments.xposed_command in {"enable", "disable"}:
        enabled = arguments.xposed_command == "enable"
        message = xposed_manager.set_module_enabled(arguments.package, enabled)
        result = {
            "ok": True,
            "package": arguments.package,
            "enabled": enabled,
            "message": message,
        }
        if arguments.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(message)
        return 0

    if arguments.xposed_command == "scope":
        if arguments.scope_command == "list":
            _print_xposed_scopes(
                xposed_manager.scopes(arguments.package),
                arguments.json,
            )
            return 0

        action = "add" if arguments.scope_command == "add" else "rm"
        message = xposed_manager.update_scope(
            arguments.package,
            arguments.target,
            action,
        )
        result = {
            "ok": True,
            "package": arguments.package,
            "target": arguments.target,
            "action": arguments.scope_command,
            "message": message,
        }
        if arguments.json:
            print(json.dumps(result, ensure_ascii=False, indent=2))
        else:
            print(message)
        return 0

    raise XposedError(f"Unsupported xposed command: {arguments.xposed_command}")


def _print_policy_snapshot(
    snapshot: PolicySnapshot,
    json_output: bool,
) -> None:
    if json_output:
        print(
            json.dumps(
                {
                    "ok": True,
                    **snapshot.as_dict(),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return

    print(f"Boot hash: {snapshot.boot_id_hash}")
    for policy in snapshot.policies:
        packages = ", ".join(policy.packages) if policy.packages else "unmapped"
        print(
            f"{policy.uid}  {policy.decision}  "
            f"until={policy.until}  "
            f"logging={policy.logging}  "
            f"notification={policy.notification}  "
            f"{packages}"
        )


def _run_policy(arguments: argparse.Namespace) -> int:
    collected_state = _collect(arguments)
    if not collected_state.evaluation.succeeded:
        raise XposedError("Device does not match the selected profile.")
    if not collected_state.snapshot.root_available:
        raise XposedError("Temporary root is not active in this boot.")

    policy_inspector = MagiskPolicyInspector(collected_state.client)

    if arguments.policy_command == "list":
        policy_snapshot = policy_inspector.inspect()
        _print_policy_snapshot(policy_snapshot, arguments.json)
        return 0

    if arguments.policy_command == "session":
        boot_session = policy_inspector.inspect_boot_session()
        if arguments.json:
            print(
                json.dumps(
                    {"ok": True, **boot_session.as_dict()},
                    ensure_ascii=False,
                    indent=2,
                )
            )
        else:
            print(f"Current boot hash: {boot_session.current_boot_hash}")
            print(f"Marker boot hash: {boot_session.marker_boot_hash or 'unmarked'}")
            print(f"State: {boot_session.state}")
        return 0

    if arguments.policy_command == "mark":
        if not arguments.yes:
            raise XposedError("Refusing to write boot marker without --yes.")
        boot_session = policy_inspector.mark_boot_session()
        if arguments.json:
            print(
                json.dumps(
                    {"ok": True, **boot_session.as_dict()},
                    ensure_ascii=False,
                    indent=2,
                )
            )
        else:
            print(f"Boot session marked: {boot_session.state}")
        return 0

    if arguments.policy_command == "expire":
        preserve_uids = {2000}
        package_output = collected_state.client.shell(
            "cmd package list packages -U",
            timeout_seconds=20.0,
        )
        if package_output.succeeded:
            for line in package_output.stdout.splitlines():
                if "package:dev.dby2.rootkit " in line and "uid:" in line:
                    preserve_uids.add(
                        int(line.rsplit("uid:", 1)[1].strip())
                    )
        preserve_uids.update(arguments.preserve)
        plan = policy_inspector.build_expiry_plan(preserve_uids)

        if arguments.json:
            print(
                json.dumps(
                    {"ok": True, **plan.as_dict()},
                    ensure_ascii=False,
                    indent=2,
                )
            )
        else:
            print(f"State: {plan.state}")
            print(f"Preserve UIDs: {', '.join(map(str, plan.preserve_uids))}")
            print(f"Expiring UIDs: {', '.join(map(str, plan.expiring_uids)) or 'none'}")
            print(f"Backup path: {plan.backup_path}")

        if arguments.yes and plan.expiring_uids:
            boot_session = policy_inspector.apply_expiry_plan(plan)
            result = {
                "ok": True,
                "applied": True,
                "boot_session": boot_session.as_dict(),
                "plan": plan.as_dict(),
            }
            if arguments.json:
                print(json.dumps(result, ensure_ascii=False, indent=2))
            else:
                print("Stale policies removed and boot session remarked.")
        return 0

    raise XposedError(f"Unsupported policy command: {arguments.policy_command}")


def _run_bootstrap(arguments: argparse.Namespace) -> int:
    collected_state = _collect(arguments)
    if not collected_state.evaluation.succeeded:
        raise XposedError("Device does not match the selected profile.")

    magisk_apk = _resolve_artifact(
        arguments.magisk_apk,
        "Magisk APK",
        arguments.magisk_sha256,
    )

    rootkit_apk = (
        _resolve_artifact(
            arguments.rootkit_apk,
            "RootKit APK",
            arguments.rootkit_sha256,
        )
        if arguments.rootkit_apk is not None
        else None
    )

    module_zips: list[Path] = []
    module_inputs = (
        (
            arguments.nyazygisk_zip,
            arguments.nyazygisk_sha256,
            "NyaZygisk module ZIP",
        ),
        (
            arguments.vector_zip,
            arguments.vector_sha256,
            "Vector module ZIP",
        ),
    )
    for module_zip, module_sha256, module_label in module_inputs:
        if module_zip is None:
            continue
        module_zips.append(
            _resolve_artifact(
                module_zip,
                module_label,
                module_sha256,
            )
        )

    plan = {
        "magisk_apk": str(magisk_apk),
        "rootkit_apk": str(rootkit_apk) if rootkit_apk else "",
        "modules": [str(module_zip) for module_zip in module_zips],
        "root_already_active": collected_state.snapshot.root_available,
        "engine": str(arguments.engine.resolve()),
        "activate": not arguments.skip_activation,
        "replace_modules": arguments.replace_modules,
    }
    if arguments.dry_run:
        if arguments.json:
            print(json.dumps({"ok": True, "dry_run": True, **plan}, indent=2))
        else:
            print(json.dumps(plan, indent=2))
        return 0
    if not arguments.yes:
        raise XposedError("Refusing bootstrap without --yes.")

    if not collected_state.snapshot.root_available:
        if arguments.require_existing_root:
            raise XposedError(
                "The packaged root broker is not active. "
                "External runtime engine fallback is disabled."
            )
        engine_result = _run_runtime_engine(
            collected_state,
            arguments.engine,
        )
        if engine_result.returncode != 0:
            raise XposedError(
                f"Root engine failed with exit code {engine_result.returncode}."
            )
        collected_state = _collect(arguments)
        if not collected_state.snapshot.root_available:
            raise XposedError("Root engine finished but UID 0 is not available.")

    bootstrap = MagiskBootstrap(collected_state.client)
    bootstrap.install_apk(magisk_apk)
    app_info = bootstrap.read_package_info()
    magisk_output = bootstrap.install_magisk(magisk_apk, app_info)
    rootkit_output = ""
    if rootkit_apk is not None:
        rootkit_result = collected_state.client.install(rootkit_apk)
        if not rootkit_result.succeeded:
            raise XposedError(
                "RootKit APK install failed: "
                f"{rootkit_result.stderr.strip() or rootkit_result.stdout.strip()}"
            )
        rootkit_output = rootkit_result.stdout.strip()

    module_outputs: list[str] = []
    if not arguments.skip_modules:
        for module_zip in module_zips:
            module_outputs.append(
                bootstrap.install_module(
                    module_zip,
                    replace_existing=arguments.replace_modules,
                )
            )

    activation_output = ""
    if not arguments.skip_activation:
        activation_output = bootstrap.activate_runtime()

    final_state = _collect(arguments)
    final_checks = {
        check["name"]: check["succeeded"]
        for check in final_state.report["checks"]
    }
    required_checks = ["root", "magisk"]
    if not arguments.skip_activation:
        required_checks.extend(["zygisk", "vector"])
    result = {
        "ok": all(final_checks.get(name) is True for name in required_checks),
        "magisk_app": {
            "uid": app_info.uid,
            "native_directory": app_info.native_directory,
            "version": app_info.version_name,
        },
        "magisk_setup": magisk_output,
        "rootkit_install": rootkit_output,
        "module_outputs": module_outputs,
        "activation": activation_output,
        "final_report": final_state.report,
    }
    if arguments.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("bootstrap complete")
        print(f"Magisk: {final_state.snapshot.magisk_version}")
        print(f"Root: {final_state.snapshot.root_identity}")
        print(f"Vector: {final_state.snapshot.vector_status}")
    return 0 if result["ok"] else 9


def _run_resume(arguments: argparse.Namespace) -> int:
    collected_state = _collect(arguments)
    if not collected_state.evaluation.succeeded:
        raise XposedError("Device does not match the selected profile.")

    magisk_apk = _resolve_artifact(
        arguments.magisk_apk,
        "Magisk APK",
        arguments.magisk_sha256,
    )
    plan = {
        "magisk_apk": str(magisk_apk),
        "root_already_active": collected_state.snapshot.root_available,
        "engine": str(arguments.engine.expanduser().resolve()),
        "reuse_installed_modules": True,
    }
    if arguments.dry_run:
        if arguments.json:
            print(json.dumps({"ok": True, "dry_run": True, **plan}, indent=2))
        else:
            print(json.dumps(plan, indent=2))
        return 0
    if not arguments.yes:
        raise XposedError("Refusing resume without --yes.")

    if not collected_state.snapshot.root_available:
        if arguments.require_existing_root:
            raise XposedError(
                "The packaged root broker is not active. "
                "External runtime engine fallback is disabled."
            )
        engine_result = _run_runtime_engine(
            collected_state,
            arguments.engine,
        )
        if engine_result.returncode != 0:
            raise XposedError(
                f"Root engine failed with exit code {engine_result.returncode}."
            )
        collected_state = _collect(arguments)
        if not collected_state.evaluation.succeeded:
            raise XposedError("Device profile changed after root engine execution.")
        if not collected_state.snapshot.root_available:
            raise XposedError("Root engine finished but UID 0 is not available.")

    bootstrap = MagiskBootstrap(collected_state.client)
    app_info = bootstrap.read_package_info()
    magisk_output = bootstrap.install_magisk(magisk_apk, app_info)
    activation_output = bootstrap.activate_runtime()

    final_state = _collect(arguments)
    final_checks = {
        check["name"]: check["succeeded"]
        for check in final_state.report["checks"]
    }
    required_checks = ["root", "magisk", "zygisk", "vector"]
    result = {
        "ok": all(final_checks.get(name) is True for name in required_checks),
        "magisk_app": {
            "uid": app_info.uid,
            "native_directory": app_info.native_directory,
            "version": app_info.version_name,
        },
        "magisk_setup": magisk_output,
        "activation": activation_output,
        "final_report": final_state.report,
    }
    if arguments.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print("resume complete")
        print(f"Magisk: {final_state.snapshot.magisk_version}")
        print(f"Root: {final_state.snapshot.root_identity}")
        print(f"Vector: {final_state.snapshot.vector_status}")
    return 0 if result["ok"] else 9


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    arguments = parser.parse_args(argv)

    command_handlers = {
        "doctor": _run_doctor,
        "status": _run_status,
        "verify": _run_verify,
        "logs": _run_logs,
        "install": _run_install,
        "root": _run_root,
        "xposed": _run_xposed,
        "policy": _run_policy,
        "bootstrap": _run_bootstrap,
        "resume": _run_resume,
    }

    try:
        return command_handlers[arguments.command](arguments)
    except (AdbError, ProfileError, XposedError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        return 130
