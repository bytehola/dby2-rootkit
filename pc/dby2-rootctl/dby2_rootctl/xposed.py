from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from dby2_rootctl.adb import AdbClient, CommandResult


VECTOR_CLI = "/data/adb/modules/zygisk_vector/cli"
PACKAGE_PATTERN = re.compile(r"^[A-Za-z0-9._]+$")
SCOPE_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9._]+(?:/[0-9]+)?$")


class XposedError(RuntimeError):
    pass


@dataclass(frozen=True)
class XposedModule:
    package_name: str
    uid: int
    status: str

    @property
    def enabled(self) -> bool:
        return self.status.lower() == "enabled"


@dataclass(frozen=True)
class XposedScope:
    package_name: str
    user_id: int

    @property
    def target(self) -> str:
        return f"{self.package_name}/{self.user_id}"


def validate_package_name(package_name: str) -> str:
    if not PACKAGE_PATTERN.fullmatch(package_name):
        raise XposedError(f"Invalid package name: {package_name}")
    return package_name


def normalize_scope_target(target: str) -> str:
    normalized_target = target if "/" in target else f"{target}/0"
    if not SCOPE_TARGET_PATTERN.fullmatch(normalized_target):
        raise XposedError(f"Invalid scope target: {target}")
    return normalized_target


def parse_json_payload(raw_output: str) -> dict[str, Any]:
    opening_brace = raw_output.find("{")
    if opening_brace < 0:
        raise XposedError("Vector CLI returned no JSON payload")

    try:
        parsed_payload = json.loads(raw_output[opening_brace:])
    except json.JSONDecodeError as error:
        raise XposedError("Vector CLI returned invalid JSON") from error

    if not isinstance(parsed_payload, dict):
        raise XposedError("Vector CLI returned an unexpected JSON value")
    return parsed_payload


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\\''") + "'"


class XposedManager:
    def __init__(self, client: AdbClient):
        self.client = client

    def _run_root(self, command: str, timeout_seconds: float = 20.0) -> CommandResult:
        result = self.client.shell(
            f"/system/bin/su -c {shell_quote(command)}",
            timeout_seconds=timeout_seconds,
        )
        if not result.succeeded:
            detail = result.stderr.strip() or result.stdout.strip()
            raise XposedError(
                f"Vector command failed with exit code {result.returncode}: "
                f"{detail or command}"
            )
        return result

    def status(self) -> dict[str, Any]:
        result = self._run_root(f"{VECTOR_CLI} --json status")
        payload = parse_json_payload(result.stdout)
        if payload.get("success") is not True:
            raise XposedError("Vector status reported failure")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise XposedError("Vector status payload has no data object")
        return {
            "success": True,
            "framework_version": data.get("Framework Version"),
            "version_code": data.get("Version Code"),
            "api_version": data.get("API Version"),
            "enabled_modules": data.get("Enabled Modules"),
        }

    def modules(self) -> list[XposedModule]:
        result = self._run_root(f"{VECTOR_CLI} modules ls --json")
        payload = parse_json_payload(result.stdout)
        raw_modules = payload.get("data")
        if not isinstance(raw_modules, list):
            raise XposedError("Vector module payload has no data array")

        modules: list[XposedModule] = []
        for raw_module in raw_modules:
            if not isinstance(raw_module, dict):
                continue
            modules.append(
                XposedModule(
                    package_name=str(raw_module.get("PACKAGE", "")),
                    uid=int(raw_module.get("UID", -1)),
                    status=str(raw_module.get("STATUS", "unknown")),
                )
            )
        return modules

    def set_module_enabled(self, package_name: str, enabled: bool) -> str:
        validate_package_name(package_name)
        action = "enable" if enabled else "disable"
        result = self._run_root(
            f"{VECTOR_CLI} modules {action} {package_name}"
        )
        if "Failed: []" not in result.stdout:
            raise XposedError(
                f"Vector module update did not report a clean result: "
                f"{result.stdout.strip()}"
            )
        return result.stdout.strip()

    def scopes(self, package_name: str) -> list[XposedScope]:
        validate_package_name(package_name)
        result = self._run_root(
            f"{VECTOR_CLI} scope ls {package_name} --json"
        )
        payload = parse_json_payload(result.stdout)
        raw_scopes = payload.get("data")
        if not isinstance(raw_scopes, list):
            raise XposedError("Vector scope payload has no data array")

        scopes: list[XposedScope] = []
        for raw_scope in raw_scopes:
            if not isinstance(raw_scope, dict):
                continue
            scopes.append(
                XposedScope(
                    package_name=str(raw_scope.get("APP_PACKAGE", "")),
                    user_id=int(raw_scope.get("USER_ID", 0)),
                )
            )
        return scopes

    def update_scope(
        self,
        package_name: str,
        target: str,
        action: str,
    ) -> str:
        validate_package_name(package_name)
        normalized_target = normalize_scope_target(target)
        if action not in {"add", "rm"}:
            raise XposedError(f"Unsupported scope action: {action}")

        result = self._run_root(
            f"{VECTOR_CLI} scope {action} {package_name} {normalized_target}"
        )
        return result.stdout.strip()
