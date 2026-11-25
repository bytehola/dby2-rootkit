package dev.dby2.rootkit;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

final class RuntimeInspector {
    private static final String VECTOR_CLI =
            "/data/adb/modules/zygisk_vector/cli";
    private static final String NYAZYGISK_PROPERTIES =
            "/data/system_de/nyazygisk/module.prop";

    private final ShellCommandRunner commandRunner;

    RuntimeInspector(ShellCommandRunner commandRunner) {
        this.commandRunner = commandRunner;
    }

    RuntimeReport inspect() {
        String summary = "magisk: " + readMagiskVersion() + "\n"
                + "zygisk: " + readZygiskStatus() + "\n"
                + "vector: " + readVectorStatus();
        ModuleReadResult moduleResult = readVectorModules();
        return new RuntimeReport(
                summary,
                moduleResult.modules,
                moduleResult.error
        );
    }

    CommandResult setModuleEnabled(String packageName, boolean enabled) {
        if (!isValidPackageName(packageName)) {
            return new CommandResult("invalid package name", 2, false);
        }

        String action = enabled ? "enable" : "disable";
        CommandResult result = commandRunner.runRoot(
                VECTOR_CLI + " modules " + action + " " + packageName
        );
        if (result.succeeded() && result.output.contains("Failed: []")) {
            return result;
        }
        return new CommandResult(result.output, result.exitCode, result.timedOut);
    }

    ModuleScopeReport readModuleScopes(String modulePackage) {
        if (!isValidPackageName(modulePackage)) {
            return new ModuleScopeReport(
                    Collections.emptyList(),
                    "invalid module package"
            );
        }

        CommandResult result = commandRunner.runRoot(
                VECTOR_CLI + " scope ls " + modulePackage + " --json"
        );
        if (!result.succeeded()) {
            return new ModuleScopeReport(
                    Collections.emptyList(),
                    "scope list unavailable"
            );
        }

        try {
            JSONObject response = new JSONObject(result.output);
            JSONArray scopes = response.optJSONArray("data");
            if (scopes == null) {
                return new ModuleScopeReport(
                        Collections.emptyList(),
                        "invalid scope response"
                );
            }

            List<String> scopeEntries = new ArrayList<>();
            for (int index = 0; index < scopes.length(); index++) {
                JSONObject scope = scopes.optJSONObject(index);
                if (scope == null) {
                    continue;
                }
                scopeEntries.add(
                        scope.optString("APP_PACKAGE", "unknown")
                                + "/"
                                + scope.optInt("USER_ID", 0)
                );
            }
            return new ModuleScopeReport(scopeEntries, "");
        } catch (Exception error) {
            return new ModuleScopeReport(
                    Collections.emptyList(),
                    "invalid scope response"
            );
        }
    }

    CommandResult addModuleScope(String modulePackage, String target) {
        return updateModuleScope(modulePackage, target, "add");
    }

    CommandResult removeModuleScope(String modulePackage, String target) {
        return updateModuleScope(modulePackage, target, "rm");
    }

    private CommandResult updateModuleScope(
            String modulePackage,
            String target,
            String action
    ) {
        if (!isValidPackageName(modulePackage)) {
            return new CommandResult("invalid module package", 2, false);
        }

        String normalizedTarget = target.contains("/") ? target : target + "/0";
        if (!normalizedTarget.matches("[A-Za-z0-9._]+/[0-9]+")) {
            return new CommandResult("invalid target package", 2, false);
        }

        String command = VECTOR_CLI + " scope " + action + " "
                + modulePackage + " " + normalizedTarget;
        CommandResult result = commandRunner.runRoot(command);
        Log.d(
                "DBY2RootKit",
                "scope command=" + command
                        + " exit=" + result.exitCode
                        + " output=" + result.output
        );
        return result;
    }

    private boolean isValidPackageName(String packageName) {
        return packageName.matches("[A-Za-z0-9._]+");
    }

    private String readMagiskVersion() {
        CommandResult result = commandRunner.runRoot("/system/bin/magisk -v");
        if (!result.succeeded()) {
            return "unavailable";
        }
        return result.displayText();
    }

    private String readZygiskStatus() {
        CommandResult result = commandRunner.runRoot(
                "cat " + NYAZYGISK_PROPERTIES
        );
        if (!result.succeeded()) {
            return "unavailable";
        }

        String version = "unknown";
        String injection = "unknown";
        String daemon = "unknown";
        for (String line : result.output.split("\n")) {
            if (line.startsWith("version=")) {
                version = line.substring("version=".length());
            } else if (line.startsWith("zygote_64_status=")) {
                injection = line.substring("zygote_64_status=".length());
            } else if (line.startsWith("daemon_64_status=")) {
                daemon = line.substring("daemon_64_status=".length());
            }
        }
        return version + " / zygote=" + injection + " / daemon=" + daemon;
    }

    private String readVectorStatus() {
        CommandResult result = commandRunner.runRoot(
                VECTOR_CLI + " --json status"
        );
        if (!result.succeeded()) {
            return "unavailable";
        }

        try {
            JSONObject response = new JSONObject(result.output);
            JSONObject data = response.optJSONObject("data");
            if (data == null) {
                return "invalid status response";
            }
            return "framework=" + data.optString("Framework Version", "unknown")
                    + " / api=" + data.optInt("API Version", 0)
                    + " / modules=" + data.optInt("Enabled Modules", 0);
        } catch (Exception error) {
            return "invalid status response";
        }
    }

    private ModuleReadResult readVectorModules() {
        CommandResult result = commandRunner.runRoot(
                VECTOR_CLI + " modules ls --json"
        );
        if (!result.succeeded()) {
            return new ModuleReadResult(
                    Collections.emptyList(),
                    "module list unavailable"
            );
        }

        try {
            JSONObject response = new JSONObject(result.output);
            JSONArray modules = response.optJSONArray("data");
            if (modules == null) {
                return new ModuleReadResult(
                        Collections.emptyList(),
                        "invalid module response"
                );
            }

            List<ModuleRecord> moduleRecords = new ArrayList<>();
            for (int index = 0; index < modules.length(); index++) {
                JSONObject module = modules.optJSONObject(index);
                if (module == null) {
                    continue;
                }
                moduleRecords.add(
                        new ModuleRecord(
                                module.optString("PACKAGE", "unknown"),
                                module.optInt("UID", -1),
                                module.optString("STATUS", "unknown")
                        )
                );
            }
            return new ModuleReadResult(moduleRecords, "");
        } catch (Exception error) {
            return new ModuleReadResult(
                    Collections.emptyList(),
                    "invalid module response"
            );
        }
    }

    private static final class ModuleReadResult {
        final List<ModuleRecord> modules;
        final String error;

        ModuleReadResult(List<ModuleRecord> modules, String error) {
            this.modules = modules;
            this.error = error;
        }
    }
}
