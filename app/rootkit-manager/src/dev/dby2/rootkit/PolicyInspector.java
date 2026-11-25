package dev.dby2.rootkit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

final class PolicyInspector {
    private static final String POLICY_QUERY =
            "/system/bin/magisk --sqlite "
                    + "'select uid,policy,until,logging,notification "
                    + "from policies order by uid'";

    private final ShellCommandRunner commandRunner;

    PolicyInspector(ShellCommandRunner commandRunner) {
        this.commandRunner = commandRunner;
    }

    PolicyReport collectReport() {
        CommandResult bootResult = commandRunner.runRoot(
                "cat /proc/sys/kernel/random/boot_id"
        );
        CommandResult bootMarkerResult = commandRunner.runRoot(
                "if [ -f /data/adb/dby2/boot_id ]; "
                        + "then cat /data/adb/dby2/boot_id; "
                        + "else echo __missing__; fi"
        );
        CommandResult policyResult = commandRunner.runRoot(POLICY_QUERY);
        CommandResult packageResult = commandRunner.runRoot(
                "cmd package list packages -U"
        );

        if (!bootResult.succeeded() ||
            !bootMarkerResult.succeeded() ||
            !policyResult.succeeded() ||
            !packageResult.succeeded()) {
            return new PolicyReport("", "", Collections.emptyList(), "授权读取失败");
        }

        Map<Integer, List<String>> packagesByUid = parsePackageMap(
                packageResult.output
        );
        List<PolicyRecord> policies = new ArrayList<>();
        for (String line : policyResult.output.split("\n")) {
            PolicyRecord record = parsePolicyLine(line, packagesByUid);
            if (record != null) {
                policies.add(record);
            }
        }

        String currentBootId = bootResult.output.trim();
        String markerBootId = bootMarkerResult.output.trim();
        if ("__missing__".equals(markerBootId)) {
            markerBootId = "";
        }
        String bootSessionState;
        if (markerBootId.isEmpty()) {
            bootSessionState = "unmarked";
        } else if (currentBootId.equals(markerBootId)) {
            bootSessionState = "same-boot";
        } else {
            bootSessionState = "new-boot";
        }

        return new PolicyReport(
                shortHash(currentBootId),
                bootSessionState,
                policies,
                ""
        );
    }

    private Map<Integer, List<String>> parsePackageMap(String rawOutput) {
        Map<Integer, List<String>> packagesByUid = new HashMap<>();
        for (String line : rawOutput.split("\n")) {
            String trimmed = line.trim();
            if (!trimmed.startsWith("package:") || !trimmed.contains(" uid:")) {
                continue;
            }
            String packageName = trimmed.substring(
                    "package:".length(),
                    trimmed.indexOf(" uid:")
            );
            String uidText = trimmed.substring(trimmed.indexOf(" uid:") + 5);
            try {
                int uid = Integer.parseInt(uidText.trim());
                packagesByUid
                        .computeIfAbsent(uid, ignored -> new ArrayList<>())
                        .add(packageName);
            } catch (NumberFormatException ignored) {
                // Ignore malformed package manager rows.
            }
        }
        return packagesByUid;
    }

    private PolicyRecord parsePolicyLine(
            String line,
            Map<Integer, List<String>> packagesByUid
    ) {
        try {
            int uid = -1;
            int policy = -1;
            long until = 0;
            for (String field : line.trim().split("\\|")) {
                String[] parts = field.split("=", 2);
                if (parts.length != 2) {
                    continue;
                }
                switch (parts[0]) {
                    case "uid":
                        uid = Integer.parseInt(parts[1]);
                        break;
                    case "policy":
                        policy = Integer.parseInt(parts[1]);
                        break;
                    case "until":
                        until = Long.parseLong(parts[1]);
                        break;
                    default:
                        break;
                }
            }
            if (uid < 0 || policy < 0) {
                return null;
            }

            List<String> packages = packagesByUid.get(uid);
            if (packages == null) {
                packages = Collections.singletonList("unmapped");
            }
            return new PolicyRecord(uid, policyName(policy), until, packages);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }

    private String policyName(int policy) {
        switch (policy) {
            case 0:
                return "query";
            case 1:
                return "deny";
            case 2:
                return "allow";
            case 3:
                return "restrict";
            default:
                return "unknown-" + policy;
        }
    }

    private String shortHash(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (int index = 0; index < 6; index++) {
                hex.append(String.format("%02x", hash[index]));
            }
            return hex.toString();
        } catch (Exception ignored) {
            return "unknown";
        }
    }
}
