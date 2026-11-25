package dev.dby2.rootkit;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;

final class ShellCommandRunner {
    private static final int DEFAULT_TIMEOUT_SECONDS = 8;

    CommandResult run(String command) {
        return run(command, DEFAULT_TIMEOUT_SECONDS);
    }

    CommandResult run(String command, int timeoutSeconds) {
        Process process = null;
        try {
            process = new ProcessBuilder("sh", "-c", command)
                    .redirectErrorStream(true)
                    .start();

            if (!process.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                process.destroyForcibly();
                return new CommandResult("command timed out", 124, true);
            }

            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(
                            process.getInputStream(),
                            StandardCharsets.UTF_8
                    ))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (output.length() > 0) {
                        output.append('\n');
                    }
                    output.append(line);
                }
            }

            String result = output.toString().trim();
            if (result.isEmpty()) {
                result = "no output";
            }
            return new CommandResult(result, process.exitValue(), false);
        } catch (Exception error) {
            return new CommandResult(
                    "command failed: " + error.getClass().getSimpleName(),
                    1,
                    false
            );
        } finally {
            if (process != null && process.isAlive()) {
                process.destroyForcibly();
            }
        }
    }

    CommandResult runRoot(String command) {
        String escapedCommand = escapeForSingleQuotes(command);
        CommandResult systemSuResult = run(
                "/system/bin/su -c '" + escapedCommand + "'"
        );
        if (systemSuResult.succeeded()) {
            return systemSuResult;
        }

        CommandResult pathSuResult = run(
                "su -c '" + escapedCommand + "'"
        );
        if (pathSuResult.succeeded()) {
            return pathSuResult;
        }
        return systemSuResult;
    }

    private String escapeForSingleQuotes(String command) {
        return command.replace("'", "'\\''");
    }
}

final class CommandResult {
    final String output;
    final int exitCode;
    final boolean timedOut;

    CommandResult(String output, int exitCode, boolean timedOut) {
        this.output = output;
        this.exitCode = exitCode;
        this.timedOut = timedOut;
    }

    boolean succeeded() {
        return exitCode == 0 && !timedOut;
    }

    String displayText() {
        return output.isEmpty() ? "no output" : output;
    }
}
