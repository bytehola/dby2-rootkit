package dev.dby2.rootkit;

import java.util.List;

final class RuntimeReport {
    final String summary;
    final List<ModuleRecord> modules;
    final String moduleError;

    RuntimeReport(
            String summary,
            List<ModuleRecord> modules,
            String moduleError
    ) {
        this.summary = summary;
        this.modules = modules;
        this.moduleError = moduleError;
    }
}
