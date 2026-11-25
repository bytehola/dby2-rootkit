package dev.dby2.rootkit;

import java.util.List;

final class ModuleScopeReport {
    final List<String> scopes;
    final String error;

    ModuleScopeReport(List<String> scopes, String error) {
        this.scopes = scopes;
        this.error = error;
    }
}
