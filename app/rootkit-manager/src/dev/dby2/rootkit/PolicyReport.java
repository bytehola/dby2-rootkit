package dev.dby2.rootkit;

import java.util.List;

final class PolicyReport {
    final String bootHash;
    final String bootSessionState;
    final List<PolicyRecord> policies;
    final String error;

    PolicyReport(
            String bootHash,
            String bootSessionState,
            List<PolicyRecord> policies,
            String error
    ) {
        this.bootHash = bootHash;
        this.bootSessionState = bootSessionState;
        this.policies = policies;
        this.error = error;
    }
}
