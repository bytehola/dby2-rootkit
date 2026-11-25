package dev.dby2.rootkit;

import java.util.List;

final class PolicyRecord {
    final int uid;
    final String decision;
    final long until;
    final List<String> packages;

    PolicyRecord(int uid, String decision, long until, List<String> packages) {
        this.uid = uid;
        this.decision = decision;
        this.until = until;
        this.packages = packages;
    }
}
