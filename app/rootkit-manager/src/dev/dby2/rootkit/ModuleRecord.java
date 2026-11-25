package dev.dby2.rootkit;

final class ModuleRecord {
    final String packageName;
    final int uid;
    final String status;

    ModuleRecord(String packageName, int uid, String status) {
        this.packageName = packageName;
        this.uid = uid;
        this.status = status;
    }

    boolean isEnabled() {
        return "enabled".equalsIgnoreCase(status);
    }
}
