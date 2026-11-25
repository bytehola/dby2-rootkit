package dev.dby2.rootkit;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.view.Gravity;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;

public final class MainActivity extends Activity {
    private static final int PAGE_PADDING_DP = 24;
    private static final int SECTION_GAP_DP = 16;

    private TextView statusView;
    private TextView detailsView;
    private TextView runtimeView;
    private TextView policyView;
    private LinearLayout moduleContainer;
    private Button refreshButton;
    private Button verifyButton;
    private Button runtimeButton;
    private Button softRebootButton;
    private Button policyButton;
    private final List<CheckBox> moduleControls = new ArrayList<>();
    private final List<Button> moduleScopeButtons = new ArrayList<>();

    private final ShellCommandRunner commandRunner = new ShellCommandRunner();
    private final RuntimeInspector runtimeInspector =
            new RuntimeInspector(commandRunner);
    private final PolicyInspector policyInspector =
            new PolicyInspector(commandRunner);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(createPage());
        refreshStatus();
    }

    private LinearLayout createPage() {
        LinearLayout page = new LinearLayout(this);
        page.setOrientation(LinearLayout.VERTICAL);
        page.setGravity(Gravity.START);
        page.setPadding(
                dp(PAGE_PADDING_DP),
                dp(PAGE_PADDING_DP),
                dp(PAGE_PADDING_DP),
                dp(SECTION_GAP_DP)
        );
        page.setBackgroundColor(Color.rgb(245, 247, 249));

        TextView title = new TextView(this);
        title.setText("DBY2 RootKit");
        title.setTextSize(26);
        title.setTextColor(Color.rgb(24, 28, 32));
        page.addView(title);

        statusView = new TextView(this);
        statusView.setText("正在检查运行状态");
        statusView.setTextSize(17);
        statusView.setTextColor(Color.rgb(68, 76, 84));
        statusView.setPadding(0, dp(10), 0, dp(SECTION_GAP_DP));
        page.addView(statusView);

        ScrollView scrollView = new ScrollView(this);
        scrollView.setFillViewport(true);

        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setGravity(Gravity.START);
        scrollView.addView(content);

        detailsView = new TextView(this);
        detailsView.setText("读取设备信息...");
        detailsView.setTextSize(14);
        detailsView.setTextColor(Color.rgb(48, 56, 64));
        detailsView.setTypeface(Typeface.MONOSPACE);
        detailsView.setTextIsSelectable(true);
        detailsView.setLineSpacing(0, 1.18f);
        content.addView(detailsView);

        TextView runtimeTitle = new TextView(this);
        runtimeTitle.setText("Xposed 运行时");
        runtimeTitle.setTextSize(17);
        runtimeTitle.setTextColor(Color.rgb(24, 28, 32));
        runtimeTitle.setPadding(0, dp(24), 0, dp(8));
        content.addView(runtimeTitle);

        runtimeView = new TextView(this);
        runtimeView.setText("尚未读取运行时状态");
        runtimeView.setTextSize(14);
        runtimeView.setTextColor(Color.rgb(48, 56, 64));
        runtimeView.setTypeface(Typeface.MONOSPACE);
        runtimeView.setTextIsSelectable(true);
        runtimeView.setLineSpacing(0, 1.18f);
        content.addView(runtimeView);

        TextView moduleTitle = new TextView(this);
        moduleTitle.setText("模块");
        moduleTitle.setTextSize(16);
        moduleTitle.setTextColor(Color.rgb(24, 28, 32));
        moduleTitle.setPadding(0, dp(18), 0, dp(8));
        content.addView(moduleTitle);

        moduleContainer = new LinearLayout(this);
        moduleContainer.setOrientation(LinearLayout.VERTICAL);
        content.addView(moduleContainer);

        TextView policyTitle = new TextView(this);
        policyTitle.setText("Root 授权");
        policyTitle.setTextSize(16);
        policyTitle.setTextColor(Color.rgb(24, 28, 32));
        policyTitle.setPadding(0, dp(18), 0, dp(8));
        content.addView(policyTitle);

        policyView = new TextView(this);
        policyView.setText("尚未读取授权状态");
        policyView.setTextSize(13);
        policyView.setTextColor(Color.rgb(48, 56, 64));
        policyView.setTypeface(Typeface.MONOSPACE);
        policyView.setTextIsSelectable(true);
        policyView.setLineSpacing(0, 1.12f);
        content.addView(policyView);

        policyButton = new Button(this);
        policyButton.setText("读取授权");
        policyButton.setOnClickListener(view -> inspectPolicies());
        content.addView(policyButton);

        page.addView(
                scrollView,
                new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.MATCH_PARENT,
                        0,
                        1.0f
                )
        );

        LinearLayout actions = new LinearLayout(this);
        actions.setOrientation(LinearLayout.HORIZONTAL);
        actions.setGravity(Gravity.START);
        actions.setPadding(0, dp(SECTION_GAP_DP), 0, 0);

        refreshButton = new Button(this);
        refreshButton.setText("刷新状态");
        refreshButton.setOnClickListener(view -> refreshStatus());
        actions.addView(
                refreshButton,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f)
        );

        verifyButton = new Button(this);
        verifyButton.setText("验证 Root");
        verifyButton.setOnClickListener(view -> verifyRoot());
        actions.addView(
                verifyButton,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f)
        );

        runtimeButton = new Button(this);
        runtimeButton.setText("Xposed");
        runtimeButton.setOnClickListener(view -> inspectRuntime());
        actions.addView(
                runtimeButton,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f)
        );

        softRebootButton = new Button(this);
        softRebootButton.setText("软重启");
        softRebootButton.setOnClickListener(view -> confirmSoftReboot());
        actions.addView(
                softRebootButton,
                new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.0f)
        );

        page.addView(actions);
        return page;
    }

    private void refreshStatus() {
        setButtonsEnabled(false);
        statusView.setText("正在检查运行状态");

        new Thread(() -> {
            String report = collectStatusReport();
            boolean rooted = report.contains("root: uid=0(root)");
            runOnUiThread(() -> {
                statusView.setText(rooted ? "临时 Root 已激活" : "临时 Root 未激活");
                statusView.setTextColor(
                        rooted
                                ? Color.rgb(24, 122, 72)
                                : Color.rgb(176, 48, 48)
                );
                detailsView.setText(report);
                setButtonsEnabled(true);
            });
        }, "dby2-status").start();
    }

    private void verifyRoot() {
        setButtonsEnabled(false);
        statusView.setText("正在验证 Root");

        new Thread(() -> {
            String verification = runRootCommand(
                    "id; getenforce; pidof system_server; pidof surfaceflinger"
            );
            boolean rooted = verification.contains("uid=0(root)");
            runOnUiThread(() -> {
                statusView.setText(rooted ? "Root 验证成功" : "Root 验证失败");
                statusView.setTextColor(
                        rooted
                                ? Color.rgb(24, 122, 72)
                                : Color.rgb(176, 48, 48)
                );
                detailsView.setText(verification);
                setButtonsEnabled(true);
            });
        }, "dby2-root-verification").start();
    }

    private void confirmSoftReboot() {
        new AlertDialog.Builder(this)
                .setTitle("软重启系统框架")
                .setMessage(
                        "平板会短暂黑屏，所有应用界面将重新加载。"
                                + "本次临时 Root 会保留，是否继续？"
                )
                .setPositiveButton("软重启", (ignoredDialog, which) ->
                        softRebootFramework())
                .setNegativeButton("取消", null)
                .show();
    }

    private void softRebootFramework() {
        setButtonsEnabled(false);
        statusView.setText("正在安排软重启");
        statusView.setTextColor(Color.rgb(68, 76, 84));

        new Thread(() -> {
            String rootIdentity = runRootCommand("id");
            if (!rootIdentity.contains("uid=0(root)")) {
                runOnUiThread(() -> {
                    statusView.setText("临时 Root 未激活");
                    statusView.setTextColor(Color.rgb(176, 48, 48));
                    Toast.makeText(
                            this,
                            "无法软重启：临时 Root 未激活",
                            Toast.LENGTH_LONG
                    ).show();
                    setButtonsEnabled(true);
                });
                return;
            }

            CommandResult result = commandRunner.runRoot(
                    "(sleep 2; setprop ctl.restart zygote) >/dev/null 2>&1 &"
            );
            runOnUiThread(() -> {
                setButtonsEnabled(true);
                if (!result.succeeded()) {
                    statusView.setText("软重启安排失败");
                    statusView.setTextColor(Color.rgb(176, 48, 48));
                    Toast.makeText(
                            this,
                            "软重启失败: " + result.displayText(),
                            Toast.LENGTH_LONG
                    ).show();
                    return;
                }
                statusView.setText("系统框架将在 2 秒后软重启");
                statusView.setTextColor(Color.rgb(166, 106, 22));
                Toast.makeText(
                        this,
                        "系统框架将在 2 秒后软重启",
                        Toast.LENGTH_LONG
                ).show();
            });
        }, "dby2-soft-reboot").start();
    }

    private void inspectRuntime() {
        setButtonsEnabled(false);
        runtimeView.setText("正在读取运行时状态");
        moduleContainer.removeAllViews();
        moduleControls.clear();
        moduleScopeButtons.clear();

        new Thread(() -> {
            RuntimeReport runtimeReport = runtimeInspector.inspect();
            runOnUiThread(() -> {
                runtimeView.setText(runtimeReport.summary);
                renderModules(runtimeReport);
                setButtonsEnabled(true);
            });
        }, "dby2-runtime-inspection").start();
    }

    private void inspectPolicies() {
        setButtonsEnabled(false);
        policyView.setText("正在读取授权状态");

        new Thread(() -> {
            PolicyReport policyReport = policyInspector.collectReport();
            runOnUiThread(() -> {
                if (!policyReport.error.isEmpty()) {
                    policyView.setText(policyReport.error);
                    setButtonsEnabled(true);
                    return;
                }

                StringBuilder report = new StringBuilder(
                        "boot hash: " + policyReport.bootHash + "\n"
                                + "boot session: " + policyReport.bootSessionState + "\n"
                );
                for (PolicyRecord policy : policyReport.policies) {
                    report.append("\n")
                            .append(policy.uid)
                            .append("  ")
                            .append(policy.decision)
                            .append("  until=")
                            .append(policy.until)
                            .append("\n  ")
                            .append(String.join(", ", policy.packages))
                            .append("\n");
                }
                policyView.setText(report.toString().trim());
                setButtonsEnabled(true);
            });
        }, "dby2-policy-inspection").start();
    }

    private void renderModules(RuntimeReport runtimeReport) {
        moduleContainer.removeAllViews();
        moduleControls.clear();
        moduleScopeButtons.clear();

        if (!runtimeReport.moduleError.isEmpty()) {
            TextView errorView = new TextView(this);
            errorView.setText(runtimeReport.moduleError);
            errorView.setTextSize(13);
            errorView.setTextColor(Color.rgb(176, 48, 48));
            moduleContainer.addView(errorView);
            return;
        }

        if (runtimeReport.modules.isEmpty()) {
            TextView emptyView = new TextView(this);
            emptyView.setText("无模块");
            emptyView.setTextSize(13);
            emptyView.setTextColor(Color.rgb(68, 76, 84));
            moduleContainer.addView(emptyView);
            return;
        }

        for (ModuleRecord module : runtimeReport.modules) {
            moduleContainer.addView(createModuleRow(module));
        }
    }

    private LinearLayout createModuleRow(ModuleRecord module) {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        row.setPadding(0, dp(6), 0, dp(6));

        TextView label = new TextView(this);
        label.setText(
                module.packageName + "\nUID " + module.uid + " · " + module.status
        );
        label.setTextSize(13);
        label.setTextColor(Color.rgb(48, 56, 64));
        label.setTypeface(Typeface.MONOSPACE);
        label.setTextIsSelectable(true);
        row.addView(
                label,
                new LinearLayout.LayoutParams(
                        0,
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        1.0f
                )
        );

        CheckBox toggle = new CheckBox(this);
        toggle.setChecked(module.isEnabled());
        toggle.setContentDescription(
                module.isEnabled() ? "禁用 " + module.packageName : "启用 " + module.packageName
        );
        bindModuleToggle(toggle, module);
        row.addView(
                toggle,
                new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                )
        );

        Button scopeButton = new Button(this);
        scopeButton.setText("作用域");
        scopeButton.setTextSize(12);
        scopeButton.setMinWidth(0);
        scopeButton.setMinimumWidth(0);
        scopeButton.setContentDescription("编辑 " + module.packageName + " 作用域");
        scopeButton.setOnClickListener(view -> showModuleScopes(module));
        row.addView(
                scopeButton,
                new LinearLayout.LayoutParams(
                        ViewGroup.LayoutParams.WRAP_CONTENT,
                        ViewGroup.LayoutParams.WRAP_CONTENT
                )
        );
        moduleControls.add(toggle);
        moduleScopeButtons.add(scopeButton);
        return row;
    }

    private void showModuleScopes(ModuleRecord module) {
        setButtonsEnabled(false);

        new Thread(() -> {
            ModuleScopeReport scopeReport = runtimeInspector.readModuleScopes(
                    module.packageName
            );
            runOnUiThread(() -> {
                setButtonsEnabled(true);
                if (!scopeReport.error.isEmpty()) {
                    Toast.makeText(
                            this,
                            "读取作用域失败: " + scopeReport.error,
                            Toast.LENGTH_LONG
                    ).show();
                    return;
                }
                showScopeDialog(module, scopeReport);
            });
        }, "dby2-scope-read").start();
    }

    private void showScopeDialog(ModuleRecord module, ModuleScopeReport scopeReport) {
        StringBuilder scopeText = new StringBuilder("当前作用域:\n");
        if (scopeReport.scopes.isEmpty()) {
            scopeText.append("无");
        } else {
            for (String scope : scopeReport.scopes) {
                scopeText.append("- ").append(scope).append('\n');
            }
        }
        scopeText.append("\n目标包名可写 pkg 或 pkg/user_id。");
        scopeText.append("\nsystem/0 会影响系统框架。");

        EditText targetInput = new EditText(this);
        targetInput.setHint("com.android.gpstest.osmdroid");
        targetInput.setSingleLine(true);
        targetInput.setTextSize(14);

        LinearLayout dialogContent = new LinearLayout(this);
        dialogContent.setOrientation(LinearLayout.VERTICAL);
        dialogContent.setPadding(dp(20), dp(8), dp(20), 0);

        TextView scopeView = new TextView(this);
        scopeView.setText(scopeText.toString());
        scopeView.setTextSize(13);
        scopeView.setTextColor(Color.rgb(48, 56, 64));
        scopeView.setTypeface(Typeface.MONOSPACE);
        scopeView.setTextIsSelectable(true);
        scopeView.setLineSpacing(0, 1.12f);
        dialogContent.addView(scopeView);
        dialogContent.addView(targetInput);

        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(module.packageName)
                .setView(dialogContent)
                .setPositiveButton("添加", null)
                .setNeutralButton("移除", null)
                .setNegativeButton("关闭", null)
                .create();
        dialog.setOnShowListener(ignored -> {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(view -> {
                String target = targetInput.getText().toString().trim();
                if (!isValidScopeTarget(target)) {
                    Toast.makeText(
                            this,
                            "目标包名格式无效",
                            Toast.LENGTH_SHORT
                    ).show();
                    return;
                }
                dialog.dismiss();
                updateModuleScope(module, target, true);
            });
            dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(view -> {
                String target = targetInput.getText().toString().trim();
                if (!isValidScopeTarget(target)) {
                    Toast.makeText(
                            this,
                            "目标包名格式无效",
                            Toast.LENGTH_SHORT
                    ).show();
                    return;
                }
                dialog.dismiss();
                updateModuleScope(module, target, false);
            });
        });
        dialog.show();
    }

    private boolean isValidScopeTarget(String target) {
        return target.matches("[A-Za-z0-9._]+(?:/[0-9]+)?");
    }

    private void updateModuleScope(
            ModuleRecord module,
            String target,
            boolean addScope
    ) {
        String action = addScope ? "添加" : "移除";
        new Thread(() -> {
            CommandResult result = addScope
                    ? runtimeInspector.addModuleScope(module.packageName, target)
                    : runtimeInspector.removeModuleScope(module.packageName, target);
            runOnUiThread(() -> {
                if (result.succeeded()) {
                    Toast.makeText(
                            this,
                            action + "作用域成功",
                            Toast.LENGTH_SHORT
                    ).show();
                    showModuleScopes(module);
                } else {
                    Toast.makeText(
                            this,
                            action + "作用域失败: " + result.displayText(),
                            Toast.LENGTH_LONG
                    ).show();
                }
            });
        }, "dby2-scope-update").start();
    }

    private void showModuleChangeConfirmation(
            ModuleRecord module,
            boolean enabled,
            CompoundButton toggle
    ) {
        String action = enabled ? "启用" : "禁用";
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle(action + "模块")
                .setMessage(
                        module.packageName
                                + "\n\n模块变更在目标应用重启后生效。"
                                + "系统级模块可能需要重启系统服务或整机。"
                )
                .setPositiveButton("继续", (ignoredDialog, which) ->
                        updateModuleEnabled(module, enabled))
                .setNegativeButton("取消", (ignoredDialog, which) -> {
                    toggle.setOnCheckedChangeListener(null);
                    toggle.setChecked(!enabled);
                    toggle.setEnabled(true);
                    bindModuleToggle(toggle, module);
                })
                .setOnCancelListener(ignoredDialog -> {
                    toggle.setOnCheckedChangeListener(null);
                    toggle.setChecked(!enabled);
                    toggle.setEnabled(true);
                    bindModuleToggle(toggle, module);
                })
                .create();
        dialog.show();
    }

    private void bindModuleToggle(CompoundButton toggle, ModuleRecord module) {
        toggle.setOnCheckedChangeListener((button, enabled) -> {
            button.setEnabled(false);
            showModuleChangeConfirmation(module, enabled, button);
        });
    }

    private void updateModuleEnabled(ModuleRecord module, boolean enabled) {
        String action = enabled ? "启用" : "禁用";
        Toast.makeText(this, "正在" + action + " " + module.packageName, Toast.LENGTH_SHORT)
                .show();

        new Thread(() -> {
            CommandResult result = runtimeInspector.setModuleEnabled(
                    module.packageName,
                    enabled
            );
            runOnUiThread(() -> {
                if (result.succeeded()) {
                    Toast.makeText(
                            this,
                            action + "成功，正在刷新模块状态",
                            Toast.LENGTH_SHORT
                    ).show();
                } else {
                    Toast.makeText(
                            this,
                            action + "失败: " + result.displayText(),
                            Toast.LENGTH_LONG
                    ).show();
                }
                inspectRuntime();
            });
        }, "dby2-module-update").start();
    }

    private String collectStatusReport() {
        return String.join(
                "\n",
                "model: " + readProperty("ro.product.model"),
                "android: " + readProperty("ro.build.version.release"),
                "sdk: " + readProperty("ro.build.version.sdk"),
                "build: " + readProperty("ro.build.display.id"),
                "kernel: " + runCommand("uname -r"),
                "selinux: " + runCommand("getenforce"),
                "system_server: " + runRootCommand("pidof system_server"),
                "surfaceflinger: " + runRootCommand("pidof surfaceflinger"),
                "root: " + runRootCommand("id")
        );
    }

    private String readProperty(String propertyName) {
        return runCommand("getprop " + propertyName);
    }

    private String runRootCommand(String command) {
        return commandRunner.runRoot(command).displayText();
    }

    private String runCommand(String command) {
        return commandRunner.run(command).displayText();
    }

    private void setButtonsEnabled(boolean enabled) {
        refreshButton.setEnabled(enabled);
        verifyButton.setEnabled(enabled);
        runtimeButton.setEnabled(enabled);
        softRebootButton.setEnabled(enabled);
        policyButton.setEnabled(enabled);
        for (CheckBox toggle : moduleControls) {
            toggle.setEnabled(enabled);
        }
        for (Button scopeButton : moduleScopeButtons) {
            scopeButton.setEnabled(enabled);
        }
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }
}
