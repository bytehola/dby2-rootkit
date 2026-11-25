# Windows 一键安装与恢复 Root

本文只适用于：

```text
设备：HUAWEI MatePad Air 11.5 2023（DBY2-W00）
系统：HarmonyOS 4.2.0.252(C00E100R3P5)
Android：12 / API 31
内核：5.4.86
```

其他型号或系统版本会被程序拒绝。

## 1. 准备条件

- 完整解压 Windows 发行包，不能只复制 EXE。
- 使用支持数据传输的 USB 线。
- 平板能够正常进入桌面。
- Windows 已安装 Microsoft Edge WebView2 Runtime。

发行包已经包含 ADB、Magisk、NyaZygisk、Vector 和 RootKit 管理 App。
普通用户不需要安装 Python、Android SDK 或单独的 DirtyFrag App。

## 2. 开启 USB 调试

在平板设置中依次进入：

1. “关于手机”。
2. 连续点击“HarmonyOS 版本”7 次。
3. 返回“系统和更新”并打开“开发人员选项”。
4. 打开“USB 调试”。
5. 打开“仅充电模式下允许 ADB 调试”。
6. 用数据线连接电脑，并在弹窗选择“始终允许使用这台计算机进行调试”。

连接模式选择“传输文件”。如果 Windows 已识别平板但 ADB 列表为空，
通常是“仅充电模式下允许 ADB 调试”尚未开启，或 USB 调试授权需要重置。
撤销 USB 调试授权后重新插拔数据线。

## 3. 启动图形界面

解压后双击：

```text
DBY2-RootKit.exe
```

程序会自动启动包内 ADB。检测到设备后，界面显示设备型号、系统版本以及
当前 Root、Magisk、Zygisk、Vector 状态。

如果设备未连接，点击“图文步骤”查看 HarmonyOS 4.2 的实机截图。完成设置后
点击“重新检测”。

## 4. 执行一键 Root

点击界面中的“一键 Root”。电脑端会：

1. 校验设备型号和系统版本。
2. 安装移植版 Magisk。
3. 启用本机 ADB 通道。
4. 通过 ADB 启动 Magisk 内的 Root 前台服务。
5. App 进程执行 DirtyFrag 并取得 kernel broker。
6. 安装 NyaZygisk 与 Vector，启动 Zygisk 与 Vector。
7. 重新采集状态并验收。
8. 显示 10 秒倒计时弹窗，到期后软重启系统框架。

电脑连接模式不需要在平板上点击 Magisk 的“一键 Root”。如果设备尚未监听
本机 `5555` ADB 通道，程序会通过 `adb tcpip 5555` 建立临时通道，再通过
ADB 启动 Magisk Root 服务。保持 USB 数据线连接，等待程序显示 Root 环境
已启动，并在倒计时结束后等待平板恢复。

Magisk 首页的“一键 Root”按钮仍然保留，但只用于没有电脑、需要在设备上
独立执行提权的场景。

## 5. 安装 RootKit 并授权

电脑端检测到 Magisk 和扩展运行后，会安装并打开 DBY2 RootKit 管理 App。
首次打开时，Magisk 显示超级用户请求：

```text
DBY2 RootKit（dev.dby2.rootkit）正在申请超级用户权限。
```

点击“允许”后等待 10 秒软重启完成。平板恢复后回到电脑界面，点击“验证”。
完整通过时显示：

```text
Root：临时 Root 已激活
Magisk：31.1:MAGISK:D
Zygisk：已注入
Vector：canary-3119 / API 102
```

如果 Magisk 设置页显示“Zygisk 未启用”，不要只根据这一项判断失败。本方案
使用 NyaZygisk 宿主，以以下结果为准：

- `/data/adb/modules/zygisksu` 和 `/data/adb/modules/zygisk_vector` 存在。
- `zygiskd64` 正在运行。
- `/data/system_de/nyazygisk/module.prop` 中 `zygote_64_status=injected`。
- Vector CLI 返回 `"success": true`。

Vector 桌面入口直接显示管理器。发行版会关闭 HarmonyOS USAP 预加载池，
并在下次 boot 的 zygote 启动前应用，避免管理器进程绕过 Zygisk 注入。

## 6. 完整重启后恢复

完整重启会清除本次 boot 的 Root、Magisk daemon、Zygisk 和 Vector。
已安装的模块目录和 Magisk 授权记录会保留。

恢复步骤与首次安装相同：

1. 保持 USB 数据线连接。
2. 解锁平板并确认 USB 调试仍已开启。
3. 打开 `DBY2-RootKit.exe`。
4. 点击“一键 Root”。
5. 等待电脑端通过 ADB 完成提权和运行环境恢复。
6. 点击“验证”确认本次 boot 的完整状态。

程序使用当前 USB ADB 连接，不依赖重启前残留的 `5555` 端口。

## 7. 导出诊断

设备连接正常时点击“诊断”，保存 ZIP 文件。诊断包会自动脱敏：

- 设备序列号。
- boot_id。
- IPv4 地址。
- MAC 地址。
- 用户主目录。
- ADB 公钥。

反馈问题时提供发行版本、发生步骤、界面文字和诊断包，不要公开原始设备
序列号或私人 ADB 文件。

## 8. 常见问题

### 没有检测到平板

检查 USB 数据线、“USB 调试”和“仅充电模式下允许 ADB 调试”三个条件。
设备状态为 `unauthorized` 时，解锁平板并接受 USB 调试授权。ADB 列表完全
为空时，系统通常还没有暴露 ADB 调试接口，不是授权弹窗丢失。

### Magisk 首页“一键 Root”的用途

确认安装的是发行包内的 `runtime/magisk/DBY2-Magisk-OneTap.apk`，不是官方
Magisk。该按钮用于脱离电脑的场景；连接电脑时应直接运行桌面程序。

### 点击后一直等待

保持平板解锁和 USB 数据线连接。首次使用只需在系统弹出的本机 ADB 调试框
中点击允许；之后程序会直接启动 Magisk Root 服务，不需要打开 Magisk 页面。

### Zygisk 或 Vector 失败

先点击“诊断”。如果系统仍可正常使用，可以再次点击“一键 Root”重试一次；
如果 App 大面积闪退或桌面卡死，完整重启后重新执行恢复流程。

### 关闭程序后是否残留 ADB

程序关闭窗口时会主动执行 `adb kill-server`。如果 Windows 任务管理器仍显示
残留进程，关闭旧窗口后重新启动发行包。

## 9. 开发者 CLI

用户流程不要求命令行。维护者可以在已取得 UID 0 broker 后执行只读验收：

```bash
./bin/dby2-rootctl verify --require-xposed
```

图形界面调用 CLI 时始终带 `--require-existing-root`，不会回退到发行包外的
Root engine。
