# 快速开始

## 支持范围

```text
设备：DBY2-W00
系统：HarmonyOS 4.2.0.252(C00E100R3P5)
Android：12 / API 31
内核：5.4.86
```

其他设备或系统版本会被 profile 闸门拒绝。

## 检查 ADB

确保 `adb` 位于 `PATH`，或通过 `ADB` 环境变量指定可执行文件：

```bash
adb devices -l
```

设备状态必须为 `device`。

## 检查设备

```bash
./bin/dby2-rootctl doctor
```

未 Root 时 `root` 检查失败属于正常状态，设备 profile 检查必须通过。

## 查看状态

```bash
./bin/dby2-rootctl --json status
```

输出中的 `serial_hash` 和 `boot_id_hash` 用于诊断，不包含原始设备标识。

## 完整验证

```bash
./bin/dby2-rootctl verify --require-xposed
```

退出码：

```text
0   通过
5   设备 profile 不匹配
9   Root 或运行环境验收失败
```

## Vector 管理

```bash
./bin/dby2-rootctl --json xposed status
./bin/dby2-rootctl --json xposed modules
```

启用、禁用和作用域管理命令使用 `xposed modules` 返回的模块包名。

## 授权审计

```bash
./bin/dby2-rootctl --json policy list
./bin/dby2-rootctl --json policy session
```

## 诊断

```bash
./bin/dby2-rootctl logs --output dby2-diagnostics.zip
```

诊断包会脱敏设备序列号、boot_id、IPv4、MAC、用户主目录和 ADB 公钥。

## Windows 图形界面

用户发行版解压后运行 `DBY2-RootKit.exe`，连接平板并点击“一键 Root”。

流程：

1. 校验 DBY2-W00、系统版本、ABI 和内核。
2. 安装移植 Magisk。
3. 通过 ADB 启动 Magisk Root 前台服务。
4. 执行 Root payload 并取得 UID 0 broker。
5. 安装 RootKit、NyaZygisk 与 Vector。
6. 验收运行状态。
7. 显示 10 秒倒计时并软重启系统框架。

完整重启后临时 Root 会消失，重新连接 USB 并执行相同流程即可恢复。
