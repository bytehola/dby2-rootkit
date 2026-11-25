<h1 align="center">DBY2 RootKit</h1>

<p align="center">面向 HUAWEI MatePad Air 11.5 2023（DBY2-W00）的临时 Root、Magisk 与 Xposed 一体化工具。</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0-3776AB?style=flat-square" alt="Version 2.0">
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square" alt="Python 3.10 or later">
  <img src="https://img.shields.io/badge/Android-12%20%2F%20API%2031-4B5563?style=flat-square" alt="Android 12 API 31">
  <img src="https://img.shields.io/badge/License-GPL--3.0--or--later-22C55E?style=flat-square" alt="GNU GPL version 3 or later">
</p>

单仓库包含电脑端、Android RootKit、Magisk、NyaZygisk、Vector、Root Engine 与 DirtyFrag 源码。

## 功能

- 通过 USB ADB 完成设备校验、临时 Root、组件安装和状态验收。
- 内置移植 Magisk，一键安装并激活 NyaZygisk 与 Vector。
- Root 完成后显示 10 秒倒计时并软重启系统框架。
- 支持 Vector 模块启停、作用域管理和 Magisk 授权审计。
- 支持脱敏诊断包，完整重启后可重新连接 USB 恢复 Root。

## 快速开始

Windows 用户发行版内置 ADB，解压后运行 `DBY2-RootKit.exe`，连接平板并点击“一键 Root”。

从源码启动图形界面：

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .\pc\dby2-rootctl
dby2-rootkit-gui
```

使用命令行：

```bash
./bin/dby2-rootctl doctor
./bin/dby2-rootctl status
./bin/dby2-rootctl verify --require-xposed
./bin/dby2-rootctl logs --output dby2-diagnostics.zip
```

`adb` 必须位于 `PATH`，或通过 `ADB` 环境变量指定。

## 支持范围

| 项目 | 值 |
|---|---|
| 设备 | `DBY2-W00` |
| 系统 | HarmonyOS `4.2.0.252(C00E100R3P5)` |
| Android | 12 / API 31 |
| ABI | `arm64-v8a` |
| 内核 | `5.4.86-qgki` |
| Xposed | Vector API 102 |

> 仅支持上述设备、系统、内核和 ABI。临时 Root 不修改系统分区，完整重启后失效。

## 构建

完整构建需要设置 `JAVA_HOME`、`ANDROID_SDK_ROOT`、`ANDROID_NDK_HOME`、`CARGO_HOME` 和 `RUSTUP_HOME`。

```bash
./scripts/build-components.sh
./scripts/test.sh
```

构建 Windows 发行包还需要 `WINDOWS_PYTHON`、`PLATFORM_TOOLS_DIRECTORY` 和 `wslpath`：

```bash
RELEASE_VERSION=2.0 \
OUTPUT_DIRECTORY=dist/user-release \
./scripts/build-user-release.sh
```

构建源码包：

```bash
RELEASE_VERSION=2.0 ./scripts/build-source-release.sh
```

> Root Engine 和 DirtyFrag 会触发内核路径，失败可能导致 oops、panic 或设备重启。

## 许可证

本项目原创源码基于 [GNU GPL v3.0 or later](./LICENSE) 发布；`components/` 中的第三方组件继续使用各自随源码附带的许可证。
