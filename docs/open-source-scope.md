# 开源范围

## 公开源码

- Windows 图形界面和 PC CLI。
- Android DBY2 RootKit 管理 App。
- DBY2 设备 profile、兼容性检查和状态采集。
- Magisk DBY2 移植。
- Vector 和 NyaZygisk 源码快照。
- DBY2 Root Engine 和 DirtyFrag 适配源码。
- 模块构建、测试、秘密扫描和 Release 脚本。

## 不进入仓库

- Huawei OTA base、CUST 和 PRELOAD 固件。
- 提取的 boot、system、vendor 和内核镜像。
- 私人 keystore、ADB 私钥和用户设备标识。
- 第三方 Xposed 模块 APK。
- 构建缓存、SDK、NDK、Rust 工具链和 Gradle 缓存。

## 发布规则

- Release 必须从干净的 Git 提交构建。
- 测试、秘密扫描和归档完整性检查必须通过。
- 每个二进制资产在 `release-manifest.json` 中记录 SHA-256。
- 第三方组件的来源和许可证记录在 `third-party/manifest.yaml`。
- 未在目标设备复测的新系统版本不得复用现有 profile。
