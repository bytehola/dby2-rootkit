# DBY2 RootKit 2.1

发布日期：2026-11-26

## 支持范围

```text
设备：HUAWEI MatePad Air 11.5 2023（DBY2-W00）
系统：HarmonyOS 4.2.0.252(C00E100R3P5)
Android：12 / API 31
内核：5.4.86-qgki
```

## 主要更新

- Magisk、NyaZygisk、Vector、Root Engine、DirtyFrag 和 DBY2 RootKit 均从仓库源码构建。
- 修复 Magisk 构建配置路径，native 与安装脚本统一为 `31.1/31100`，避免 APP 误报“需要修复运行环境”。
- PC 一键 Root 等待官方 OneTap 服务完整退出后再执行最终验收，避免重复安装和 daemon 版本冲突。
- OneTap 等待上限调整为 150 秒；超时后卸载 Magisk、Vector Manager、DBY2 RootKit，并通过 ADB 重启平板。
- 首次 PC Root 成功后持久化 `persist.adb.tcp.port=5555`，并回读确认，供后续完整重启后的平板端一键 Root 使用。
- DBY2 RootKit APP 升级为 `2.1`，版本码 `21`。

## 验证

- Python 单元测试通过。
- Root Engine、DirtyFrag、NyaZygisk、Vector、Magisk 和 RootKit APK 构建通过。
- Magisk native 与 `util_functions.sh` 版本信息一致。
- Windows 用户发行包通过 ZIP 完整性和 SHA-256 检查。

## 已知限制

- 临时 Root 不跨完整重启保留。
- 仅支持上述设备、系统、内核和 ABI。
- 第三方 Xposed 模块不在发行包内。
