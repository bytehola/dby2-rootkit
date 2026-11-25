# DBY2 RootKit 2.0

发布日期：2026-11-25

## 支持范围

```text
设备：HUAWEI MatePad Air 11.5 2023（DBY2-W00）
系统：HarmonyOS 4.2.0.252(C00E100R3P5)
Android：12 / API 31
内核：5.4.86-qgki
```

## 主要更新

- 单仓库集成 PC、Android RootKit、Magisk、Vector、NyaZygisk、Root Engine 和 DirtyFrag。
- 新增 `scripts/build-components.sh`，从 vendored 源码构建全部组件。
- PC 一键 Root 在授权提示后执行 10 秒倒计时并软重启系统框架。
- Magisk 重启菜单和 DBY2 RootKit 增加手动软重启。
- 统一版本为 2.0。
- 重建 Git 历史为单一提交。

## 验证

- Python 单元测试通过。
- Root Engine、DirtyFrag、NyaZygisk、Vector、Magisk 和 RootKit APK 构建通过。
- Windows 用户发行包通过 ZIP 完整性和 SHA-256 检查。

## 已知限制

- 临时 Root 不跨完整重启保留。
- 仅支持上述设备、系统、内核和 ABI。
- 新系统版本必须重新建立 profile 并完成真机回归。
- 第三方 Xposed 模块不在发行包内。
