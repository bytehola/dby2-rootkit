# Android RootKit

`rootkit-manager/` 是 DBY2 RootKit 的设备端管理界面。

## 功能

- 显示设备、系统、内核、SELinux 和系统服务状态。
- 验证当前 boot 的 UID 0 Root。
- 显示并启停 Vector 模块。
- 查看、添加和移除模块作用域。
- 只读查看 Magisk Root 授权和 boot session。
- 请求系统框架软重启。

## 构建

```bash
JAVA_HOME="$JAVA_HOME" \
ANDROID_SDK_ROOT="$ANDROID_SDK_ROOT" \
./app/rootkit-manager/build.sh
```

输出：

```text
app/rootkit-manager/build/DBY2-RootKit-debug.apk
```

构建脚本使用 Android SDK Build Tools 直接生成 DEX、对齐并签名 APK，不依赖
Gradle。调试 keystore 只生成在被忽略的 `build/` 目录。

> `system/0` 作用域会影响系统框架，只应在理解影响范围后使用。
