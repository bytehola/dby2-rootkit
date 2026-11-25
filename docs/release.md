# 发布流程

## 版本

当前发行版本为 `2.1`。

## 源码发行包

```bash
RELEASE_VERSION=2.1 ./scripts/build-source-release.sh
```

输出：

```text
dist/DBY2-RootKit-2.1-source.tar.gz
dist/DBY2-RootKit-2.1-source.tar.gz.sha256
```

源码发行脚本要求 Git 工作区干净。

## Windows 用户发行包

需要预先设置：

```text
JAVA_HOME
ANDROID_SDK_ROOT 或 ANDROID_HOME
ANDROID_NDK_HOME 或 ANDROID_NDK_ROOT
CARGO_HOME
RUSTUP_HOME
WINDOWS_PYTHON
PLATFORM_TOOLS_DIRECTORY
```

构建：

```bash
RELEASE_VERSION=2.1 \
OUTPUT_DIRECTORY=dist/user-release \
./scripts/build-user-release.sh
```

输出：

```text
dist/user-release/DBY2-RootKit-User-2.1-win64.zip
dist/user-release/DBY2-RootKit-User-2.1-win64.zip.sha256
```

发行包包含：

- Windows WebView 程序。
- Android Platform Tools。
- DBY2 Magisk APK。
- DBY2 RootKit APK。
- NyaZygisk 与 Vector 模块。
- GhostLock Root Engine。
- 设备 profile、许可证和第三方说明。

## 发布检查

- `./scripts/test.sh` 通过。
- `./scripts/check-secrets.sh` 通过。
- 源码和 Windows 归档的 SHA-256 已生成。
- `release-manifest.json` 中的资产哈希与实际文件一致。
- Git 工作区干净，发布提交已创建 `v2.1` 标签。
