# Runtime

运行时目录负责连接源码构建结果和用户发行包。

| 目录 | 内容 |
|---|---|
| `magisk/` | 组件构建生成的移植 Magisk APK |
| `modules/build/` | NyaZygisk 与 Vector 模块 ZIP |
| `root-engine/` | PC CLI 兼容的 Root Engine 入口 |

组件源码位于仓库根目录的 `components/`。构建缓存和二进制输出由 `.gitignore`
排除，发行时由 `scripts/build-user-release.sh` 收集。

PC CLI 通过以下环境变量调用兼容入口：

```text
ADB
SERIAL
DBY2_PROFILE_ID
DBY2_RUNTIME_ENGINE
```

未指定 `DBY2_RUNTIME_ENGINE` 时使用：

```text
components/root-engine/dby2-root.sh
```
