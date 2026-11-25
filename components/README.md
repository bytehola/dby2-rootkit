# Vendored Components

本目录以源码快照方式集成 DBY2 RootKit 依赖的五个组件：

| 目录 | 组件 | 用途 |
|---|---|---|
| `magisk/` | Magisk | 超级用户策略、模块运行时和一键 Root 入口 |
| `vector/` | Vector | Zygisk 上的 Xposed 运行时与管理器 |
| `nyazygisk/` | NyaZygisk | Zygisk 注入宿主 |
| `root-engine/` | DBY2 Root Engine | GhostLock 临时 Root broker |
| `dirtyfrag/` | DBY2 DirtyFrag | 页面缓存写入原语和模块加载链 |

每个组件保留自身的构建文件、许可证和来源说明。组件源码导入时已展开 Git
submodule 内容，仓库不依赖递归 submodule 初始化。

版本来源：

```text
Magisk     a3258d6b9a713d4c3ef7e9db0127a8561088e6a5
Vector     3b03c21ebd4cace8212e28afb87f193babf63b2a
NyaZygisk  ce72ac8f566bc292f0e92dc69ff1dfbd27cd7570
```

Root Engine 和 DirtyFrag 为本地 DBY2 适配源码，来源记录分别位于各目录的
`UPSTREAM.md`。
