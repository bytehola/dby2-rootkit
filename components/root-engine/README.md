# DBY2 Root Engine

DBY2 Root Engine 是 DBY2-W00 专用的 GhostLock 临时 Root 实现。它由 `uid=2000`
的 ADB shell 启动，通过内核写原语建立 UID/GID 为 0 的 broker，并提供命令执行、
文件写入、挂载和交互式 root shell。

## 目标

```text
设备：DBY2-W00
Android：12 / API 31
内核：5.4.86-qgki
起始身份：uid=2000(shell)
SELinux：Enforcing
```

## 构建

构建依赖 Makefile、目标内核头文件 `src/target.h` 和 Android NDK。

```bash
make -C components/root-engine -j4 LOGCAT=0 NDK_ROOT="$ANDROID_NDK_HOME"
```

输出：

```text
components/root-engine/build/bin/ghostlock_exe
```

## 运行

设备必须已通过 ADB 连接，并完成 USB 调试授权。

```bash
ADB=adb SERIAL="$ADB_SERIAL" bash components/root-engine/dby2-root.sh
```

broker 就绪后可执行：

```bash
adb -s "$ADB_SERIAL" shell \
  /data/local/tmp/ghostlock_dby2 --rsh id
```

> 该组件会触发内核漏洞。失败可能导致设备 oops、panic 或重启，应仅在明确支持且可恢复的测试设备上运行。

## 工具链

Makefile 的默认编译参数：

```text
API=35
TARGET_HEADER=src/target.h
LOGCAT=1
OUTDIR=build/bin
```

可通过 `CC`、`NDK_ROOT`、`NDK_TOOLCHAIN`、`HOST_CLANG`、`SYSROOT` 和
`RESOURCE_DIR` 覆盖。`src/target.h` 必须与目标内核构建匹配。
