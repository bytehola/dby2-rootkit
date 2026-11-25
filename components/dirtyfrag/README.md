# DBY2 DirtyFrag

该组件保存 DBY2-W00 使用的 DirtyFrag 页面缓存写入原语、内核模块、root broker
脚本和最小 Android 触发壳。主安装流程将该实现编译为
`libdirtyfrag.so`，并随移植 Magisk APK 分发。

## 组成

```text
apk-harness/      最小 Android 触发应用
module/           可选内核模块源码
native/           libdfroot、stage2、loader 和 broker 客户端
src/              XFRM 页面缓存写入探针
```

## 构建原生组件

```bash
make -C components/dirtyfrag/native \
  NDK_ROOT="$ANDROID_NDK_HOME"
```

输出：

```text
components/dirtyfrag/native/build/libdfroot.so
components/dirtyfrag/native/build/dfroot-stage2
```

## 构建 Android 触发壳

Android 触发壳需要 JDK、Android SDK、Build Tools 和调试签名密钥。

```bash
JDK_ROOT="$JAVA_HOME" \
SDK_ROOT="$ANDROID_SDK_ROOT" \
KEYSTORE="$DBY2_KEYSTORE" \
bash components/dirtyfrag/build-harness-apk.sh
```

## 内核模块

内核模块必须使用与目标设备完全匹配的内核源码和配置构建。`KERNEL_SOURCE`
和 `ANDROID_NDK_HOME` 由构建者显式提供。

```bash
KERNEL_SOURCE="$DBY2_KERNEL_SOURCE" \
ANDROID_NDK_HOME="$ANDROID_NDK_HOME" \
bash components/dirtyfrag/build-module.sh
```

> DirtyFrag 会修改页面缓存并触发目标内核路径。构建或运行不匹配的模块可能损坏系统状态。

## 来源

`native/exp.c` 的 XFRM 设置参考 `V4bel/dirtyfrag`，CBC 块构造参考
`mitschud/DirtyFrag`。其余源码为 DBY2-W00 本地适配。来源与许可证边界见
`third-party/manifest.yaml`。
