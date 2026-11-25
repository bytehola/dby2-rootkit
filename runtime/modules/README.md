# NyaZygisk and Vector Modules

## Purpose

Build the arm64-v8a NyaZygisk and Vector module ZIPs used by DBY2-W00.

The source inputs are vendored in this repository:

```text
components/nyazygisk
components/vector
```

The source versions used for the first successful build:

```text
NyaZygisk: ce72ac8f566bc292f0e92dc69ff1dfbd27cd7570
Vector:   6f6b976e3315c158d501f743c3c609e80cae7ec8
```

## NyaZygisk arm64-only patch

The upstream NyaZygisk build tries to build arm64, armv7, x86_64 and riscv64.
DBY2-W00 is arm64-only, and stable Rust does not provide the riscv64 Android
standard library.

The checked-in source already contains the arm64-only ABI selection.

This patch changes only the build ABI set. It does not alter runtime logic.

## Build

```bash
export NYAZYGISK_SOURCE="$PWD/components/nyazygisk"
export VECTOR_SOURCE="$PWD/components/vector"

./runtime/modules/build.sh
```

`ANDROID_SDK_ROOT`、`JAVA_HOME`、`CARGO_HOME` 和 `RUSTUP_HOME` 必须指向
实际构建环境。

The script expects:

- Android NDK 27.2 for NyaZygisk.
- Android NDK 30.0 for Vector.
- CMake 4.1.2.
- Rust target `aarch64-linux-android`.
- `cargo-ndk` 4.x.

Output:

```text
runtime/modules/build/
  NyaZygisk-*.zip
  Vector-*.zip
  SHA256SUMS
```

## Verified build outputs

```text
NyaZygisk-v2.6-1-ce72ac8-debug.zip
SHA256 a985ac829e89e6210b697665969b62f4286c9b16b32f50998ca9fd451796e137

Vector-vcanary-3119-1-Debug.zip
SHA256 d2c0e3b5f265ffef68c90bc71f5c2a37e9437a708a45eb177d19845d0e4947a8
```

## Current limitation

The source-built modules were installed on the test device, but the active
NyaZygisk module cannot be swapped under a running zygote without a new
zygote mapping. The original module was restored after the test.

The first-install flow must install these modules before the effective
Zygisk/Vector activation step or after a clean reboot, not by overwriting
the active module directory while the old module is running.
