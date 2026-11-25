# 架构

## 目标

为 DBY2-W00 提供可复现、可诊断、可退出的临时 Root 工具链。

系统不修改 boot、recovery、system 或 vendor 分区镜像。完整重启后回到普通系统，
需要重新获取临时 Root。

## 分层

```text
PC CLI
  -> device profile gate
  -> ADB selection
  -> start Magisk OneTapRoot foreground service over ADB
  -> Magisk APK and module bootstrap
  -> post-root verification
  -> Vector module and scope management
  -> read-only Magisk policy audit
  -> persistent boot-session marker
  -> redacted diagnostics

Magisk APK
  -> App-process DirtyFrag / GhostLock UID 0 broker
  -> Magisk-compatible runtime
  -> bundled NyaZygisk and Vector installation
  -> Zygisk injection
  -> Vector / Xposed daemon

Android App
  -> status
  -> runtime inspection
  -> root trigger
  -> su request approval
  -> Xposed modules and scope
  -> diagnostics
```

## 当前仓库实现

已经开始实现：

- `pc/dby2-rootctl`：PC CLI。
- `app/rootkit-manager`：状态和 Root 验证 App。
- `profiles/dby2-w00`：精确设备 profile。
- `runtime/root-engine/engine.sh`：维护者使用的独立脚本兼容接口。
- `components/magisk`：移植 Magisk、本机 ADB 密钥与一键 Root 实现。
- `components/vector`：Vector Xposed 运行时。
- `components/nyazygisk`：Zygisk 注入宿主。
- `components/root-engine`：GhostLock Root broker。
- `components/dirtyfrag`：DirtyFrag 页面缓存写入与模块加载链。
- `OneTapRootService.kt`：电脑通过 ADB 启动的后台 Root 服务。
- 日志脱敏和秘密扫描。

当前 App 已支持状态、Root 验证、Magisk、Zygisk、Vector、模块列表展示、
模块启停、单个作用域增删和 Root 授权只读审计。

普通用户通过图形界面的“一键 Root”完成首次安装和后续恢复。Root 完成后
可以执行 10 秒倒计时软重启，也可以从 Magisk 或 DBY2 RootKit 手动触发。

## 信任边界

### 非可信输入

- 第三方 Xposed 模块。
- 用户输入的 APK。
- 诊断日志内容。
- 目标应用和 system_server 的状态。

### 受信组件

- 经过 profile 校验的 DBY2-W00。
- 固定版本的 runtime payload。
- 本仓库构建的 PC CLI。
- 带签名的 release APK。

## 安全不变量

1. 非 `DBY2-W00` 不执行提权。
2. 非匹配 Build、SDK、ABI 或内核不执行提权。
3. 同一 boot 不重复触发单次 exploit。
4. Root 授权默认绑定 boot_id。
5. shell UID 2000 只在维护会话内获得 root。
6. 系统级 Xposed 默认开启，但只允许一次受控 system_server 重启。
7. 诊断日志默认脱敏。
8. 根执行环境消失后不自动重复 exploit。

## Root 生命周期

```text
普通系统
  -> profile 校验
  -> PC 连接：ADB 启动 Magisk Root 服务
  -> 脱离电脑：Magisk 首页一键 Root
  -> UID 0 broker
  -> su 策略生效
  -> Zygisk / Vector

重启
  -> broker 消失
  -> overlay 消失
  -> Magisk daemon 消失
  -> 持久配置文件保留
  -> 旧授权按 boot_id 失效
  -> 等待下一次显式 Root
```

## 失败恢复

- 未触发 exploit：直接退出，不改变设备。
- exploit 已触发但失败：提示重启，不再重复。
- Root 成功但系统服务异常：等待恢复或整机重启。
- Vector 失败：保留 Root，标记 Xposed 降级。
- system_server 重启超时：停止注入，进入安全模式。
- App 或 su 策略异常：使用 PC CLI 状态检查和诊断导出。
