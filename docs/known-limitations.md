# 已知限制

## 设备限制

- 只支持 `DBY2-W00`。
- 只验证了 HarmonyOS `4.2.0.252(C00E100R3P5)`。
- Android 12 / API 31。
- 内核 `5.4.86`。

其他系统版本需要新 profile 和真机验证。

## Root 限制

- 临时 Root，不跨完整重启。
- 不修改 boot，不提供开机自动 Root。
- 修改系统服务或内核状态后，仍然建议重启恢复。
- exploit 在单次 boot 中只应触发一次。

## 使用限制

- 首版推荐 PC 辅助模式。
- App 独立模式仍待安全改造。
- 持久 TCP ADB 默认不开启。
- ADB shell 的 root 权限需要维护会话控制。

## Xposed 限制

- 系统级 Xposed 默认开启，但 system_server 注入仍然是高风险操作。
- 系统服务重启只允许一次，失败后进入降级。
- 第三方系统模块需要逐个确认作用域。
- Thanox 等模块的稳定性和兼容性不受本项目保证。
- App 可以启停模块，但不会自动重启目标应用或 system_server。
- App 支持单个作用域增删，暂不支持批量覆盖作用域。
- `system/0` 作用域会影响系统框架，只应由明确了解风险的用户使用。

## 授权限制

- Magisk 策略记录目前仍会跨重启保留。
- PC 工具当前只读显示授权，不会自动清除旧记录。
- boot_id 绑定和过期清理尚未实现。
- 每次重新 Root 后应检查 `dby2-rootctl policy list`。
- boot 会话标记目前只用于识别 `same-boot/new-boot`，不会自动清理旧策略。
- 新 NyaZygisk active 模块不能热替换正在运行的旧模块，需要下一次干净 Root。
- `bootstrap --replace-modules` 会备份旧模块后切换 active 模块，只能在确认可恢复时使用。

## 发行限制

- Root payload 源码已随仓库提供，但第三方组件仍分别受其原始许可证约束。
- 第三方 Xposed 模块不在发行包内，本项目不保证第三方模块的稳定性。
- 其他系统版本必须重新建立 profile、编译匹配 payload 并完成真机回归。
