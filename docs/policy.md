# Root 授权审计

## 当前实现

PC 工具提供只读命令：

```bash
dby2-rootctl --json policy list
```

命令读取：

- 当前 boot_id 的短哈希。
- Magisk `policies` 表。
- UID、策略值、过期时间、日志和通知状态。
- `cmd package list packages -U` 提供的包名映射。
- `/data/adb/dby2/boot_id` 中的 boot 会话标记。

Android App 的“Root 授权”区也执行同一套只读查询，并显示 boot hash、UID、
策略和包名。App 不会自动修改或清理策略。

策略值含义：

```text
0 query
1 deny
2 allow
3 restrict
```

## 当前边界

当前 Magisk 策略记录仍然持久化在 `/data/adb/magisk.db`。
只读审计不会自动修改或清除策略，也不会把旧策略转换成 boot_id 策略。

因此当前状态是：

- 临时 Root 执行环境跨重启消失。
- Magisk 授权记录可能跨重启保留。
- 下一次重新取得临时 Root 后，旧授权可能重新生效。
- 发布版仍需实现 boot_id 绑定或启动时清理策略。

## Boot 会话标记

Root engine 在确认 Root 已激活后写入：

```text
/data/adb/dby2/boot_id
```

该文件权限为 root 所有、`0600`，内容为当前 boot_id。PC 命令：

```bash
dby2-rootctl policy session
dby2-rootctl --json policy session
```

状态：

- `same-boot`：当前 boot 与标记一致。
- `new-boot`：设备已经重启，标记来自旧 boot。
- `unmarked`：尚未通过新 Root engine 写入标记。

手动写入：

```bash
dby2-rootctl policy mark --yes
```

该操作只更新标记，不修改 Magisk 策略库。

## 新 boot 清理计划

```bash
dby2-rootctl policy expire
dby2-rootctl --json policy expire
```

默认只显示：

- 当前 boot 状态。
- 保留 UID。
- 将被清理的 UID。
- Magisk DB 备份路径。

只有 `state=new-boot` 时才会产生待清理 UID。执行：

```bash
dby2-rootctl policy expire --yes
```

执行前会备份：

```text
/data/adb/dby2/backups/magisk.db.<timestamp>
```

默认保留 UID 2000 和 `dev.dby2.rootkit`，可通过 `--preserve UID` 增加例外。

如果没有 `new-boot` 状态或没有待清理 UID，`--yes` 也不会修改策略库。

## 后续设计

boot_id 授权需要加入：

1. 当前 boot_id 记录。
2. 授权记录与 boot_id 的关联。
3. 启动时检测 boot_id 变化。
4. 旧策略清理或标记失效。
5. 管理器自身和用户显式持久授权的例外。
6. 变更前备份与回滚。

在这些逻辑完成并验证前，文档不会宣称 Root 授权已经按启动周期自动过期。
