DBY2 RootKit 一键 Root
======================

适用设备
--------
HUAWEI MatePad Air 11.5 2023（DBY2-W00）
HarmonyOS 4.2.0.252(C00E100R3P5)

使用步骤
--------
1. 将整个压缩包解压到普通文件夹，不要只单独复制 EXE。
2. 在平板开发者选项中打开 USB 调试和“仅充电模式下允许 ADB 调试”。
3. 使用能传输数据的 USB 线连接电脑。
4. 解锁平板，在“允许 USB 调试”弹窗中点击允许。
   如果没有弹窗，将 USB 连接方式改为“传输文件”后重新插拔数据线。
5. 双击 DBY2-RootKit.exe。
6. 等待界面显示设备已连接，点击“一键 Root”。
7. 保持 USB 数据线连接，程序会自动通过 ADB 获取临时 Root。
8. 程序会自动安装 Magisk、RootKit、NyaZygisk 与 Vector。
9. 在 RootKit 的超级用户弹窗中点击“允许”。
10. 界面会显示 10 秒倒计时，到期后自动软重启系统框架。
11. 等待平板恢复，再点击“验证”确认全部通过。

重启后
------
完整重启会清除临时 Root。重新连接 USB，打开本程序并再次点击
“一键 Root”，程序会重新通过 ADB 提权并恢复已有运行环境。

注意
----
- 仅支持上述型号和系统版本，其他版本会被拒绝。
- 这是临时 Root，不修改 boot、recovery、system 或 vendor。
- 不需要安装或启动独立的 DBY2 DirtyFrag App。
- Magisk APK 已内置 NyaZygisk 与 Vector，不需要另装 Root 工具。
- Magisk 首页“一键 Root”只用于脱离电脑的场景。
- 每次完整重启后，连接电脑使用本程序是最快的恢复方式。
- Windows 首次运行可能出现 SmartScreen 提示，因为本构建未购买代码签名。
- 请勿关闭程序窗口，直到倒计时结束且平板开始软重启。
- 诊断包会自动脱敏设备序列号、网络地址和 boot_id。

第三方组件
----------
Magisk、NyaZygisk 和 Vector 的版本、来源和许可证见：
THIRD_PARTY_NOTICES.txt
