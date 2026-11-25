# 来源记录

## 上游参考

```text
V4bel/dirtyfrag
commit aab16fcada27142dd8ce8704906cf6736cf213b8
未发现 LICENSE 文件

mitschud/DirtyFrag
commit c724a31914ff5022d1ff95ceb18a6d79f11d5071
GPL-2.0-only
```

## 本地适配

DBY2 适配代码包括 Android 11 / 5.4 内核模块、payload 加载、stage2、
broker 通信、APK 触发壳和构建脚本。适配代码与上游源码的许可证保持独立，
不得由主仓库的 GPL-3.0-or-later 声明自动覆盖。

## 未导入内容

```text
build/
vendor/*.apk
module/ 下的编译对象和生成模块
```
