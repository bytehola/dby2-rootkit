set pagination off
set confirm off
set architecture aarch64
target remote :1239

set $park_waiter = 0
set $park_task = 0
set $park_lock = 0

hbreak *0xffffffc01031196c
commands
  silent
  printf "SIGSUSPEND_ENTER sp=%#lx\n", $sp
  enable 2 3 4
  continue
end

hbreak *0xffffffc01038f330
condition 2 ((*(unsigned long *)($x0 + 0x7d0) == 0x636f6c74736f6867) && (*(unsigned long *)($x0 + 0x8d0) != 0))
commands
  silent
  set $park_task = $x0
  set $park_waiter = *(unsigned long *)($park_task + 0x8d0)
  printf "ADJUST_PI sp=%#lx task=%#lx pibo=%#lx\n", $sp, $park_task, $park_waiter
  x/12gx $park_waiter
  continue
end

hbreak *0xffffffc01038f448
condition 3 (($park_task != 0) && ($x0 == $park_task))
commands
  silent
  set $park_lock = $x3
  printf "ADJUST_CHAIN sp=%#lx task=%#lx lock=%#lx waiter=%#lx\n", $sp, $x0, $park_lock, $x2
  x/12gx $park_waiter
  printf "LOCK_AT_CHAIN\n"
  x/8gx $park_lock
  continue
end

hbreak *0xffffffc011b91b64
condition 4 (($park_waiter != 0) && ($x1 == $park_waiter))
commands
  silent
  printf "RB_ERASE root=%#lx node=%#lx parent_color=%#lx right=%#lx left=%#lx\n", $x0, $x1, *(unsigned long *)$x1, *(unsigned long *)($x1 + 0x8), *(unsigned long *)($x1 + 0x10)
  continue
end

disable 2 3 4
continue
