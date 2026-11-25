set pagination off
set confirm off
set architecture aarch64
target remote :1238

set $park_waiter = 0
set $park_task = 0

hbreak *0xffffffc0118e704c
commands
  silent
  set $park_copy = $sp + 0x20
  set $park_waiter = $park_copy + 0xb0
  printf "MCAST_POST copy=%#lx waiter=%#lx\n", $park_copy, $park_waiter
  x/12gx $park_waiter
  continue
end

hbreak *0xffffffc01038f330
condition 2 (($park_waiter != 0) && (*(unsigned long *)($x0 + 0x8d0) == $park_waiter))
commands
  silent
  set $park_task = $x0
  printf "ADJUST_PI sp=%#lx task=%#lx pibo=%#lx\n", $sp, $park_task, $park_waiter
  x/12gx $park_waiter
  continue
end

hbreak *0xffffffc01038f448
condition 3 (($park_task != 0) && ($x0 == $park_task))
commands
  silent
  printf "ADJUST_CHAIN sp=%#lx task=%#lx lock=%#lx waiter=%#lx\n", $sp, $x0, $x3, $x2
  x/12gx $park_waiter
  printf "LOCK_AT_CHAIN\n"
  x/8gx $x3
  continue
end

hbreak *0xffffffc011b91b64
condition 4 (($park_waiter != 0) && ($x1 == $park_waiter))
commands
  silent
  printf "RB_ERASE root=%#lx node=%#lx parent_color=%#lx right=%#lx left=%#lx\n", $x0, $x1, *(unsigned long *)$x1, *(unsigned long *)($x1 + 0x8), *(unsigned long *)($x1 + 0x10)
  continue
end

continue
