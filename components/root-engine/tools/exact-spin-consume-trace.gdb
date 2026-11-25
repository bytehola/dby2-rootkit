set pagination off
set confirm off
set architecture aarch64
target remote :1237

set $spin_copy = 0
set $spin_waiter = 0
set $spin_task = 0

hbreak *0xffffffc01008f640
commands
  silent
  if $x2 == 0x108
    set $spin_copy = $x0
    set $spin_waiter = $spin_copy + 0xb0
    printf "MCAST_COPY copy=%#lx waiter=%#lx\n", $spin_copy, $spin_waiter
    x/16gx $spin_waiter - 0x20
  end
  continue
end

hbreak *0xffffffc01038f330
condition 2 (($spin_waiter != 0) && (*(unsigned long *)($x0 + 0x8d0) == $spin_waiter))
commands
  silent
  set $spin_task = $x0
  printf "ADJUST_PI sp=%#lx task=%#lx pibo=%#lx task_prio=%#x waiter_prio=%#x\n", $sp, $spin_task, $spin_waiter, *(unsigned int *)($spin_task + 0x154), *(unsigned int *)($spin_waiter + 0x48)
  x/12gx $spin_waiter
  continue
end

hbreak *0xffffffc01038f448
condition 3 (($spin_task != 0) && ($x0 == $spin_task))
commands
  silent
  printf "ADJUST_CHAIN sp=%#lx task=%#lx lock=%#lx waiter=%#lx\n", $sp, $x0, $x3, $x2
  x/12gx $spin_waiter
  continue
end

hbreak *0xffffffc011b91b64
condition 4 (($spin_waiter != 0) && ($x1 == $spin_waiter))
commands
  silent
  printf "RB_ERASE root=%#lx node=%#lx parent_color=%#lx right=%#lx left=%#lx\n", $x0, $x1, *(unsigned long *)$x1, *(unsigned long *)($x1 + 0x8), *(unsigned long *)($x1 + 0x10)
  continue
end

continue
