set pagination off
set confirm off
set architecture aarch64
target remote :1236

hbreak *0xffffffc01057bff4
commands
  silent
  printf "PSELECT_RET sp=%#lx\n", $sp
  x/12gx $sp - 0x120
  enable 2 3 4
  continue
end

hbreak *0xffffffc01038f330
commands
  silent
  set $waiting_task = $x0
  set $waiting_waiter = *(unsigned long *)($waiting_task + 0x8d0)
  printf "ADJUST_PI task=%#lx pibo=%#lx task_prio=%#x task_deadline=%#lx waiter_prio=%#x waiter_deadline=%#lx\n", $waiting_task, $waiting_waiter, *(unsigned int *)($waiting_task + 0x154), *(unsigned long *)($waiting_task + 0x470), *(unsigned int *)($waiting_waiter + 0x48), *(unsigned long *)($waiting_waiter + 0x50)
  printf "WAITER_LOCK=%#lx LOCK_WORDS\n", *(unsigned long *)($waiting_waiter + 0x38)
  x/6gx *(unsigned long *)($waiting_waiter + 0x38)
  continue
end

hbreak *0xffffffc01038f448
commands
  silent
  printf "ADJUST_CHAIN task=%#lx lock=%#lx waiter=%#lx\n", $x0, $x2, $x3
  x/12gx $x3
  printf "LOCK\n"
  x/8gx $x2
  continue
end

hbreak *0xffffffc01038f3ec
commands
  silent
  printf "ADJUST_PI_RETURN task=%#lx waiter=%#lx task_prio=%#x waiter_prio=%#x\n", $x19, $x22, *(unsigned int *)($x19 + 0x154), *(unsigned int *)($x22 + 0x48)
  continue
end

disable 2 3 4
continue
