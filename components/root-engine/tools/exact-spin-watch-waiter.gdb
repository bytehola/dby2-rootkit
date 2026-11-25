set pagination off
set confirm off
set architecture aarch64
set can-use-hw-watchpoints 1
target remote :1240

set $spin_waiter = 0

hbreak *0xffffffc0118e704c
commands
  silent
  set $spin_copy = $sp + 0x20
  set $spin_waiter = $spin_copy + 0xb0
  printf "MCAST_POST copy=%#lx waiter=%#lx\n", $spin_copy, $spin_waiter
  x/12gx $spin_waiter
  disable 1
  watch *(unsigned long *)($spin_waiter + 0x30)
  watch *(unsigned long *)($spin_waiter + 0x38)
  watch *(unsigned long *)($spin_waiter + 0x40)
  continue
end

continue
printf "STOP1 pc=%#lx lr=%#lx\n", $pc, $lr
x/8i $pc - 0x10
x/12gx $spin_waiter

continue
printf "STOP2 pc=%#lx lr=%#lx\n", $pc, $lr
x/8i $pc - 0x10
x/12gx $spin_waiter

continue
printf "STOP3 pc=%#lx lr=%#lx\n", $pc, $lr
x/8i $pc - 0x10
x/12gx $spin_waiter

continue
printf "STOP4 pc=%#lx lr=%#lx\n", $pc, $lr
x/8i $pc - 0x10
x/12gx $spin_waiter

continue
printf "STOP5 pc=%#lx lr=%#lx\n", $pc, $lr
x/8i $pc - 0x10
x/12gx $spin_waiter

continue
printf "STOP6 pc=%#lx lr=%#lx\n", $pc, $lr
x/8i $pc - 0x10
x/12gx $spin_waiter
