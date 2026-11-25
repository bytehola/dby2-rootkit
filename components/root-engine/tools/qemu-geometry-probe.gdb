set pagination off
set confirm off
set architecture aarch64
target remote :1234

hbreak *0xffffffc012d0240c
commands
  silent
  set {unsigned int}0xffffffc012d0240c = 0xd65f03c0
  set $pc = $lr
  continue
end

hbreak *0xffffffc0104e2ddc
commands
  silent
  set {unsigned int}0xffffffc0104e2ddc = 0xd65f03c0
  set $pc = $lr
  continue
end

hbreak *0xffffffc01042ec2c
commands
  silent
  set $waiter_addr = $sp + 0xe0
  printf "futex waiter=%#lx sp=%#lx\n", $waiter_addr, $sp
  continue
end

hbreak *0xffffffc0118dc230
commands
  silent
  set $copy_addr = $sp + 0x20
  if $waiter_addr != 0
    printf "mcast copy=%#lx waiter=%#lx delta=%#lx payload=%#lx\n", \
      $copy_addr, $waiter_addr, $waiter_addr - $copy_addr, $copy_addr + 0xb0
  else
    printf "mcast copy=%#lx waiter=unset\n", $copy_addr
  end
  x/12gx $copy_addr + 0xb0
  continue
end

continue
