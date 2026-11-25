set pagination off
set confirm off
set architecture aarch64
target remote :1234

hbreak *0xffffffc0103e0330
condition 1 $x25 == 0xffffffc01322e000
commands
  silent
  printf "fake_lock_try waiter=%#lx lock=%#lx\n", $x24, $x25
  x/12gx $x24
  x/8gx $x25
  continue
end

hbreak *0xffffffc0103e04ac
condition 2 $x25 == 0xffffffc01322e000
commands
  silent
  printf "enqueue_walk_node=%#lx waiter=%#lx lock=%#lx\n", $x13, $x24, $x25
  x/8gx $x25
  x/12gx $x24
  continue
end

continue
