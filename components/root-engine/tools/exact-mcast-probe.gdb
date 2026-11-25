set pagination off
set confirm off
set architecture aarch64
target remote :1235

set $mcast_copy = 0
set $mcast_waiter = 0

hbreak *0xffffffc01008f640
commands
  silent
  if $x2 == 0x108
    set $mcast_copy = $x0
    set $mcast_waiter = $mcast_copy + 0xb0
    printf "MCAST copy=%#lx waiter=%#lx return=%#lx\n", \
      $mcast_copy, $mcast_waiter, $lr
    x/16gx $mcast_waiter - 0x20
  end
  continue
end

hbreak *0xffffffc01038f4b4
commands
  silent
  printf "WALK waiter=%#lx mcast_copy=%#lx mcast_waiter=%#lx\n", \
    $x24, $mcast_copy, $mcast_waiter
  x/16gx $x24 - 0x20
  printf "FAKE_LOCK\n"
  x/8gx 0xffffffc01365ee60
  continue
end

hbreak *0xffffffc0118e704c
commands
  silent
  set $post_copy = $sp + 0x20
  set $post_waiter = $post_copy + 0xb0
  printf "POST_MCAST copy=%#lx waiter=%#lx result=%#lx\n", \
    $post_copy, $post_waiter, $x0
  x/16gx $post_waiter - 0x20
  continue
end

hbreak *0xffffffc01038f5c0
commands
  silent
  printf "TRYLOCK waiter=%#lx lock=%#lx result=%#lx\n", \
    $x24, $x25, $x0
  x/4gx $x25
  continue
end

hbreak *0xffffffc01038f5cc
commands
  silent
  printf "AFTER_UNLOCK waiter=%#lx lock=%#lx\n", $x24, $x25
  x/4gx $x25
  continue
end

hbreak *0xffffffc01038f5e4
commands
  silent
  printf "BEFORE_RB_ERASE waiter=%#lx lock=%#lx\n", $x24, $x25
  x/12gx $x24
  continue
end

continue
