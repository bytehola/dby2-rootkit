set pagination off
set confirm off
set architecture aarch64
target remote :1234

hbreak *0xffffffc0118dc230
commands
  silent
  printf "mcast_copy_ret=%#lx sp=%#lx\n", $x2, $sp
  x/16gx $sp + 0x20
  x/16gx $sp + 0xc0
  continue
end

continue
