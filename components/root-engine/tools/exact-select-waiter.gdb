set pagination off
set confirm off
set architecture aarch64
target remote :1235

hbreak *0xffffffc01038f4b4
commands
  silent
  printf "WAITER task=%#lx waiter=%#lx\n", $x19, $x24
  x/12gx $x24
  continue
end

continue
