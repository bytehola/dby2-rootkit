set pagination off
set confirm off
set architecture aarch64
target remote :1235

hbreak *0xffffffc010085440
commands
  silent
  printf "RET sp=%#lx\n", $sp
  find /g $sp - 0x500, $sp + 0x100, 0xffffffc013401d40
  continue
end

continue
