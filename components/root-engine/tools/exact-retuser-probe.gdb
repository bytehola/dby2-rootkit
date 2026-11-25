set pagination off
set confirm off
set architecture aarch64
target remote :1235

hbreak *0xffffffc010085440
commands
  silent
  if *(unsigned long *)($sp - 0x40) == 0xffffffc013401d40
    printf "RET_USER sp=%#lx waiter=%#lx\n", $sp, $sp - 0x70
    x/12gx $sp - 0x70
  end
  continue
end

continue
