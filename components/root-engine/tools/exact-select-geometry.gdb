set pagination off
set confirm off
set architecture aarch64
target remote :1235

hbreak *0xffffffc0103dce8c
commands
  silent
  printf "FUTEX sp=%#lx waiter=%#lx\n", $sp, $sp + 0xe0
  continue
end

hbreak *0xffffffc01057b13c
commands
  silent
  printf "PSELECT core_sp=%#lx stack_fds=%#lx\n", $sp, $sp + 0x50
  continue
end

hbreak *0xffffffc01057bff4
commands
  silent
  printf "PSELECT_RET wrapper_sp=%#lx waiter=%#lx\n", $sp, $sp - 0x120
  x/14gx $sp - 0x120
  printf "FAKE_PAGE\n"
  x/24gx 0xffffffc01365ee60
  continue
end

continue
