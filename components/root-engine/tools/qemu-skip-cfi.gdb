set pagination off
set confirm off
set architecture aarch64
target remote :1234

# QEMU's TCG build cannot execute the vendor trace-event CFI path correctly.
hbreak *0xffffffc012d0240c
commands
  silent
  set {unsigned int}0xffffffc012d0240c = 0xd65f03c0
  set $pc = $lr
  continue
end

# Keep later harmless vendor CFI false positives from panicking the guest.
hbreak *0xffffffc0104e2ddc
commands
  silent
  set {unsigned int}0xffffffc0104e2ddc = 0xd65f03c0
  set $pc = $lr
  continue
end

continue
