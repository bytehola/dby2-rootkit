set pagination off
set confirm off
set architecture aarch64
target remote :1234

hbreak *0xffffffc012d0240c
commands
  silent
  # QEMU trips a false-positive legacy CFI check in vendor initcalls.
  # Return immediately from the abort handler so the calibration guest can boot.
  set {unsigned int}0xffffffc0104e2e20 = 0xd65f03c0
  set $pc = $lr
  detach
  quit
end

continue
