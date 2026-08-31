#![no_std]
#![no_main]
#![deny(unsafe_code)]
#![doc = "Desk-only K210 image-pipeline sentinel. Never authorized for a miner."]

#[cfg(not(target_arch = "riscv64"))]
compile_error!("the K210 safe-idle sentinel is only defined for riscv64");

#[cfg(target_arch = "riscv64")]
// SAFETY: This is the sentinel's sole machine-code boundary. It defines the
// entry point and only disables interrupts, installs a local trap vector, and
// waits; it performs no memory-mapped or board I/O.
#[allow(unsafe_code)]
mod boot {
    core::arch::global_asm!(
        r#"
    .section .text.start, "ax", @progbits
    .align 3
    .global _start
    .type _start, @function
_start:
    csrci mstatus, 8
    csrw mie, zero
    csrw mip, zero
    la t0, _dcent_k210_trap
    csrw mtvec, t0

_dcent_k210_safe_idle:
    wfi
    j _dcent_k210_safe_idle

    .align 2
_dcent_k210_trap:
    csrci mstatus, 8
    csrw mie, zero
    j _dcent_k210_safe_idle
    .size _start, . - _start
"#
    );
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
