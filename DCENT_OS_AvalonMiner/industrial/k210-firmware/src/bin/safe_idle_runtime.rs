#![no_std]
#![no_main]
#![deny(unsafe_code)]
#![doc = "Phase-A physical safe-idle runtime: dual-hart park, zero board MMIO."]

#[cfg(not(target_arch = "riscv64"))]
compile_error!("the K210 Phase-A runtime is only defined for riscv64");

// Compile-time join to the exported BSP and sealed-profile contract. These are
// assertions, not merely type checks: a later profile edit cannot silently
// grant MMIO or actuation to this physical image.
const _: () = assert!(dcent_avalon_k210_core::bsp::RAM_BASE == 0x8000_0000);
const _: () = assert!(!dcent_avalon_k210_core::bsp::profile::SEALED.permits_mmio());
const _: () = assert!(!dcent_avalon_k210_core::bsp::profile::SEALED.permits_actuation());

#[cfg(target_arch = "riscv64")]
// SAFETY: This is the freestanding machine entry boundary. It only disables
// interrupts, installs an in-image trap vector, parks hart 1, clears the
// linker-owned BSS on hart 0, initializes the linker-owned stack, and waits.
// It performs no MMIO and has no Avalon pin, flash, cooling, PSU, or hash map.
#[allow(unsafe_code)]
mod boot {
    core::arch::global_asm!(
        r#"
    .option push
    .option norvc
    .option norelax
    .section .text.start, "ax", @progbits
    .align 3
    .global _start
    .type _start, @function
_start:
    csrci mstatus, 8
    csrw mie, zero
    csrw mip, zero
    la t0, .Ldcent_trap
    csrw mtvec, t0
    csrr t0, mhartid
    bnez t0, .Ldcent_park

    la sp, __stack_top
    la t0, __bss_start
    la t1, __bss_end
.Ldcent_clear_bss:
    bgeu t0, t1, .Ldcent_idle
    sd zero, 0(t0)
    addi t0, t0, 8
    j .Ldcent_clear_bss

.Ldcent_idle:
    wfi
    j .Ldcent_idle

.Ldcent_park:
    wfi
    j .Ldcent_park

.Ldcent_trap:
    csrci mstatus, 8
    csrw mie, zero
    j .Ldcent_park
    .size _start, . - _start

    .section .rodata.dcent_boundary, "a", @progbits
.Ldcent_physical_boundary:
    .ascii "DCENT-K210 PHASE-A ZERO-MMIO NON-INSTALLABLE v1\n"
    .option pop
"#
    );
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
