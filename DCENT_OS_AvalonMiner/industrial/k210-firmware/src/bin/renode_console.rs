#![no_std]
#![no_main]
#![deny(unsafe_code)]
#![doc = "Renode-only K210 console beacon. Never package for physical hardware."]

#[cfg(not(target_arch = "riscv64"))]
compile_error!("the K210 Renode console is only defined for riscv64");

#[cfg(target_arch = "riscv64")]
// SAFETY: This binary is an emulator-only test surface. Its only MMIO is the
// modeled UARTHS TXCTRL/TXDATA pair. The physical candidate builder accepts a
// different fixed binary name and can never select this target.
#[allow(unsafe_code)]
mod boot {
    use dcent_avalon_k210_core::bsp;

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
    la t0, .Ldcent_renode_trap
    csrw mtvec, t0
    csrr t0, mhartid
    bnez t0, .Ldcent_renode_park

    la sp, __stack_top
    la t0, __bss_start
    la t1, __bss_end
.Ldcent_renode_clear_bss:
    bgeu t0, t1, .Ldcent_renode_beacon
    sd zero, 0(t0)
    addi t0, t0, 8
    j .Ldcent_renode_clear_bss

.Ldcent_renode_beacon:
    li t0, {uarths_base}
    li t1, {tx_enable}
    sw t1, {txctrl_offset}(t0)
    la t1, .Ldcent_beacon_bytes
    la t2, .Ldcent_beacon_end
.Ldcent_renode_next:
    bgeu t1, t2, .Ldcent_renode_park
    lw t4, {txdata_offset}(t0)
    bltz t4, .Ldcent_renode_next
    lbu t3, 0(t1)
    sw t3, {txdata_offset}(t0)
    addi t1, t1, 1
    j .Ldcent_renode_next

.Ldcent_renode_park:
    wfi
    j .Ldcent_renode_park

.Ldcent_renode_trap:
    csrci mstatus, 8
    csrw mie, zero
    j .Ldcent_renode_park
    .size _start, . - _start

    .section .rodata, "a", @progbits
.Ldcent_beacon_bytes:
    .ascii "DCENT-K210 RENODE safe-idle v1\n"
.Ldcent_beacon_end:
"#,
        uarths_base = const bsp::UARTHS_BASE,
        tx_enable = const bsp::uarths::TXCTRL_TXEN,
        txctrl_offset = const bsp::uarths::REG_TXCTRL,
        txdata_offset = const bsp::uarths::REG_TXDATA,
    );
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
