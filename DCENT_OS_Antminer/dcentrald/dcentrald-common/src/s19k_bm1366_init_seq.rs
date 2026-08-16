//! S19k BM1366 **EXPERIMENTAL** native init program (host-testable).
//!
//! Does not open UART, energize rails, or claim mining. Native BM1366
//! cold-init remains refused in `serial_mining.rs`. This module pins the
//! byte program so a later EXPERIMENTAL executor can run it without
//! inventing opcodes.
//!
//! : `wire_b::CMD_CHAIN_INACTIVE = 0x53`. GetAddress is `CMD_GET_ADDRESS = 0x52`.

use crate::s19k_bm1366_uart_rx::{
    CHAIN_INACTIVE_UART, ESP_BM1366_CHIP_ID_RX_LEN, GET_ADDRESS_UART, UART_RESP_LEN, S19kRxDiag,
};
use crate::bm1366_pll_reg_and_actual;
use crate::s19k_bm1366_wire_b::{
    cmd_set_config, pack_set_address_uart_trans, s19k_aml_linear_addresses, CORE_REG_ASICBOOST,
    CORE_REG_CLOCK_DELAY, CORE_REG_HASH_CLOCK, PLL_RAMP_START_MHZ, PUBLIC_FASTUART_REG,
    PUBLIC_FASTUART_VALUE, REG_PLL0, REG_TICKET_MASK, REG_UART_RELAY, REG_VERSION_ROLL,
    S19K_WIRE_HASH_COUNTING, TICKET_MASK_PLAIN_DIFF_MINUS_ONE_256, UART_RELAY_CHIP0_PUBLIC,
};
use crate::s19k_uart_trans_job::{BRAIINS_TTYS_BAUD, BRAIINS_TTYS_DISCOVER};

/// On-chip version rolling register (desk 11e / ESP-Miner family).
pub const INIT_REG_VERSION_ROLL: u8 = REG_VERSION_ROLL;
/// Ticket mask register.
pub const INIT_REG_TICKET_MASK: u8 = REG_TICKET_MASK;
/// Hash counting register (stock S19k `0x0000115A`).
pub const INIT_REG_HASH_COUNTING: u8 = 0x10;
/// Init-control / mystery register (ESP-Miner `init4` + per-chip `set_a8`).
pub const INIT_REG_INIT_CTRL: u8 = 0xA8;
/// ESP-Miner BM1366 broadcast `0xA8` (`55 AA 51 09 00 A8 00 07 00 00 …`).
pub const INIT_CTRL_A8_BCAST: u32 = 0x0007_0000;
/// ESP-Miner BM1366 per-chip `0xA8` (`41 09 <addr> A8 00 07 01 F0`).
pub const INIT_CTRL_A8_UNICAST: u32 = 0x0007_01F0;
/// ESP-Miner per-chip MiscCtrl (`41 09 <addr> 18 F0 00 C1 00`).
pub const MISC_CTRL_UNICAST: u32 = 0xF000_C100;
/// `FIRMWARE_INTERNALS.md` BM1366 per-chip `0xA8 = 0xF0010700` contradicts
/// the ESP UART bytes. Refuse it as the S19k program value.
pub const REFUSED_INTERNALS_A8_PER_CHIP: u32 = 0xF001_0700;
/// `bosminer.unpacked` file offset of bytes `00 00 11 5A`.
/// PHDR maps this to VA `0x019A20A6` (NOT file+0x400000).
pub const BOSMINER_115A_BE_FILE_OFF: u64 = 0x0159_20A6;
pub const BOSMINER_115A_BE_VA: u64 = 0x019A_20A6;
/// Sole Ghidra data xref near this constant: tuner `FUN_0065f830` @ `0x664c0c`
/// (string `bosminer_plus_tuner`). **Not** a UART `set_config` writer.
pub const BOSMINER_115A_TUNER_XREF_VA: u64 = 0x0066_4C0C;
/// `FUN_008434e0` logs “HCN divider / serial versions / frequency / max work
/// time” using `12_500_000 / freq`. Work-time arithmetic, **not** a UART
/// `set_config(reg=0x10)` writer.
pub const BOSMINER_HCN_DIVIDER_LOG_FN_VA: u64 = 0x0084_34E0;
/// Crystal used by that log for max-work-time, not a hash-count register.
pub const BOSMINER_HCN_DIVIDER_LOG_XTAL_HZ: u32 = 12_500_000;
/// ASCII `hash_counting_number`. Ghidra xref is metrics registrar
/// `FUN_0041ea18` @ `0x41ee38` (`PARAM`), not a UART `set_config`.
pub const BOSMINER_HASH_COUNTING_NUMBER_STR_VA: u64 = 0x0139_DB65;
pub const BOSMINER_HASH_COUNTING_NUMBER_XREF_FN_VA: u64 = 0x0041_EA18;
/// Serde `TicketMaskReg` → `ticket_mask`. Not a UART writer.
pub const BOSMINER_TICKET_MASK_SERDE_FN_VA: u64 = 0x0086_F5E0;
/// Count of 4-aligned ARM64 `MOVZ Wd, #0x51` in `bosminer.unpacked`.
/// Sample `FUN_008c4bfc` allocates a 0x51-byte VoltageController panic
/// string — **not** UART set_config `0x51`.
pub const BOSMINER_MOVZ51_HITS: usize = 33;
pub const BOSMINER_MOVZ51_VOLTAGE_ALLOC_VA: u64 = 0x008C_4BFC;
/// ESP-Miner `BM1366_set_max_baud` FastUART host rate. Not 3 M / 115200.
pub const ESP_FASTUART_HOST_BAUD: u32 = 1_000_000;
/// `a lab unit` dmesg: meson wake 9600→115200 and **hold** (no 3M step).
pub const S19K_78_DMESG_HOLD_BAUD: u32 = 115_200;
/// ESP `BM1366_set_default_baud` writes **MiscCtrl 0x18**, not FastUART 0x28.
/// Payload `{0x00,0x00,0b01111010,0b00110001}` = `0x00007A31`. Divider 26
/// (`11010`) in bits 9-13. Formula `25e6/((div+1)*8)` = 115740; ESP returns
/// 115749. Neither is a Track-1 `0x28` leave-115200 encoding.
pub const ESP_BM1366_MISCCTRL_DEFAULT_BAUD_REG: u8 = 0x18;
pub const ESP_BM1366_MISCCTRL_DEFAULT_BAUD_VALUE: u32 = 0x0000_7A31;
pub const ESP_BM1366_MISCCTRL_DEFAULT_BAUD_DIV: u32 = 26;
pub const ESP_BM1366_MISCCTRL_XTAL_HZ: u32 = 25_000_000;
pub const ESP_BM1366_SET_DEFAULT_BAUD_RETURN_HZ: u32 = 115_749;
/// bosminer-hal write_reg / read_register live in `command.rs`.
pub const BOSMINER_HAL_COMMAND_RS_VA: u64 = 0x0130_3F89;
pub const BOSMINER_SET_BAUD_RATE_STR_VA: u64 = 0x0131_B8D5;
/// packed_struct field blob including `ext_baud_enable` (FastUartReg).
/// Adjacent names: `unknown_bits_31_28` … `rfs` … `tfs`.
pub const BOSMINER_FASTUART_FIELDS_STR_VA: u64 = 0x0132_0C4B;
/// Bible BM1366 3.125 Mbaud FastUART at reg `0x28`. Not S19k host `3_000_000`.
pub const : u32 = 0x0000_3001;
/// Bible / live BM1362 3.125 Mbaud FastUART at reg `0x28`.
pub const : u32 = 0x0000_3011;
/// Host rate that matches the bible BM1366 encoding. Distinct from Track-1 3M.
pub const : u32 = 3_125_000;
/// bosminer DATA: `28 00 00 00 30 11` (reg `0x28` + BE `0x00003011`).
/// Second LOAD: file + `0x410000` → VA.
pub const BOSMINER_REG28_3011_FILE_OFF: u64 = 0x013B_0A28;
pub const BOSMINER_REG28_3011_VA: u64 = 0x017C_0A28;
/// bosminer DATA: `28 00 00 00 30 01` (reg `0x28` + BE `0x00003001`).
pub const BOSMINER_REG28_3001_FILE_OFF: u64 = 0x0141_FA28;
pub const BOSMINER_REG28_3001_VA: u64 = 0x0182_FA28;
/// `MOVZ X1,#0x3001` sites. A later `MOVK X1,#imm16,LSL#16` completes a
/// 64-bit pointer — not a FastUART immediate.
pub const BOSMINER_MOVZ_X1_3001_VA_A: u64 = 0x010B_A39C;
pub const BOSMINER_MOVZ_X1_3001_VA_B: u64 = 0x010C_49D8;
/// `command.rs` `read_register` — logs `Hashchip: no response for read_register`.
pub const BOSMINER_COMMAND_RS_READ_REGISTER_FN_VA: u64 = 0x008A_9044;
pub const BOSMINER_COMMAND_RS_READ_REGISTER_STR_VA: u64 = 0x0130_3FC0;
/// 4-byte BE UART payload send. Callers: AM2 set-baud + MiscCtrl modify.
/// This is the write primitive, not a dedicated `write_reg` symbol.
pub const BOSMINER_UART_BE4_SEND_FN_VA: u64 = 0x008A_200C;
/// `Modifying MiscCtrl for chip` — ASIC `0x18` path, not FastUART `0x28`.
pub const BOSMINER_MISCCTRL_MODIFY_FN_VA: u64 = 0x008B_40DC;
/// AM2 S17 `CHAIN/: Set baud rate` async state machine. Not S19k AML.
pub const BOSMINER_AM2_SET_BAUD_FN_VA: u64 = 0x0083_6934;
/// Packed UART `51 09 00 28` (set_config FastUART) hits in `bosminer.unpacked`.
pub const BOSMINER_SETCFG_51_09_00_28_HITS: usize = 0;
/// First-LOAD `BL` to [`BOSMINER_UART_BE4_SEND_FN_VA`]. AM2 / send-self / MiscCtrl.
pub const BOSMINER_UART_BE4_SEND_BL_HITS: usize = 4;
pub const BOSMINER_UART_BE4_SEND_BL_VA: [u64; 4] = [
    0x0083_6C3C,
    0x008A_2300,
    0x008A_255C,
    0x008B_4504,
];
/// Sole code caller of host termios `FUN_00bbe3d4`.
pub const BOSMINER_HOST_TERMIOS_CALLER_FN_VA: u64 = 0x008F_E748;
pub const BOSMINER_HOST_TERMIOS_FN_VA: u64 = 0x00BB_E3D4;
/// : first-LOAD `MOVZ #0xC6C0` sites that complete `3_000_000` with `MOVK #0x2D,LSL#16`.
pub const BOSMINER_HOST_3M_BAUD: u32 = 3_000_000;
pub const BOSMINER_HOST_3M_MOVZ_HITS: usize = 4;
pub const BOSMINER_HOST_3M_MOVZ_VA: [u64; 4] = [
    0x00BB_E5BC,
    0x00BC_00EC,
    0x00BC_1F94,
    0x00BC_7020,
];
pub const BOSMINER_HOST_3M_MOVZ_INSN: [u32; 4] = [
    0x5298_D808,
    0x5298_D802,
    0x5298_D802,
    0x5298_D808,
];
/// Termios compare: `MOVZ/MOVK` are consecutive. AML open is `+0x20`.
pub const BOSMINER_HOST_3M_TERMIOS_MOVK_VA: u64 = 0x00BB_E5C0;
pub const BOSMINER_HOST_3M_TERMIOS_MOVK_INSN: u32 = 0x72A0_05A8;
pub const BOSMINER_AML_OPEN_3M_MOVK_VA: u64 = 0x00BC_1FB4;
pub const BOSMINER_AML_OPEN_3M_MOVK_INSN: u32 = 0x72A0_05A2;
/// Linux ARM `B3000000` = `0010015` octal = `0x100D`.
pub const BOSMINER_B3000000_SPEED_T: u32 = 0x100D;
pub const BOSMINER_B3000000_MOVZ_HITS: usize = 3;
pub const BOSMINER_B3000000_MOVZ_VA: [u64; 3] = [0x00BB_E5CC, 0x00BC_2918, 0x00BC_7130];
pub const BOSMINER_B3000000_MOVZ_INSN: [u32; 3] = [
    0x5282_01A1,
    0x5282_01A2,
    0x5282_01A1,
];
pub const BOSMINER_ANTMINER_AML_RS: &[u8] =
    b"open/utils-rs/serial-driver/src/antminer_aml.rs";
pub const BOSMINER_ANTMINER_AML_RS_FILE_OFF: u64 = 0x00F9_2558;
pub const BOSMINER_SETTING_SPEED_STR: &[u8] = b"setting speed";
pub const BOSMINER_NIX_TERMIOS_RS: &[u8] = b"nix-0.26.4/src/sys/termios.rs";
pub const BOSMINER_NIX_TERMIOS_RS_FILE_OFF: u64 = 0x00F9_B584;
/// `open/utils-rs/serial-driver/src/antminer_aml.rs` — host tty speed, not chip.
pub const BOSMINER_ANTMINER_AML_RS_VA: u64 = 0x0139_2558;
/// `packed_struct-0.10.1/src/packing.rs` — generic Command packer crate.
/// : this is how bosminer builds set_config at runtime (no ASCII `set_config`).
pub const BOSMINER_PACKED_STRUCT_PACKING_RS_VA: u64 = 0x0131_BE45;
/// File offset of `values were not written correctly to register`.
pub const BOSMINER_WRITE_VERIFY_STR_FILE_OFF: u64 = 0x00F2_0197;
pub const BOSMINER_WRITE_VERIFY_STR_VA: u64 = 0x0132_0197;
/// `command.rs` packed_struct 4-byte value pack (alloc 4, bit fields 0x10/8/4).
/// : the only first-LOAD `BL` sites are inside `FUN_008b1b98` /
/// `FUN_008b2b34` (bm1398.rs loc table). Not an exclusive S19k AML packer.
pub const BOSMINER_PACKED_STRUCT_PACK_FN_VA: u64 = 0x008A_8D28;
/// Historical name.  loc table attributes this FN to
/// `bosminer-am2-s17/src/hashchain/bm1398.rs`, not `command.rs`.
pub const BOSMINER_COMMAND_RS_WRITE_FN_VA: u64 = 0x008B_1B98;
/// Same loc table as the write FN (`bm1398.rs`). 0 `BL` / 0 `B`.
pub const BOSMINER_BM1398_READ_FN_VA: u64 = 0x008B_2B34;
/// `BL FUN_008a8d28` sites: write+0x1e8, read+0x260, read+0x3b4.
pub const BOSMINER_PACK_BL_HITS: usize = 3;
pub const BOSMINER_PACK_BL_VA: [u64; 3] = [0x008B_1D80, 0x008B_2D94, 0x008B_2EE8];
pub const BOSMINER_WRITE_BL_HITS: usize = 0;
pub const BOSMINER_READ_FN_BL_HITS: usize = 0;
/// Second-LOAD rustc loc record: `fn` then filename `&str`.
pub const BOSMINER_WRITE_LOC_PTR_FILE_OFF: u64 = 0x015B_4590;
pub const BOSMINER_WRITE_LOC_PTR_VA: u64 = 0x019C_4590;
pub const BOSMINER_READ_LOC_PTR_FILE_OFF: u64 = 0x015B_46A8;
pub const BOSMINER_READ_LOC_PTR_VA: u64 = 0x019C_46A8;
pub const BOSMINER_BM1398_RS_LOC_STR: &[u8] =
    b"open/bosminer/bosminer-am2-s17/src/hashchain/bm1398.rs";
pub const BOSMINER_BM1398_RS_LOC_STR_FILE_OFF: u64 = 0x00F2_1135;
pub const BOSMINER_BM1398_RS_LOC_STR_VA: u64 = 0x0132_1135;
pub const BOSMINER_BM1398_RS_LOC_STR_LEN: u32 = 0x36;
/// : hashchain/bm1366.rs loc FNs. None `BL` PACK/WRITE/BE4.
pub const BOSMINER_BM1366_RS_LOC_STR: &[u8] =
    b"open/bosminer/bosminer-am2-s17/src/hashchain/bm1366.rs";
pub const BOSMINER_BM1366_RS_LOC_STR_FILE_OFF: u64 = 0x00F2_32F5;
pub const BOSMINER_BM1366_RS_LOC_STR_VA: u64 = 0x0132_32F5;
pub const BOSMINER_BM1366_RS_LOC_STR_LEN: u32 = 54;
/// First cluster method loc (`FUN_008dc828`) — not the large `0x916474` pad.
pub const BOSMINER_BM1366_FIRST_METHOD_FN_VA: u64 = 0x008D_C828;
pub const BOSMINER_BM1366_FIRST_METHOD_LOC_FILE_OFF: u64 = 0x015B_7EA8;
pub const BOSMINER_BM1366_LOC_FNS: [u64; 8] = [
    0x0091_6474,
    0x008D_C828,
    0x008D_CFBC,
    0x008D_D4C8,
    0x008D_D63C,
    0x008D_E274,
    0x008D_E430,
    0x008D_E984,
];
/// : `bm1366.rs:241` (`FUN_008de984`) packs chip reg `0x28` = `0x0006000F`.
pub const BOSMINER_BM1366_REG28_FN_VA: u64 = 0x008D_E984;
pub const BOSMINER_BM1366_REG28_LOC_LINE: u32 = 241;
pub const BOSMINER_BM1366_REG28_VALUE: u32 = 0x0006_000F;
pub const BOSMINER_BM1366_REG28_MOVZ_VA: u64 = 0x008D_F2B0;
pub const BOSMINER_BM1366_REG28_MOVZ_INSN: u32 = 0x5280_0500;
pub const BOSMINER_BM1366_REG28_VAL_MOVZ_VA: u64 = 0x008D_F2A8;
pub const BOSMINER_BM1366_REG28_VAL_MOVZ_INSN: u32 = 0x5280_01E1;
pub const BOSMINER_BM1366_REG28_VAL_MOVK_VA: u64 = 0x008D_F2B4;
pub const BOSMINER_BM1366_REG28_VAL_MOVK_INSN: u32 = 0x72A0_C001;
pub const BOSMINER_BM1366_REG28_BL_VA: u64 = 0x008D_F2B8;
pub const BOSMINER_BM1366_REG28_BL_INSN: u32 = 0x940C_4FF5;
pub const BOSMINER_BM1366_REG28_PACK_FN_VA: u64 = 0x00BF_328C;
pub const BOSMINER_BM1366_REG28_PACK_REV_VA: u64 = 0x00BF_32C0;
pub const BOSMINER_BM1366_REG28_PACK_REV_INSN: u32 = 0x5AC0_0AA8;
/// Clone of the same W0=0x28 / W1=0x0006000F / BL packer.
pub const BOSMINER_BM1366_REG28_CLONE_MOVZ_VA: u64 = 0x0084_64FC;
pub const BOSMINER_BM1366_REG28_CLONE_MOVZ_INSN: u32 = 0x5280_0500;
pub const BOSMINER_BM1366_REG28_CLONE_VAL_MOVK_VA: u64 = 0x0084_6500;
pub const BOSMINER_BM1366_REG28_CLONE_VAL_MOVK_INSN: u32 = 0x72A0_C001;
pub const BOSMINER_BM1366_REG28_CLONE_BL_VA: u64 = 0x0084_6504;
pub const BOSMINER_BM1366_REG28_CLONE_BL_INSN: u32 = 0x940E_B362;
pub const BOSMINER_BM1366_REG28_PACK_CALL_HITS: usize = 2;
pub const BOSMINER_BM1366_REG28_LOC_FILE_OFF: u64 = 0x015B_7FF8;
pub const BOSMINER_BM1366_REG28_LOC_COL: u32 = 64;
/// Packed-struct enum dispatch used by those methods (`LDRB [X0,#0x70]` + `BLR X8`).
pub const BOSMINER_BM1366_PACKED_DISPATCH_FN_VA: u64 = 0x008D_823C;
pub const BOSMINER_BM1366_PACKED_DISPATCH_LDRB_VA: u64 = 0x008D_8244;
pub const BOSMINER_BM1366_PACKED_DISPATCH_LDRB_INSN: u32 = 0x3941_C008;
pub const BOSMINER_BM1366_PACKED_DISPATCH_BLR_VA: u64 = 0x008D_826C;
pub const BOSMINER_BM1366_PACKED_DISPATCH_BLR_INSN: u32 = 0xD63F_0100;
/// Same `LDRB [X0,#0x70]` at the bm1398 packer entry+0xc.
pub const BOSMINER_PACK_LDRB_VA: u64 = 0x008A_8D34;
pub const BOSMINER_BM1366_DISPATCH_BL_HITS: usize = 48;
pub const BOSMINER_BM1366_DISPATCH_BL_IN_LOC_CLUSTER: usize = 39;
/// : `+0x70` tag. Only 3 and 4 are taken; other tags RET.
pub const BOSMINER_BM1366_DISPATCH_TAG_OFF: u8 = 0x70;
pub const BOSMINER_BM1366_DISPATCH_TAG3: u8 = 3;
pub const BOSMINER_BM1366_DISPATCH_TAG4: u8 = 4;
pub const BOSMINER_BM1366_DISPATCH_CMP3_VA: u64 = 0x008D_824C;
pub const BOSMINER_BM1366_DISPATCH_CMP3_INSN: u32 = 0x7100_0D1F;
pub const BOSMINER_BM1366_DISPATCH_BEQ3_VA: u64 = 0x008D_8250;
pub const BOSMINER_BM1366_DISPATCH_BEQ3_INSN: u32 = 0x5400_0220;
pub const BOSMINER_BM1366_DISPATCH_CMP4_VA: u64 = 0x008D_8254;
pub const BOSMINER_BM1366_DISPATCH_CMP4_INSN: u32 = 0x7100_111F;
/// Tag 4: `LDP X21, X20, [X19, #0x78]` fat pointer, then `LDR X8,[X20]` `BLR X8`.
pub const BOSMINER_BM1366_DISPATCH_LDP_VA: u64 = 0x008D_825C;
pub const BOSMINER_BM1366_DISPATCH_LDP_INSN: u32 = 0xA947_D275;
pub const BOSMINER_BM1366_DISPATCH_FAT_PTR_OFF: u8 = 0x78;
pub const BOSMINER_BM1366_DISPATCH_LDR_V0_VA: u64 = 0x008D_8260;
pub const BOSMINER_BM1366_DISPATCH_LDR_V0_INSN: u32 = 0xF940_0288;
/// Tag 3: `LDR X8, [X8, #0x18]` then `BLR X8` (`0x8d82d0`).
pub const BOSMINER_BM1366_DISPATCH_TAG3_SLOT_LDR_VA: u64 = 0x008D_82CC;
pub const BOSMINER_BM1366_DISPATCH_TAG3_SLOT_LDR_INSN: u32 = 0xF940_0D08;
pub const BOSMINER_BM1366_DISPATCH_TAG3_BLR_VA: u64 = 0x008D_82D0;
pub const BOSMINER_BM1366_DISPATCH_VTABLE_SLOT: u8 = 0x18;
/// `CBZ X1` then exclusive-load/atomic. Rust Arc/refcount, not UART.
pub const BOSMINER_DISPATCH_ARC_LIKE_FN_VA: u64 = 0x011F_2764;
pub const BOSMINER_DISPATCH_ARC_LIKE_CBZ_INSN: u32 = 0xB400_0241;
pub const BOSMINER_DISPATCH_DROP_GLUE_FN_VA: u64 = 0x005F_4A7C;
/// : one `+0x78` fat-ptr vtable installed by `FUN_008ddb0c`.
/// `drop=0`, `size=0x30`, `align=8`, method `+0x18` = `FUN_011de81c`.
pub const BOSMINER_FAT_PTR_VTABLE_VA: u64 = 0x019C_7900;
pub const BOSMINER_FAT_PTR_VTABLE_FILE_OFF: u64 = 0x015B_7900;
pub const BOSMINER_FAT_PTR_VTABLE_DROP: u64 = 0;
pub const BOSMINER_FAT_PTR_VTABLE_SIZE: u64 = 0x30;
pub const BOSMINER_FAT_PTR_VTABLE_ALIGN: u64 = 8;
pub const BOSMINER_FAT_PTR_VTABLE_METHOD_VA: u64 = 0x011D_E81C;
pub const BOSMINER_FAT_PTR_VTABLE_ADRP_VA: u64 = 0x008D_DB0C;
pub const BOSMINER_FAT_PTR_VTABLE_ADD_VA: u64 = 0x008D_DB10;
pub const BOSMINER_FAT_PTR_VTABLE_ADD_INSN: u32 = 0x9124_0129;
pub const BOSMINER_FAT_PTR_STP_VA: u64 = 0x008D_DB58;
pub const BOSMINER_FAT_PTR_STP_INSN: u32 = 0xA907_A67F;
pub const BOSMINER_PSU_PROTOCOL_RS: &[u8] =
    b"open/bosminer/bosminer-am2-s17/src/hardware/antminer/psu_protocol.rs";
pub const BOSMINER_PSU_PROTOCOL_RS_FILE_OFF: u64 = 0x00F2_31EE;
pub const BOSMINER_PSU_PROTOCOL_RS_VA: u64 = 0x0132_31EE;
/// `FUN_011de81c` head: `MOV X8,X0` then `BR X4` trampoline.
pub const BOSMINER_VTABLE_METHOD_MOV_INSN: u32 = 0xAA00_03E8;
pub const BOSMINER_VTABLE_METHOD_BR_VA: u64 = 0x011D_E834;
pub const BOSMINER_VTABLE_METHOD_BR_INSN: u32 = 0xD61F_0080;
/// `packing.rs` string adjacent to AML `command.rs` @ `0x131e720`.
pub const BOSMINER_AML_PACKING_RS_VA: u64 = 0x0131_E7BC;
/// `open/utils-rs/serial-driver/src/antminer_aml.rs` open path (exclusive AML host UART).
pub const BOSMINER_ANTMINER_AML_OPEN_FN_VA: u64 = 0x00BC_1F28;
/// Hashchain/session caller of that AML open.
pub const BOSMINER_AML_SERIAL_SESSION_FN_VA: u64 = 0x008F_8018;
/// : `FUN_008dfe6c` loc is `hashchain.rs:112:32`, not `psu_protocol.rs`.
pub const BOSMINER_HASHCHAIN_RS_LOC_STR: &[u8] =
    b"open/bosminer/bosminer-am2-s17/src/hashchain.rs";
pub const BOSMINER_HASHCHAIN_RS_LOC_STR_FILE_OFF: u64 = 0x00F2_3527;
pub const BOSMINER_HASHCHAIN_RS_LOC_STR_VA: u64 = 0x0132_3527;
pub const BOSMINER_HASHCHAIN_RS_LOC_STR_LEN: u32 = 0x2F;
pub const BOSMINER_HASHCHAIN_PLUS78_FN_VA: u64 = 0x008D_FE6C;
pub const BOSMINER_HASHCHAIN_PLUS78_LOC_FILE_OFF: u64 = 0x015B_83C8;
pub const BOSMINER_HASHCHAIN_PLUS78_LOC_LINE: u32 = 112;
pub const BOSMINER_HASHCHAIN_PLUS78_LOC_COL: u32 = 32;
/// `STP X8,X9,[X19,#0x78]` — data=`*(*(obj+0x20))+0x10`, meta=`obj+0x158`.
pub const BOSMINER_HASHCHAIN_PLUS78_STP_VA: u64 = 0x008D_FF48;
pub const BOSMINER_HASHCHAIN_PLUS78_STP_INSN: u32 = 0xA907_A668;
pub const BOSMINER_HASHCHAIN_PLUS78_INNER_LDR_VA: u64 = 0x008D_FF24;
pub const BOSMINER_HASHCHAIN_PLUS78_INNER_LDR_INSN: u32 = 0xF940_126C;
pub const BOSMINER_HASHCHAIN_PLUS78_DEREF_VA: u64 = 0x008D_FF34;
pub const BOSMINER_HASHCHAIN_PLUS78_DEREF_INSN: u32 = 0xF940_018A;
pub const BOSMINER_HASHCHAIN_PLUS78_ADD158_VA: u64 = 0x008D_FF3C;
pub const BOSMINER_HASHCHAIN_PLUS78_ADD158_INSN: u32 = 0x9105_6269;
pub const BOSMINER_HASHCHAIN_PLUS78_ADD10_VA: u64 = 0x008D_FF44;
pub const BOSMINER_HASHCHAIN_PLUS78_ADD10_INSN: u32 = 0x9100_4148;
pub const BOSMINER_HASHCHAIN_PLUS78_INLINE_OFF: u16 = 0x158;
pub const BOSMINER_HASHCHAIN_PACKED_OBJ_OFF: u16 = 0x68;
pub const BOSMINER_HASHCHAIN_PACKED_X0_ADD_VA: u64 = 0x008D_FF4C;
pub const BOSMINER_HASHCHAIN_PACKED_X0_ADD_INSN: u32 = 0x9101_A260;
/// Sibling packed-tag helper: same `LDRB [X0,#0x70]`, CMP#2/#3.
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_FN_VA: u64 = 0x008D_5F9C;
/// `MOV X19,X0` so later `LDP [X19,#0x10]` is relative to the packed object.
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_MOV_X19_VA: u64 = 0x008D_5FAC;
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_MOV_X19_INSN: u32 = 0xAA00_03F3;
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_LDRB_VA: u64 = 0x008D_5FA8;
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_CMP2_VA: u64 = 0x008D_5FB4;
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_CMP2_INSN: u32 = 0x7100_091F;
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_CMP3_VA: u64 = 0x008D_5FBC;
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_LDP10_VA: u64 = 0x008D_5FD0;
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_LDP10_INSN: u32 = 0xA941_5A68;
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_BL_HITS: usize = 2;
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_BL_VA: [u64; 2] = [0x008D_F010, 0x008D_FF54];
pub const BOSMINER_HASHCHAIN_SIBLING_PACK_BL_INSN: u32 = 0x97FF_D812;
pub const BOSMINER_HASHCHAIN_DISPATCH_BL_VA: u64 = 0x008D_FF64;
pub const BOSMINER_HASHCHAIN_DISPATCH_BL_INSN: u32 = 0x97FF_E0B6;
/// : `bosminer-antminer` `bm139x.rs` legacy FastUartReg panic string.
pub const BOSMINER_LEGACY_FASTUART_FAIL_STR: &[u8] = b"BUG: Failed to build legacy FastUartReg";
pub const BOSMINER_LEGACY_FASTUART_FAIL_STR_FILE_OFF: u64 = 0x00F2_51D0;
pub const BOSMINER_LEGACY_FASTUART_FAIL_STR_VA: u64 = 0x0132_51D0;
pub const BOSMINER_BM139X_RS_LOC_STR: &[u8] =
    b"open/bosminer/bosminer-antminer/src/bm139x.rs";
pub const BOSMINER_BM139X_RS_LOC_STR_FILE_OFF: u64 = 0x00F2_51A3;
pub const BOSMINER_BM139X_RS_LOC_STR_VA: u64 = 0x0132_51A3;
pub const BOSMINER_BM139X_RS_LOC_STR_LEN: u32 = 0x2D;
/// Cold panic stub. `ADRP`+`ADD #0x1d0` is the only former of the fail string.
pub const BOSMINER_LEGACY_FASTUART_PANIC_FN_VA: u64 = 0x0091_AFE8;
pub const BOSMINER_LEGACY_FASTUART_PANIC_ADRP_VA: u64 = 0x0091_AFF4;
pub const BOSMINER_LEGACY_FASTUART_PANIC_ADD_VA: u64 = 0x0091_AFF8;
pub const BOSMINER_LEGACY_FASTUART_PANIC_ADD_INSN: u32 = 0x9107_4000;
///  name. : this VA is the **divisor** leaf, not the field packer.
pub const BOSMINER_LEGACY_FASTUART_PACK_FN_VA: u64 = 0x0091_AF14;
/// `FUN_0091af14`: baud-divisor math. 0 static `BL`. `LDRB [X0,#7/8/9]` then `UDIV`.
pub const BOSMINER_LEGACY_FASTUART_DIV_FN_VA: u64 = 0x0091_AF14;
pub const BOSMINER_LEGACY_FASTUART_DIV_LDRB7_INSN: u32 = 0x3940_1C08;
pub const BOSMINER_LEGACY_FASTUART_DIV_LSR24_VA: u64 = 0x0091_AF30;
pub const BOSMINER_LEGACY_FASTUART_DIV_LSR24_INSN: u32 = 0x5318_7C2B;
pub const BOSMINER_LEGACY_FASTUART_DIV_CMP255_VA: u64 = 0x0091_AF34;
pub const BOSMINER_LEGACY_FASTUART_DIV_CMP255_INSN: u32 = 0x7103_FD7F;
pub const BOSMINER_LEGACY_FASTUART_DIV_UDIV_RET_VA: u64 = 0x0091_AF54;
pub const BOSMINER_LEGACY_FASTUART_DIV_UDIV_RET_INSN: u32 = 0x9AC9_0900;
pub const BOSMINER_LEGACY_FASTUART_DIV_BL_HITS: usize = 0;
/// Second-LOAD qword slot whose value is `FUN_0091af14`. Neighbors are DATA, not `.text`.
pub const BOSMINER_LEGACY_FASTUART_DIV_FPTR_FILE_OFF: u64 = 0x016B_E820;
pub const BOSMINER_LEGACY_FASTUART_DIV_FPTR_VA: u64 = 0x01AC_E820;
pub const BOSMINER_LEGACY_FASTUART_DIV_FPTR_PREV: u64 = 0x01AE_5350;
pub const BOSMINER_LEGACY_FASTUART_DIV_FPTR_NEXT: u64 = 0x01AE_4948;
/// : `LDP X0,X8,[X8]` then the same pair is stored at `+0x78` and `+0x88`.
pub const BOSMINER_HASHCHAIN_DUP78_LDP_VA: u64 = 0x008D_3A78;
pub const BOSMINER_HASHCHAIN_DUP78_LDP_INSN: u32 = 0xA940_2100;
pub const BOSMINER_HASHCHAIN_DUP78_STP_VA: u64 = 0x008D_3A7C;
pub const BOSMINER_HASHCHAIN_DUP78_STP_INSN: u32 = 0xA907_A260;
pub const BOSMINER_HASHCHAIN_DUP88_STP_VA: u64 = 0x008D_3A80;
pub const BOSMINER_HASHCHAIN_DUP88_STP_INSN: u32 = 0xA908_A260;
/// `STP X0,X1,[X19,#0x78]` after a `BLR` in the same cluster (Result/fat-ptr consume).
pub const BOSMINER_HASHCHAIN_BLR78_STP_VA: u64 = 0x008D_54F4;
pub const BOSMINER_HASHCHAIN_BLR78_STP_INSN: u32 = 0xA907_8660;
/// : seven byte-identical clones `MOV X0,X21; BLR X8; STP X0,X1,[X19,#0x78]`.
pub const BOSMINER_HASHCHAIN_BLR78_FAMILY_HITS: usize = 7;
pub const BOSMINER_HASHCHAIN_BLR78_MOV_INSN: u32 = 0xAA15_03E0;
pub const BOSMINER_HASHCHAIN_BLR78_BLR_INSN: u32 = 0xD63F_0100;
pub const BOSMINER_HASHCHAIN_BLR78_FAMILY_VA: [u64; 7] = [
    0x008D_54F4,
    0x008D_57D8,
    0x008D_5AD8,
    0x008D_5DEC,
    0x008D_60E8,
    0x008D_641C,
    0x008D_66B4,
];
/// Field packer leaf. Sole static `BL` is bm1398 write `@ 0x8b20fc`.
pub const BOSMINER_LEGACY_FASTUART_FIELDS_FN_VA: u64 = 0x0091_AF6C;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_UBFX_INSN: u32 = 0x5303_1009;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CMP1_VA: u64 = 0x0091_AF70;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CMP1_INSN: u32 = 0x7100_053F;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_BL_VA: u64 = 0x008B_20FC;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_BL_INSN: u32 = 0x9401_A39C;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0_VA: u64 = 0x008B_20F0;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0_INSN: u32 = 0x5280_00C0;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0: u32 = 6;
/// : sole caller also `MOVZ W2,#0x80` / `MOVZ W3,#0xF` (`FUN_008b1b98`).
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2_VA: u64 = 0x008B_20F4;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2_INSN: u32 = 0x5280_1002;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2: u32 = 0x80;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W3_VA: u64 = 0x008B_20F8;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W3_INSN: u32 = 0x5280_01E3;
pub const BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W3: u32 = 0x0F;
/// W1 is `LDRB [*(obj+8),#0x22c]; SUB #1`, not an immediate.
pub const BOSMINER_LEGACY_FASTUART_W1_LDR8_VA: u64 = 0x008B_20E0;
pub const BOSMINER_LEGACY_FASTUART_W1_LDR8_INSN: u32 = 0xF940_0668;
pub const BOSMINER_LEGACY_FASTUART_W1_LDRB_VA: u64 = 0x008B_20E4;
pub const BOSMINER_LEGACY_FASTUART_W1_LDRB_INSN: u32 = 0x3948_B108;
pub const BOSMINER_LEGACY_FASTUART_W1_SUB1_VA: u64 = 0x008B_20E8;
pub const BOSMINER_LEGACY_FASTUART_W1_SUB1_INSN: u32 = 0x5100_0501;
pub const BOSMINER_LEGACY_FASTUART_W1_LDRB_OFF: u16 = 0x22C;
/// : sibling `FUN_008b24b8` loads the same `+0x22c` byte from `X0`.
pub const BOSMINER_FASTUART_22C_SIBLING_FN_VA: u64 = 0x008B_24B8;
pub const BOSMINER_FASTUART_22C_SIBLING_LDRB_VA: u64 = 0x008B_24DC;
pub const BOSMINER_FASTUART_22C_SIBLING_LDRB_INSN: u32 = 0x3948_B009;
pub const BOSMINER_FASTUART_22C_XTAL_MOVZ_VA: u64 = 0x008B_24F0;
pub const BOSMINER_FASTUART_22C_XTAL_MOVZ_INSN: u32 = 0x528F_0801;
pub const BOSMINER_FASTUART_22C_XTAL_MOVK_VA: u64 = 0x008B_24F4;
pub const BOSMINER_FASTUART_22C_XTAL_MOVK_INSN: u32 = 0x72A0_2FA1;
pub const BOSMINER_FASTUART_22C_XTAL_HZ: u32 = 25_000_000;
pub const BOSMINER_FASTUART_22C_LDRB_HITS: usize = 12;
/// `25_000_000 / 8 = 3_125_000`. Not Track-1 host `3_000_000`.
pub const BOSMINER_FASTUART_22C_: u8 = 8;
/// `UBFIZ W13,W0,#4,#2` then `BFXIL W13,W1,#4,#4`. Dest byte 5 stores W13.
pub const BOSMINER_LEGACY_FASTUART_W13_UBFIZ_VA: u64 = 0x0091_AF84;
pub const BOSMINER_LEGACY_FASTUART_W13_UBFIZ_INSN: u32 = 0x531C_040D;
pub const BOSMINER_LEGACY_FASTUART_W13_BFXIL_VA: u64 = 0x0091_AFA4;
pub const BOSMINER_LEGACY_FASTUART_W13_BFXIL_INSN: u32 = 0x3304_1C2D;
pub const BOSMINER_LEGACY_FASTUART_STRB_5_VA: u64 = 0x0091_AFD4;
pub const BOSMINER_LEGACY_FASTUART_STRB_5_INSN: u32 = 0x3900_150D;
/// packed_struct dest offsets written by `FUN_0091af6c` (14 bytes).
pub const BOSMINER_LEGACY_FASTUART_DEST_W2_OFF: usize = 0;
pub const BOSMINER_LEGACY_FASTUART_DEST_W13_OFF: usize = 5;
pub const BOSMINER_LEGACY_FASTUART_DEST_ENUM_OFF: usize = 0x0C;
/// rustc names at `BOSMINER_FASTUART_FIELDS_STR_VA`. Not dest-byte labels.
pub const BOSMINER_FASTUART_FIELDS_STR: &[u8] = b"unknown_bits_31_28";
pub const BOSMINER_FASTUART_FIELDS_STR_FILE_OFF: u64 = 0x00F2_0C4B;
pub const BOSMINER_FASTUART_EXT_BAUD_ENABLE_STR: &[u8] = b"ext_baud_enable";
/// : rustc concatenated FastUartReg names (no NUL). Widths only
/// from identifiers that include a bit range. `rfs`/`tfs` width unbound.
pub const BOSMINER_FASTUART_NAMED_BIT_BLOB: &[u8] =
    b"unknown_bits_31_28unknown_bits_27_23unknown_bit_22unknown_bits_21_17\
ext_baud_enableunknown_bit_15rfsunknown_bit_13unknown_bit_7_reserved_bit_6tfs";
pub const BOSMINER_FASTUART_BIT76_STR: &[u8] = b"unknown_bit_7_reserved_bit_6";
pub const BOSMINER_FASTUART_RFS_STR: &[u8] = b"rfs";
pub const BOSMINER_FASTUART_TFS_STR: &[u8] = b"tfs";
pub const BOSMINER_FASTUART_EXT_BAUD_ENABLE_BIT: u32 = 16;
pub const BOSMINER_FASTUART_NAMED_BIT_15: u32 = 15;
pub const BOSMINER_FASTUART_NAMED_BIT_13: u32 = 13;
pub const BOSMINER_FASTUART_NAMED_BITS_31_28_SHIFT: u32 = 28;
pub const BOSMINER_FASTUART_NAMED_BITS_27_23_SHIFT: u32 = 23;
pub const BOSMINER_FASTUART_NAMED_BIT_22: u32 = 22;
pub const BOSMINER_FASTUART_NAMED_BITS_21_17_SHIFT: u32 = 17;
pub const BOSMINER_FASTUART_NAMED_BITS_7_6_SHIFT: u32 = 6;
/// : `STR Xt,[X19,#0x88]` of `*(obj+0x30)+0x18`. Not engine nonce `.text`.
pub const BOSMINER_NESTED88_HITS: usize = 2;
pub const BOSMINER_NESTED88_STR_VA: [u64; 2] = [0x008B_27EC, 0x008D_EA60];
pub const BOSMINER_NESTED88_STR_INSN: [u32; 2] = [0xF900_466A, 0xF900_4668];
pub const BOSMINER_NESTED88_LDR30_VA: [u64; 2] = [0x008B_27D0, 0x008D_EA3C];
pub const BOSMINER_NESTED88_LDR30_INSN: u32 = 0xF940_1A6A;
pub const BOSMINER_NESTED88_ADD18_VA: [u64; 2] = [0x008B_27E0, 0x008D_EA54];
pub const BOSMINER_NESTED88_ADD18_INSN: [u32; 2] = [0x9100_614A, 0x9100_6148];
pub const BOSMINER_NESTED88_ADD_IMM: u16 = 0x18;
pub const BOSMINER_LEGACY_FASTUART_PACKED_LEN: usize = 0x0E;
pub const BOSMINER_LEGACY_FASTUART_STRH0_VA: u64 = 0x0091_AFD0;
pub const BOSMINER_LEGACY_FASTUART_STRH0_INSN: u32 = 0x7900_010E;
pub const BOSMINER_LEGACY_FASTUART_STRB_C_VA: u64 = 0x0091_AF8C;
pub const BOSMINER_LEGACY_FASTUART_STRB_C_INSN: u32 = 0x3900_3109;
pub const BOSMINER_LEGACY_FASTUART_STRB_D_VA: u64 = 0x0091_AFE0;
pub const BOSMINER_LEGACY_FASTUART_STRB_D_INSN: u32 = 0x3900_350B;
/// DATA pin length: `28 00 00 00` + BE low-16. Not [`BOSMINER_LEGACY_FASTUART_PACKED_LEN`].
pub const BOSMINER_REG28_FASTUART_DATA_LEN: usize = 6;
pub const BOSMINER_LEGACY_FASTUART_PACK_BEQ_VA: u64 = 0x0091_AF74;
pub const BOSMINER_LEGACY_FASTUART_PACK_BEQ_INSN: u32 = 0x5400_03A0;
pub const BOSMINER_LEGACY_FASTUART_PACK_RET_VA: u64 = 0x0091_AFE4;
pub const BOSMINER_LEGACY_FASTUART_PACK_RET_INSN: u32 = 0xD65F_03C0;
/// rustc loc `bm139x.rs:659:26` next to the fail string.
pub const BOSMINER_BM139X_FASTUART_LOC_FILE_OFF: u64 = 0x015B_A080;
pub const BOSMINER_BM139X_FASTUART_LOC_LINE: u32 = 659;
pub const BOSMINER_BM139X_FASTUART_LOC_COL: u32 = 26;
/// Parallel constructor: packed at `+0x30`, fat ptr at `+0x40`, inline `+0x120`.
pub const BOSMINER_HASHCHAIN_ALT_PACKED_OFF: u16 = 0x30;
pub const BOSMINER_HASHCHAIN_ALT_FAT_OFF: u16 = 0x40;
pub const BOSMINER_HASHCHAIN_ALT_INLINE_OFF: u16 = 0x120;
pub const BOSMINER_HASHCHAIN_ALT_STP_VA: u64 = 0x008D_F004;
pub const BOSMINER_HASHCHAIN_ALT_STP_INSN: u32 = 0xA904_2668;

/// AML host UART open is not a chip set_config packer.
pub fn refuse_bosminer_aml_open_as_set_config() -> Result<(), &'static str> {
    Err("FUN_00bc1f28 is antminer_aml.rs serial open; not chip set_config")
}

/// Byte-presence pin only. Does not prove the write path.
pub fn admit_bosminer_contains_s19k_hcn_be(blob: &[u8]) -> Result<(), &'static str> {
    let off = BOSMINER_115A_BE_FILE_OFF as usize;
    if blob.len() < off + 4 {
        return Err("bosminer blob shorter than 0x115A BE pin");
    }
    if &blob[off..off + 4] != &[0x00, 0x00, 0x11, 0x5A] {
        return Err("bosminer file 0x15920A6 is not BE 0000115A");
    }
    Ok(())
}

///  inference that this pin is the HCN UART writer is **false**.
pub fn refuse_bosminer_115a_file_pin_as_hcn_writer() -> Result<(), &'static str> {
    Err(
        "bosminer 00 00 11 5A @ file 0x15920A6 / VA 0x19A20A6 xrefs FUN_0065f830 tuner; not a reg 0x10 writer",
    )
}

/// : the HCN-divider log FN is not the UART HCN writer either.
pub fn refuse_bosminer_hcn_divider_log_as_reg10_writer() -> Result<(), &'static str> {
    Err(
        "FUN_008434e0 logs 12.5 MHz/freq work-time; not a UART set_config(0x10) writer",
    )
}

/// : telemetry field name, not a UART packer.
pub fn refuse_bosminer_hash_counting_number_string_as_hcn_writer() -> Result<(), &'static str> {
    Err(
        "hash_counting_number @ VA 0x139db65 xrefs FUN_0041ea18 metrics registrar; not UART reg 0x10",
    )
}

pub fn refuse_bosminer_ticket_mask_serde_as_uart_writer() -> Result<(), &'static str> {
    Err("FUN_0086f5e0 is serde TicketMaskReg; not a UART ticket-mask writer")
}

/// : `MOVZ #0x51` is not the set_config packer.
pub fn refuse_bosminer_movz51_as_set_config_packer() -> Result<(), &'static str> {
    Err(
        "33 MOVZ Wd,#0x51 are alloc/panic/serde (FUN_008c4bfc 0x51-byte VoltageController); not UART 0x51",
    )
}

/// HCN UART write is generic set_config(reg=0x10), not a dedicated bosminer FN.
pub fn s19k_hcn_set_config_uart() -> [u8; 11] {
    pack_experimental_init_write(*HASH_COUNTING_BCAST_WRITE)
}

/// : AM2 `FUN_008a200c` is not the S19k AML set_config packer.
pub fn refuse_bosminer_be4_send_as_s19k_set_config() -> Result<(), &'static str> {
    Err(
        "FUN_008a200c callers are AM2 S17 set-baud + MiscCtrl (bm1398.rs); not S19k AML set_config",
    )
}

fn le_u64_at(blob: &[u8], off: u64) -> Option<u64> {
    let i = off as usize;
    blob.get(i..i + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
}

/// Loc table at `0x19c4590`: `FUN_008b1b98` + `bm1398.rs` (len 0x36). Not a vtable.
pub fn admit_bosminer_write_loc_is_bm1398_rs(blob: &[u8]) -> Result<(), &'static str> {
    let fn_ptr = le_u64_at(blob, BOSMINER_WRITE_LOC_PTR_FILE_OFF)
        .ok_or("bosminer shorter than write loc ptr")?;
    if fn_ptr != BOSMINER_COMMAND_RS_WRITE_FN_VA {
        return Err("write loc qword is not FUN_008b1b98");
    }
    let str_va = le_u64_at(blob, BOSMINER_WRITE_LOC_PTR_FILE_OFF + 8)
        .ok_or("bosminer shorter than write loc str")?;
    if str_va != BOSMINER_BM1398_RS_LOC_STR_VA {
        return Err("write loc filename VA is not bm1398.rs");
    }
    let str_len = le_u64_at(blob, BOSMINER_WRITE_LOC_PTR_FILE_OFF + 16)
        .ok_or("bosminer shorter than write loc len")?;
    if str_len != u64::from(BOSMINER_BM1398_RS_LOC_STR_LEN) {
        return Err("write loc filename len is not 0x36");
    }
    let s_off = BOSMINER_BM1398_RS_LOC_STR_FILE_OFF as usize;
    let want = BOSMINER_BM1398_RS_LOC_STR;
    if blob.get(s_off..s_off + want.len()) != Some(want) {
        return Err("file 0xf21135 is not bosminer-am2-s17 hashchain/bm1398.rs");
    }
    Ok(())
}

/// Same loc filename as the write FN.
pub fn admit_bosminer_read_loc_is_bm1398_rs(blob: &[u8]) -> Result<(), &'static str> {
    let fn_ptr = le_u64_at(blob, BOSMINER_READ_LOC_PTR_FILE_OFF)
        .ok_or("bosminer shorter than read loc ptr")?;
    if fn_ptr != BOSMINER_BM1398_READ_FN_VA {
        return Err("read loc qword is not FUN_008b2b34");
    }
    let str_va = le_u64_at(blob, BOSMINER_READ_LOC_PTR_FILE_OFF + 8)
        .ok_or("bosminer shorter than read loc str")?;
    if str_va != BOSMINER_BM1398_RS_LOC_STR_VA {
        return Err("read loc filename VA is not bm1398.rs");
    }
    Ok(())
}

/// 3 `BL` to the 4-byte packer, all inside the bm1398 write/read bodies.
pub fn admit_bosminer_pack_bl_sites() -> Result<(), &'static str> {
    if BOSMINER_PACK_BL_HITS != 3 {
        return Err("pack BL census drifted");
    }
    if BOSMINER_PACK_BL_VA[0] != BOSMINER_COMMAND_RS_WRITE_FN_VA + 0x1E8 {
        return Err("first pack BL is not WRITE+0x1e8");
    }
    if BOSMINER_PACK_BL_VA[1] != BOSMINER_BM1398_READ_FN_VA + 0x260 {
        return Err("second pack BL is not READ+0x260");
    }
    if BOSMINER_PACK_BL_VA[2] != BOSMINER_BM1398_READ_FN_VA + 0x3B4 {
        return Err("third pack BL is not READ+0x3b4");
    }
    Ok(())
}

///  named this command.rs. Loc table is bm1398.rs. Not S19k AML.
pub fn refuse_command_rs_write_as_s19k_aml_set_config() -> Result<(), &'static str> {
    Err(
        "FUN_008b1b98 loc is bosminer-am2-s17 hashchain/bm1398.rs; 0 BL; not S19k AML set_config",
    )
}

/// Pack helper is only BL-called from that bm1398 write/read pair.
pub fn refuse_pack_fn_as_s19k_exclusive_set_config() -> Result<(), &'static str> {
    Err(
        "FUN_008a8d28 has 3 BL (WRITE+0x1e8 / READ+0x260 / READ+0x3b4) in bm1398.rs; not S19k AML exclusive",
    )
}

/// The DATA qword is a rustc loc record, not a dispatch vtable.
pub fn refuse_write_loc_ptr_as_aml_vtable() -> Result<(), &'static str> {
    Err(
        "u64 @ 0x19c4590 is fn+bm1398.rs loc (len 0x36); not an AML write_reg vtable",
    )
}

fn first_load_off(va: u64) -> Option<usize> {
    va.checked_sub(0x400_000).map(|o| o as usize)
}

fn le_u32_at(blob: &[u8], va: u64) -> Option<u32> {
    let i = first_load_off(va)?;
    blob.get(i..i + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
}

/// Loc table for the first hashchain/bm1366.rs method (`FUN_008dc828`).
pub fn admit_bosminer_bm1366_first_method_loc(blob: &[u8]) -> Result<(), &'static str> {
    let s_off = BOSMINER_BM1366_RS_LOC_STR_FILE_OFF as usize;
    let want = BOSMINER_BM1366_RS_LOC_STR;
    if blob.get(s_off..s_off + want.len()) != Some(want) {
        return Err("file 0xf232f5 is not hashchain/bm1366.rs");
    }
    let fn_ptr = le_u64_at(blob, BOSMINER_BM1366_FIRST_METHOD_LOC_FILE_OFF)
        .ok_or("bosminer shorter than bm1366 first-method loc")?;
    if fn_ptr != BOSMINER_BM1366_FIRST_METHOD_FN_VA {
        return Err("bm1366 first-method loc qword is not FUN_008dc828");
    }
    let str_va = le_u64_at(blob, BOSMINER_BM1366_FIRST_METHOD_LOC_FILE_OFF + 8)
        .ok_or("bosminer shorter than bm1366 loc str")?;
    if str_va != BOSMINER_BM1366_RS_LOC_STR_VA {
        return Err("bm1366 loc filename VA mismatch");
    }
    let str_len = le_u64_at(blob, BOSMINER_BM1366_FIRST_METHOD_LOC_FILE_OFF + 16)
        .ok_or("bosminer shorter than bm1366 loc len")?;
    if str_len != u64::from(BOSMINER_BM1366_RS_LOC_STR_LEN) {
        return Err("bm1366 loc filename len is not 54");
    }
    Ok(())
}

/// `FUN_008d823c` shares PACK's `LDRB [X0,#0x70]` then `BLR X8`.
pub fn admit_bosminer_bm1366_packed_dispatch(blob: &[u8]) -> Result<(), &'static str> {
    let ldrb = le_u32_at(blob, BOSMINER_BM1366_PACKED_DISPATCH_LDRB_VA)
        .ok_or("bosminer shorter than dispatch LDRB")?;
    if ldrb != BOSMINER_BM1366_PACKED_DISPATCH_LDRB_INSN {
        return Err("FUN_008d823c+8 is not LDRB W8,[X0,#0x70]");
    }
    let pack_ldrb = le_u32_at(blob, BOSMINER_PACK_LDRB_VA).ok_or("bosminer shorter than pack LDRB")?;
    if pack_ldrb != BOSMINER_BM1366_PACKED_DISPATCH_LDRB_INSN {
        return Err("FUN_008a8d28+0xc is not the same LDRB [X0,#0x70]");
    }
    let blr = le_u32_at(blob, BOSMINER_BM1366_PACKED_DISPATCH_BLR_VA)
        .ok_or("bosminer shorter than dispatch BLR")?;
    if blr != BOSMINER_BM1366_PACKED_DISPATCH_BLR_INSN {
        return Err("FUN_008d823c+0x30 is not BLR X8");
    }
    Ok(())
}

/// Hashchain/bm1366.rs methods do not `BL` the bm1398 pack/write/send FNs.
pub fn refuse_bm1366_loc_fns_as_direct_pack_callers() -> Result<(), &'static str> {
    Err(
        "8 hashchain/bm1366.rs loc FNs have 0 BL to PACK/WRITE/BE4; they BLR via FUN_008d823c",
    )
}

/// The dispatch is enum/vtable, not a named FastUART 51 09 00 28 writer.
pub fn refuse_bm1366_packed_dispatch_as_named_fastuart() -> Result<(), &'static str> {
    Err(
        "FUN_008d823c is packed_struct LDRB#0x70 + BLR X8 (48 BL, 39 in bm1366 cluster); not a static FastUART set_config",
    )
}

/// Tag at `+0x70` is 3 or 4. `B.EQ` tag3 / `CMP #4` encodings.
pub fn admit_bosminer_dispatch_tag_3_or_4(blob: &[u8]) -> Result<(), &'static str> {
    let cmp3 = le_u32_at(blob, BOSMINER_BM1366_DISPATCH_CMP3_VA)
        .ok_or("bosminer shorter than dispatch CMP#3")?;
    if cmp3 != BOSMINER_BM1366_DISPATCH_CMP3_INSN {
        return Err("FUN_008d824c is not CMP W8,#3");
    }
    let beq = le_u32_at(blob, BOSMINER_BM1366_DISPATCH_BEQ3_VA)
        .ok_or("bosminer shorter than dispatch B.EQ")?;
    if beq != BOSMINER_BM1366_DISPATCH_BEQ3_INSN {
        return Err("FUN_008d8250 is not B.EQ tag3");
    }
    let cmp4 = le_u32_at(blob, BOSMINER_BM1366_DISPATCH_CMP4_VA)
        .ok_or("bosminer shorter than dispatch CMP#4")?;
    if cmp4 != BOSMINER_BM1366_DISPATCH_CMP4_INSN {
        return Err("FUN_008d8254 is not CMP W8,#4");
    }
    Ok(())
}

/// Tag 4 `BLR X8` is `vtable[0]` of the fat pointer at `[obj+0x78]`.
pub fn admit_bosminer_blr_x8_is_fat_ptr_vtable0(blob: &[u8]) -> Result<(), &'static str> {
    let ldp = le_u32_at(blob, BOSMINER_BM1366_DISPATCH_LDP_VA)
        .ok_or("bosminer shorter than dispatch LDP")?;
    if ldp != BOSMINER_BM1366_DISPATCH_LDP_INSN {
        return Err("FUN_008d825c is not LDP X21,X20,[X19,#0x78]");
    }
    let ldr = le_u32_at(blob, BOSMINER_BM1366_DISPATCH_LDR_V0_VA)
        .ok_or("bosminer shorter than dispatch LDR vtable0")?;
    if ldr != BOSMINER_BM1366_DISPATCH_LDR_V0_INSN {
        return Err("FUN_008d8260 is not LDR X8,[X20]");
    }
    let blr = le_u32_at(blob, BOSMINER_BM1366_PACKED_DISPATCH_BLR_VA)
        .ok_or("bosminer shorter than dispatch BLR")?;
    if blr != BOSMINER_BM1366_PACKED_DISPATCH_BLR_INSN {
        return Err("FUN_008d826c is not BLR X8");
    }
    Ok(())
}

/// Tag 3 `BLR X8` is `vtable[+0x18]` loaded from `[obj+0xa8]`.
pub fn admit_bosminer_tag3_blr_is_vtable_plus18(blob: &[u8]) -> Result<(), &'static str> {
    let ldr = le_u32_at(blob, BOSMINER_BM1366_DISPATCH_TAG3_SLOT_LDR_VA)
        .ok_or("bosminer shorter than tag3 LDR #0x18")?;
    if ldr != BOSMINER_BM1366_DISPATCH_TAG3_SLOT_LDR_INSN {
        return Err("FUN_008d82cc is not LDR X8,[X8,#0x18]");
    }
    let blr = le_u32_at(blob, BOSMINER_BM1366_DISPATCH_TAG3_BLR_VA)
        .ok_or("bosminer shorter than tag3 BLR")?;
    if blr != BOSMINER_BM1366_PACKED_DISPATCH_BLR_INSN {
        return Err("FUN_008d82d0 is not BLR X8");
    }
    Ok(())
}

/// No unique .text VA for those `BLR`s. Do not name a write_reg callee.
pub fn refuse_blr_x8_as_named_text_write_reg() -> Result<(), &'static str> {
    Err(
        "BLR X8 is vtable[0] of [obj+0x78] (tag4) or vtable[+0x18] of [obj+0xa8] (tag3); runtime, not a unique .text write_reg",
    )
}

/// `FUN_011f2764` is CBZ+exclusive-load / refcount, not UART.
pub fn refuse_dispatch_arc_like_as_uart_write(blob: &[u8]) -> Result<(), &'static str> {
    let w = le_u32_at(blob, BOSMINER_DISPATCH_ARC_LIKE_FN_VA)
        .ok_or("bosminer shorter than 0x11f2764")?;
    if w != BOSMINER_DISPATCH_ARC_LIKE_CBZ_INSN {
        return Err("FUN_011f2764 does not start CBZ X1");
    }
    Err("FUN_011f2764 is CBZ X1 + exclusive-load/atomic (Arc/refcount); not UART write_reg")
}

/// `0x19c7900` is drop=0 / size=0x30 / align=8 / method=`FUN_011de81c`.
pub fn admit_bosminer_fat_ptr_vtable_layout(blob: &[u8]) -> Result<(), &'static str> {
    let off = BOSMINER_FAT_PTR_VTABLE_FILE_OFF;
    let drop = le_u64_at(blob, off).ok_or("bosminer shorter than fat-ptr vtable")?;
    if drop != BOSMINER_FAT_PTR_VTABLE_DROP {
        return Err("fat-ptr vtable[0] drop is not 0");
    }
    let size = le_u64_at(blob, off + 8).ok_or("bosminer shorter than fat-ptr size")?;
    if size != BOSMINER_FAT_PTR_VTABLE_SIZE {
        return Err("fat-ptr vtable size is not 0x30");
    }
    let align = le_u64_at(blob, off + 16).ok_or("bosminer shorter than fat-ptr align")?;
    if align != BOSMINER_FAT_PTR_VTABLE_ALIGN {
        return Err("fat-ptr vtable align is not 8");
    }
    let meth = le_u64_at(blob, off + 24).ok_or("bosminer shorter than fat-ptr method")?;
    if meth != BOSMINER_FAT_PTR_VTABLE_METHOD_VA {
        return Err("fat-ptr vtable[+0x18] is not FUN_011de81c");
    }
    Ok(())
}

/// Adjacent loc string is `psu_protocol.rs`, not hashchain/bm1366.rs.
pub fn admit_bosminer_fat_ptr_vtable_loc_is_psu_protocol(
    blob: &[u8],
) -> Result<(), &'static str> {
    let off = BOSMINER_PSU_PROTOCOL_RS_FILE_OFF as usize;
    let want = BOSMINER_PSU_PROTOCOL_RS;
    if blob.get(off..off + want.len()) != Some(want) {
        return Err("file 0xf231ee is not psu_protocol.rs");
    }
    Ok(())
}

/// `ADRP 0x19c7000` + `ADD #0x900` + `STP XZR,X9,[X19,#0x78]`.
pub fn admit_bosminer_fat_ptr_vtable_install(blob: &[u8]) -> Result<(), &'static str> {
    let add = le_u32_at(blob, BOSMINER_FAT_PTR_VTABLE_ADD_VA)
        .ok_or("bosminer shorter than fat-ptr ADD #0x900")?;
    if add != BOSMINER_FAT_PTR_VTABLE_ADD_INSN {
        return Err("FUN_008ddb10 is not ADD X9,X9,#0x900");
    }
    let stp = le_u32_at(blob, BOSMINER_FAT_PTR_STP_VA)
        .ok_or("bosminer shorter than fat-ptr STP")?;
    if stp != BOSMINER_FAT_PTR_STP_INSN {
        return Err("FUN_008ddb58 is not STP XZR,X9,[X19,#0x78]");
    }
    Ok(())
}

/// `FUN_011de81c` is `MOV X8,X0` / `BR X4` — a rustc trampoline, not UART.
pub fn refuse_vtable_method_as_uart_write_reg(blob: &[u8]) -> Result<(), &'static str> {
    let mov = le_u32_at(blob, BOSMINER_FAT_PTR_VTABLE_METHOD_VA)
        .ok_or("bosminer shorter than FUN_011de81c")?;
    if mov != BOSMINER_VTABLE_METHOD_MOV_INSN {
        return Err("FUN_011de81c does not start MOV X8,X0");
    }
    let br = le_u32_at(blob, BOSMINER_VTABLE_METHOD_BR_VA)
        .ok_or("bosminer shorter than FUN_011de81c BR")?;
    if br != BOSMINER_VTABLE_METHOD_BR_INSN {
        return Err("FUN_011de81c+0x18 is not BR X4");
    }
    Err(
        "FUN_011de81c is a rustc MOV/BR trampoline; fat-ptr vtable loc is psu_protocol.rs, not BM1366 FastUART",
    )
}

/// `FUN_008dfe6c` rustc loc is `hashchain.rs:112:32`.
pub fn admit_bosminer_plus78_fn_loc_is_hashchain_rs(blob: &[u8]) -> Result<(), &'static str> {
    let s_off = BOSMINER_HASHCHAIN_RS_LOC_STR_FILE_OFF as usize;
    let want = BOSMINER_HASHCHAIN_RS_LOC_STR;
    if blob.get(s_off..s_off + want.len()) != Some(want) {
        return Err("file 0xf23527 is not hashchain.rs");
    }
    if want != crate::s19k_braiins_job::BOSMINER_HASHCHAIN_RS.as_bytes() {
        return Err("hashchain.rs loc string drifted from BOSMINER_HASHCHAIN_RS");
    }
    let fn_ptr = le_u64_at(blob, BOSMINER_HASHCHAIN_PLUS78_LOC_FILE_OFF)
        .ok_or("bosminer shorter than hashchain +0x78 loc fn")?;
    if fn_ptr != BOSMINER_HASHCHAIN_PLUS78_FN_VA {
        return Err("hashchain +0x78 loc fn is not FUN_008dfe6c");
    }
    let str_va = le_u64_at(blob, BOSMINER_HASHCHAIN_PLUS78_LOC_FILE_OFF + 8)
        .ok_or("bosminer shorter than hashchain +0x78 loc str")?;
    if str_va != BOSMINER_HASHCHAIN_RS_LOC_STR_VA {
        return Err("hashchain +0x78 loc filename VA is not hashchain.rs");
    }
    let str_len = le_u64_at(blob, BOSMINER_HASHCHAIN_PLUS78_LOC_FILE_OFF + 16)
        .ok_or("bosminer shorter than hashchain +0x78 loc len")?;
    if str_len != u64::from(BOSMINER_HASHCHAIN_RS_LOC_STR_LEN) {
        return Err("hashchain +0x78 loc filename len is not 0x2f");
    }
    let line_col = le_u64_at(blob, BOSMINER_HASHCHAIN_PLUS78_LOC_FILE_OFF + 24)
        .ok_or("bosminer shorter than hashchain +0x78 line/col")?;
    let line = line_col as u32;
    let col = (line_col >> 32) as u32;
    if line != BOSMINER_HASHCHAIN_PLUS78_LOC_LINE {
        return Err("hashchain +0x78 loc line is not 112");
    }
    if col != BOSMINER_HASHCHAIN_PLUS78_LOC_COL {
        return Err("hashchain +0x78 loc col is not 32");
    }
    Ok(())
}

/// `0x8dff48` stores `(*(*(obj+0x20))+0x10, obj+0x158)`, not `0x19c7900`.
pub fn admit_bosminer_hashchain_plus78_operands(blob: &[u8]) -> Result<(), &'static str> {
    let inner = le_u32_at(blob, BOSMINER_HASHCHAIN_PLUS78_INNER_LDR_VA)
        .ok_or("bosminer shorter than hashchain LDR [X19,#0x20]")?;
    if inner != BOSMINER_HASHCHAIN_PLUS78_INNER_LDR_INSN {
        return Err("FUN_008dfe6c is missing LDR X12,[X19,#0x20]");
    }
    let deref = le_u32_at(blob, BOSMINER_HASHCHAIN_PLUS78_DEREF_VA)
        .ok_or("bosminer shorter than hashchain LDR [X12]")?;
    if deref != BOSMINER_HASHCHAIN_PLUS78_DEREF_INSN {
        return Err("FUN_008dfe6c is missing LDR X10,[X12]");
    }
    let add158 = le_u32_at(blob, BOSMINER_HASHCHAIN_PLUS78_ADD158_VA)
        .ok_or("bosminer shorter than hashchain ADD #0x158")?;
    if add158 != BOSMINER_HASHCHAIN_PLUS78_ADD158_INSN {
        return Err("FUN_008dfe6c is missing ADD X9,X19,#0x158");
    }
    let add10 = le_u32_at(blob, BOSMINER_HASHCHAIN_PLUS78_ADD10_VA)
        .ok_or("bosminer shorter than hashchain ADD #0x10")?;
    if add10 != BOSMINER_HASHCHAIN_PLUS78_ADD10_INSN {
        return Err("FUN_008dfe6c is missing ADD X8,X10,#0x10");
    }
    let stp = le_u32_at(blob, BOSMINER_HASHCHAIN_PLUS78_STP_VA)
        .ok_or("bosminer shorter than hashchain STP #0x78")?;
    if stp != BOSMINER_HASHCHAIN_PLUS78_STP_INSN {
        return Err("0x8dff48 is not STP X8,X9,[X19,#0x78]");
    }
    Ok(())
}

/// `FUN_008d5f9c` is the same packed `+0x70` tag family; tag<=2 uses `[X0+#0x10]`.
pub fn admit_bosminer_sibling_pack_tag_dispatch(blob: &[u8]) -> Result<(), &'static str> {
    let mov = le_u32_at(blob, BOSMINER_HASHCHAIN_SIBLING_PACK_MOV_X19_VA)
        .ok_or("bosminer shorter than sibling MOV X19,X0")?;
    if mov != BOSMINER_HASHCHAIN_SIBLING_PACK_MOV_X19_INSN {
        return Err("FUN_008d5f9c+0x10 is not MOV X19,X0");
    }
    let ldrb = le_u32_at(blob, BOSMINER_HASHCHAIN_SIBLING_PACK_LDRB_VA)
        .ok_or("bosminer shorter than sibling LDRB #0x70")?;
    if ldrb != BOSMINER_BM1366_PACKED_DISPATCH_LDRB_INSN {
        return Err("FUN_008d5f9c+0xc is not LDRB W8,[X0,#0x70]");
    }
    let cmp2 = le_u32_at(blob, BOSMINER_HASHCHAIN_SIBLING_PACK_CMP2_VA)
        .ok_or("bosminer shorter than sibling CMP#2")?;
    if cmp2 != BOSMINER_HASHCHAIN_SIBLING_PACK_CMP2_INSN {
        return Err("FUN_008d5f9c is not CMP W8,#2");
    }
    let cmp3 = le_u32_at(blob, BOSMINER_HASHCHAIN_SIBLING_PACK_CMP3_VA)
        .ok_or("bosminer shorter than sibling CMP#3")?;
    if cmp3 != BOSMINER_BM1366_DISPATCH_CMP3_INSN {
        return Err("FUN_008d5f9c is not CMP W8,#3");
    }
    let ldp10 = le_u32_at(blob, BOSMINER_HASHCHAIN_SIBLING_PACK_LDP10_VA)
        .ok_or("bosminer shorter than sibling LDP #0x10")?;
    if ldp10 != BOSMINER_HASHCHAIN_SIBLING_PACK_LDP10_INSN {
        return Err("FUN_008d5f9c tag<=2 is not LDP X8,X22,[X19,#0x10]");
    }
    if BOSMINER_HASHCHAIN_SIBLING_PACK_BL_HITS != 2 {
        return Err("sibling pack BL census drifted");
    }
    if BOSMINER_HASHCHAIN_SIBLING_PACK_BL_VA != [0x008D_F010, 0x008D_FF54] {
        return Err("sibling pack BL sites drifted");
    }
    Ok(())
}

/// After the `+0x78` store: `X0=self+0x68`, `BL FUN_008d5f9c`, then `BL FUN_008d823c`.
pub fn admit_bosminer_hashchain_plus78_calls_sibling_then_dispatch(
    blob: &[u8],
) -> Result<(), &'static str> {
    let add = le_u32_at(blob, BOSMINER_HASHCHAIN_PACKED_X0_ADD_VA)
        .ok_or("bosminer shorter than ADD X0,#0x68")?;
    if add != BOSMINER_HASHCHAIN_PACKED_X0_ADD_INSN {
        return Err("0x8dff4c is not ADD X0,X19,#0x68");
    }
    let bl_sib = le_u32_at(blob, BOSMINER_HASHCHAIN_SIBLING_PACK_BL_VA[1])
        .ok_or("bosminer shorter than BL FUN_008d5f9c")?;
    if bl_sib != BOSMINER_HASHCHAIN_SIBLING_PACK_BL_INSN {
        return Err("0x8dff54 is not BL FUN_008d5f9c");
    }
    let bl_disp = le_u32_at(blob, BOSMINER_HASHCHAIN_DISPATCH_BL_VA)
        .ok_or("bosminer shorter than BL FUN_008d823c")?;
    if bl_disp != BOSMINER_HASHCHAIN_DISPATCH_BL_INSN {
        return Err("0x8dff64 is not BL FUN_008d823c");
    }
    Ok(())
}

/// Parallel site: fat ptr at `+0x40` (= packed `+0x30` + `+0x10`), inline `+0x120`.
pub fn admit_bosminer_hashchain_alt_fat_ptr_pattern(blob: &[u8]) -> Result<(), &'static str> {
    let stp = le_u32_at(blob, BOSMINER_HASHCHAIN_ALT_STP_VA)
        .ok_or("bosminer shorter than alt STP #0x40")?;
    if stp != BOSMINER_HASHCHAIN_ALT_STP_INSN {
        return Err("0x8df004 is not STP X8,X9,[X19,#0x40]");
    }
    if BOSMINER_HASHCHAIN_ALT_PACKED_OFF + 0x10 != BOSMINER_HASHCHAIN_ALT_FAT_OFF {
        return Err("alt fat ptr is not packed+0x10");
    }
    if BOSMINER_HASHCHAIN_PACKED_OBJ_OFF + 0x10 != BOSMINER_BM1366_DISPATCH_FAT_PTR_OFF as u16 {
        return Err("0x8dff48 is not packed(+0x68)+0x10");
    }
    Ok(())
}

/// 's rodata vtable is a different store (`STP XZR,X9` @ `0x8ddb58`).
pub fn refuse_hashchain_plus78_as_psu_rodata_vtable() -> Result<(), &'static str> {
    Err(
        "0x8dff48 STP X8,X9,[X19,#0x78] is hashchain.rs:112 (inner+0x10, self+0x158); not 0x19c7900 psu_protocol vtable",
    )
}

/// Second qword is `ADD X9,X19,#0x158`, not a `.text` FastUART writer.
pub fn refuse_hashchain_plus78_second_as_text_fastuart() -> Result<(), &'static str> {
    Err(
        "0x8dff48 second qword is obj+0x158 inline buffer/metadata; not a named .text FastUART / write_reg",
    )
}

/// Fail string lives in `bosminer-antminer/src/bm139x.rs` rodata.
pub fn admit_bosminer_legacy_fastuart_fail_str(blob: &[u8]) -> Result<(), &'static str> {
    let off = BOSMINER_LEGACY_FASTUART_FAIL_STR_FILE_OFF as usize;
    let want = BOSMINER_LEGACY_FASTUART_FAIL_STR;
    if blob.get(off..off + want.len()) != Some(want) {
        return Err("file 0xf251d0 is not BUG: Failed to build legacy FastUartReg");
    }
    let rs = BOSMINER_BM139X_RS_LOC_STR_FILE_OFF as usize;
    if blob.get(rs..rs + BOSMINER_BM139X_RS_LOC_STR.len()) != Some(BOSMINER_BM139X_RS_LOC_STR) {
        return Err("file 0xf251a3 is not bosminer-antminer bm139x.rs");
    }
    Ok(())
}

/// rustc loc next to the fail string is `bm139x.rs:659:26`.
pub fn admit_bosminer_legacy_fastuart_loc_is_bm139x_rs(
    blob: &[u8],
) -> Result<(), &'static str> {
    let str_va = le_u64_at(blob, BOSMINER_BM139X_FASTUART_LOC_FILE_OFF)
        .ok_or("bosminer shorter than bm139x FastUart loc")?;
    if str_va != BOSMINER_BM139X_RS_LOC_STR_VA {
        return Err("FastUart loc filename VA is not bm139x.rs");
    }
    let str_len = le_u64_at(blob, BOSMINER_BM139X_FASTUART_LOC_FILE_OFF + 8)
        .ok_or("bosminer shorter than bm139x FastUart loc len")?;
    if str_len != u64::from(BOSMINER_BM139X_RS_LOC_STR_LEN) {
        return Err("bm139x.rs loc len is not 0x2d");
    }
    let line_col = le_u64_at(blob, BOSMINER_BM139X_FASTUART_LOC_FILE_OFF + 16)
        .ok_or("bosminer shorter than bm139x FastUart line/col")?;
    if line_col as u32 != BOSMINER_BM139X_FASTUART_LOC_LINE {
        return Err("bm139x FastUart loc line is not 659");
    }
    if (line_col >> 32) as u32 != BOSMINER_BM139X_FASTUART_LOC_COL {
        return Err("bm139x FastUart loc col is not 26");
    }
    Ok(())
}

/// `FUN_0091afe8` is the only `ADRP`+`ADD #0x1d0` former of the fail string.
pub fn admit_bosminer_legacy_fastuart_panic_former(blob: &[u8]) -> Result<(), &'static str> {
    let add = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_PANIC_ADD_VA)
        .ok_or("bosminer shorter than FastUart panic ADD")?;
    if add != BOSMINER_LEGACY_FASTUART_PANIC_ADD_INSN {
        return Err("FUN_0091afe8+0x10 is not ADD X0,X0,#0x1d0");
    }
    Ok(())
}

/// Packer `B.EQ` `@ 0x91af74` is the only branch into the panic stub.
pub fn admit_bosminer_legacy_fastuart_pack_beq_panic(blob: &[u8]) -> Result<(), &'static str> {
    let beq = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_PACK_BEQ_VA)
        .ok_or("bosminer shorter than FastUart pack B.EQ")?;
    if beq != BOSMINER_LEGACY_FASTUART_PACK_BEQ_INSN {
        return Err("0x91af74 is not B.EQ FUN_0091afe8");
    }
    let ret = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_PACK_RET_VA)
        .ok_or("bosminer shorter than FastUart pack RET")?;
    if ret != BOSMINER_LEGACY_FASTUART_PACK_RET_INSN {
        return Err("0x91afe4 is not RET");
    }
    Ok(())
}

/// The panic stub never transmits UART. It is a rustc cold path.
pub fn refuse_legacy_fastuart_panic_as_uart_write() -> Result<(), &'static str> {
    Err(
        "FUN_0091afe8 only materializes BUG: Failed to build legacy FastUartReg; 0 BL; not a write_reg",
    )
}

/// bm139x.rs FastUartReg is not Track-1 host 3_000_000 and not a packed 51 09 00 28.
pub fn refuse_legacy_fastuart_as_s19k_host_3m() -> Result<(), &'static str> {
    Err(
        "bm139x.rs legacy FastUartReg packer/panic is not Braiins S19k host 3_000_000 and not a static 51 09 00 28 writer",
    )
}

/// `FUN_0091af14` loads divisor bytes and returns `UDIV`; it does not store 0x3001.
pub fn admit_bosminer_legacy_fastuart_divisor_path(blob: &[u8]) -> Result<(), &'static str> {
    let ldrb = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_DIV_FN_VA + 4)
        .ok_or("bosminer shorter than divisor LDRB #7")?;
    if ldrb != BOSMINER_LEGACY_FASTUART_DIV_LDRB7_INSN {
        return Err("FUN_0091af14+4 is not LDRB W8,[X0,#7]");
    }
    let lsr = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_DIV_LSR24_VA)
        .ok_or("bosminer shorter than divisor LSR #24")?;
    if lsr != BOSMINER_LEGACY_FASTUART_DIV_LSR24_INSN {
        return Err("FUN_0091af14 is missing LSR W11,W1,#24");
    }
    let cmp = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_DIV_CMP255_VA)
        .ok_or("bosminer shorter than divisor CMP #255")?;
    if cmp != BOSMINER_LEGACY_FASTUART_DIV_CMP255_INSN {
        return Err("FUN_0091af14 is missing CMP W11,#255");
    }
    let udiv = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_DIV_UDIV_RET_VA)
        .ok_or("bosminer shorter than divisor UDIV")?;
    if udiv != BOSMINER_LEGACY_FASTUART_DIV_UDIV_RET_INSN {
        return Err("FUN_0091af14 return is not UDIV X0,X8,X9");
    }
    if BOSMINER_LEGACY_FASTUART_DIV_BL_HITS != 0 {
        return Err("divisor BL census drifted");
    }
    Ok(())
}

/// Field leaf starts `UBFX #3,#2` / `CMP #1`; stores a 14-byte map to `[X8]`.
pub fn admit_bosminer_legacy_fastuart_fields_layout(blob: &[u8]) -> Result<(), &'static str> {
    let ubfx = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_FIELDS_FN_VA)
        .ok_or("bosminer shorter than fields UBFX")?;
    if ubfx != BOSMINER_LEGACY_FASTUART_FIELDS_UBFX_INSN {
        return Err("FUN_0091af6c does not start UBFX W9,W0,#3,#2");
    }
    let cmp1 = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_FIELDS_CMP1_VA)
        .ok_or("bosminer shorter than fields CMP #1")?;
    if cmp1 != BOSMINER_LEGACY_FASTUART_FIELDS_CMP1_INSN {
        return Err("FUN_0091af70 is not CMP W9,#1");
    }
    let strh = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_STRH0_VA)
        .ok_or("bosminer shorter than fields STRH #0")?;
    if strh != BOSMINER_LEGACY_FASTUART_STRH0_INSN {
        return Err("0x91afd0 is not STRH W14,[X8,#0]");
    }
    let strc = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_STRB_C_VA)
        .ok_or("bosminer shorter than fields STRB #0xc")?;
    if strc != BOSMINER_LEGACY_FASTUART_STRB_C_INSN {
        return Err("0x91af8c is not STRB W9,[X8,#0xc]");
    }
    let strd = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_STRB_D_VA)
        .ok_or("bosminer shorter than fields STRB #0xd")?;
    if strd != BOSMINER_LEGACY_FASTUART_STRB_D_INSN {
        return Err("0x91afe0 is not STRB W11,[X8,#0xd]");
    }
    if BOSMINER_LEGACY_FASTUART_PACKED_LEN != 0x0E {
        return Err("FastUartReg packed_struct store map is not 14 bytes");
    }
    Ok(())
}

/// Sole static caller is `FUN_008b1b98` (bm1398.rs write) with `MOVZ W0,#6`.
pub fn admit_bosminer_legacy_fastuart_fields_caller(blob: &[u8]) -> Result<(), &'static str> {
    let bl = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_FIELDS_BL_VA)
        .ok_or("bosminer shorter than fields BL")?;
    if bl != BOSMINER_LEGACY_FASTUART_FIELDS_BL_INSN {
        return Err("0x8b20fc is not BL FUN_0091af6c");
    }
    let w0 = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0_VA)
        .ok_or("bosminer shorter than fields MOVZ W0,#6")?;
    if w0 != BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0_INSN {
        return Err("bm1398 write does not MOVZ W0,#6 before FastUartReg pack");
    }
    if BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0 != 6 {
        return Err("caller W0 immediate drifted");
    }
    Ok(())
}

/// DATA `28 00 00 00 30 01` is 6 bytes. Field packer writes 14 bytes to `[X8]`.
pub fn refuse_reg28_3001_as_legacy_fastuart_pack() -> Result<(), &'static str> {
    Err(
        "DATA 28 00 00 00 30 01 is a 6-byte reg+BE pin; FUN_0091af6c stores 14 packed_struct field bytes, not 0x00003001",
    )
}

/// Divisor `UDIV` return is a quotient, not bible FastUART 0x00003001.
pub fn refuse_legacy_fastuart_divisor_as_3001() -> Result<(), &'static str> {
    Err(
        "FUN_0091af14 returns UDIV X0,X8,X9 (bytes at +7/+8/+9); 0 BL; not DATA 0x00003001 / host 3M",
    )
}

/// Sole packer caller passes W0=6, not 0x3001 or 0x3011.
pub fn refuse_bm1398_pack_call_as_bible_3001() -> Result<(), &'static str> {
    Err(
        "0x8b20fc MOVZ W0,#6 then BL FUN_0091af6c; not bible 0x00003001 / 0x00003011 / S19k 3M",
    )
}

/// Second-LOAD slot `@ file 0x16be820` holds `FUN_0091af14`.
pub fn admit_bosminer_legacy_fastuart_div_fptr(blob: &[u8]) -> Result<(), &'static str> {
    let slot = le_u64_at(blob, BOSMINER_LEGACY_FASTUART_DIV_FPTR_FILE_OFF)
        .ok_or("bosminer shorter than divisor fptr slot")?;
    if slot != BOSMINER_LEGACY_FASTUART_DIV_FN_VA {
        return Err("file 0x16be820 is not FUN_0091af14");
    }
    let prev = le_u64_at(blob, BOSMINER_LEGACY_FASTUART_DIV_FPTR_FILE_OFF - 8)
        .ok_or("bosminer shorter than divisor fptr prev")?;
    if prev != BOSMINER_LEGACY_FASTUART_DIV_FPTR_PREV {
        return Err("divisor fptr prev qword is not 0x1ae5350");
    }
    let next = le_u64_at(blob, BOSMINER_LEGACY_FASTUART_DIV_FPTR_FILE_OFF + 8)
        .ok_or("bosminer shorter than divisor fptr next")?;
    if next != BOSMINER_LEGACY_FASTUART_DIV_FPTR_NEXT {
        return Err("divisor fptr next qword is not 0x1ae4948");
    }
    Ok(())
}

/// Neighbor qwords are second-LOAD DATA, not a `.text` UART writer table.
pub fn refuse_div_fptr_neighbors_as_uart_write() -> Result<(), &'static str> {
    Err(
        "0x16be820 holds FUN_0091af14 between DATA 0x1ae5350/0x1ae4948; not a .text FastUART write_reg table",
    )
}

/// `LDP X0,X8,[X8]` then the same pair is `STP` to `+0x78` and `+0x88`.
pub fn admit_bosminer_hashchain_dup78_88_copy(blob: &[u8]) -> Result<(), &'static str> {
    let ldp = le_u32_at(blob, BOSMINER_HASHCHAIN_DUP78_LDP_VA)
        .ok_or("bosminer shorter than dup LDP")?;
    if ldp != BOSMINER_HASHCHAIN_DUP78_LDP_INSN {
        return Err("0x8d3a78 is not LDP X0,X8,[X8]");
    }
    let s78 = le_u32_at(blob, BOSMINER_HASHCHAIN_DUP78_STP_VA)
        .ok_or("bosminer shorter than dup STP #0x78")?;
    if s78 != BOSMINER_HASHCHAIN_DUP78_STP_INSN {
        return Err("0x8d3a7c is not STP X0,X8,[X19,#0x78]");
    }
    let s88 = le_u32_at(blob, BOSMINER_HASHCHAIN_DUP88_STP_VA)
        .ok_or("bosminer shorter than dup STP #0x88")?;
    if s88 != BOSMINER_HASHCHAIN_DUP88_STP_INSN {
        return Err("0x8d3a80 is not STP X0,X8,[X19,#0x88]");
    }
    Ok(())
}

/// That `+0x88` store is a duplicated fat-ptr copy, not the engine nonce callee.
pub fn refuse_hashchain_dup88_as_engine_nonce_fn() -> Result<(), &'static str> {
    Err(
        "0x8d3a80 STP X0,X8,[X19,#0x88] copies the same pair as +0x78; not engine+0x88 nonce .text",
    )
}

/// `0x8d54f4` stores a `BLR` return pair at `+0x78` (consume), not a vtable install.
pub fn admit_bosminer_hashchain_blr78_consume(blob: &[u8]) -> Result<(), &'static str> {
    let stp = le_u32_at(blob, BOSMINER_HASHCHAIN_BLR78_STP_VA)
        .ok_or("bosminer shorter than BLR +0x78 STP")?;
    if stp != BOSMINER_HASHCHAIN_BLR78_STP_INSN {
        return Err("0x8d54f4 is not STP X0,X1,[X19,#0x78]");
    }
    Ok(())
}

/// All seven `+0x78` STP clones are `MOV X0,X21; BLR X8; STP X0,X1,[X19,#0x78]`.
pub fn admit_bosminer_hashchain_blr78_family(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HASHCHAIN_BLR78_FAMILY_HITS != 7 {
        return Err("BLR +0x78 family census drifted");
    }
    if BOSMINER_HASHCHAIN_BLR78_FAMILY_VA[0] != BOSMINER_HASHCHAIN_BLR78_STP_VA {
        return Err("family[0] is not the Wave-140 consume site");
    }
    for &va in &BOSMINER_HASHCHAIN_BLR78_FAMILY_VA {
        let mov = le_u32_at(blob, va - 8).ok_or("bosminer shorter than BLR78 MOV")?;
        if mov != BOSMINER_HASHCHAIN_BLR78_MOV_INSN {
            return Err("BLR78 clone is missing MOV X0,X21");
        }
        let blr = le_u32_at(blob, va - 4).ok_or("bosminer shorter than BLR78 BLR")?;
        if blr != BOSMINER_HASHCHAIN_BLR78_BLR_INSN {
            return Err("BLR78 clone is missing BLR X8");
        }
        let stp = le_u32_at(blob, va).ok_or("bosminer shorter than BLR78 STP")?;
        if stp != BOSMINER_HASHCHAIN_BLR78_STP_INSN {
            return Err("BLR78 clone is not STP X0,X1,[X19,#0x78]");
        }
    }
    Ok(())
}

/// Those seven sites consume a `BLR` Result at `+0x78`. They do not name engine+0x88.
pub fn refuse_blr78_family_as_engine_plus88() -> Result<(), &'static str> {
    Err(
        "7 MOV X0,X21; BLR X8; STP X0,X1,[X19,#0x78] clones consume a Result at +0x78; not engine+0x88 .text",
    )
}

/// : `W13 = (W0[1:0] << 4) | W1[7:4]` (`UBFIZ` then `BFXIL`).
pub fn bosminer_legacy_fastuart_w13(w0: u32, w1: u32) -> u8 {
    (((w0 & 3) << 4) | ((w1 >> 4) & 0xF)) as u8
}

/// dest[0x0C] enum nibble. `FUN_0091af6c` panics when this equals 1.
pub fn bosminer_legacy_fastuart_enum_field(w0: u32) -> u8 {
    ((w0 >> 3) & 3) as u8
}

pub fn bosminer_legacy_fastuart_enum_ok(w0: u32) -> bool {
    bosminer_legacy_fastuart_enum_field(w0) != 1
}

/// Exact 14-byte `[X8]` map from `FUN_0091af6c` STRB/STRH sites.
pub fn pack_bosminer_legacy_fastuart_fields(w0: u32, w1: u32, w2: u32, w3: u32) -> [u8; 14] {
    [
        (w2 & 0xFF) as u8,
        (w1 & 1) as u8,
        ((w0 >> 6) & 1) as u8,
        ((w0 >> 5) & 1) as u8,
        ((w0 >> 2) & 1) as u8,
        bosminer_legacy_fastuart_w13(w0, w1),
        ((w1 >> 2) & 3) as u8,
        ((w1 >> 1) & 1) as u8,
        ((w3 >> 7) & 1) as u8,
        ((w3 >> 5) & 3) as u8,
        ((w3 >> 4) & 1) as u8,
        (w3 & 0xF) as u8,
        bosminer_legacy_fastuart_enum_field(w0),
        ((w0 >> 7) & 1) as u8,
    ]
}

/// Sole static caller: `W0=6`, `W2=0x80`, `W3=0xF`; `W1` is the `+0x22c` byte minus 1.
pub fn pack_bosminer_legacy_fastuart_bm1398_write_instance(w1: u32) -> [u8; 14] {
    pack_bosminer_legacy_fastuart_fields(
        BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0,
        w1,
        BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2,
        BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W3,
    )
}

/// `UBFIZ`/`BFXIL`/`STRB #5` plus caller `MOVZ W2/#W3`.
pub fn admit_bosminer_legacy_fastuart_w13_map(blob: &[u8]) -> Result<(), &'static str> {
    let ubfiz = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_W13_UBFIZ_VA)
        .ok_or("bosminer shorter than W13 UBFIZ")?;
    if ubfiz != BOSMINER_LEGACY_FASTUART_W13_UBFIZ_INSN {
        return Err("0x91af84 is not UBFIZ W13,W0,#4,#2");
    }
    let bfxil = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_W13_BFXIL_VA)
        .ok_or("bosminer shorter than W13 BFXIL")?;
    if bfxil != BOSMINER_LEGACY_FASTUART_W13_BFXIL_INSN {
        return Err("0x91afa4 is not BFXIL W13,W1,#4,#4");
    }
    let str5 = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_STRB_5_VA)
        .ok_or("bosminer shorter than STRB #5")?;
    if str5 != BOSMINER_LEGACY_FASTUART_STRB_5_INSN {
        return Err("0x91afd4 is not STRB W13,[X8,#5]");
    }
    let w2 = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2_VA)
        .ok_or("bosminer shorter than MOVZ W2,#0x80")?;
    if w2 != BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2_INSN {
        return Err("bm1398 write does not MOVZ W2,#0x80 before FastUartReg pack");
    }
    let w3 = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W3_VA)
        .ok_or("bosminer shorter than MOVZ W3,#0xF")?;
    if w3 != BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W3_INSN {
        return Err("bm1398 write does not MOVZ W3,#0xF before FastUartReg pack");
    }
    if BOSMINER_LEGACY_FASTUART_DEST_W13_OFF != 5 {
        return Err("W13 dest offset drifted");
    }
    Ok(())
}

/// W1 is `LDR X8,[X19,#8]; LDRB [X8,#0x22c]; SUB #1` immediately before the pack BL.
pub fn admit_bosminer_legacy_fastuart_w1_ldrb_sub1(blob: &[u8]) -> Result<(), &'static str> {
    let ldr = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_W1_LDR8_VA)
        .ok_or("bosminer shorter than W1 LDR [X19,#8]")?;
    if ldr != BOSMINER_LEGACY_FASTUART_W1_LDR8_INSN {
        return Err("0x8b20e0 is not LDR X8,[X19,#8]");
    }
    let ldrb = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_W1_LDRB_VA)
        .ok_or("bosminer shorter than W1 LDRB #0x22c")?;
    if ldrb != BOSMINER_LEGACY_FASTUART_W1_LDRB_INSN {
        return Err("0x8b20e4 is not LDRB W8,[X8,#0x22c]");
    }
    let sub1 = le_u32_at(blob, BOSMINER_LEGACY_FASTUART_W1_SUB1_VA)
        .ok_or("bosminer shorter than W1 SUB #1")?;
    if sub1 != BOSMINER_LEGACY_FASTUART_W1_SUB1_INSN {
        return Err("0x8b20e8 is not SUB W1,W8,#1");
    }
    if BOSMINER_LEGACY_FASTUART_W1_LDRB_OFF != 0x22C {
        return Err("W1 LDRB offset drifted");
    }
    Ok(())
}

pub fn admit_bosminer_fastuart_field_name_blob(blob: &[u8]) -> Result<(), &'static str> {
    let off = BOSMINER_FASTUART_FIELDS_STR_FILE_OFF as usize;
    let head = BOSMINER_FASTUART_FIELDS_STR;
    if blob.get(off..off + head.len()) != Some(head) {
        return Err("file 0xf20c4b is not unknown_bits_31_28");
    }
    let window = blob
        .get(off..off + 0x80)
        .ok_or("bosminer shorter than FastUART field-name window")?;
    if !window
        .windows(BOSMINER_FASTUART_EXT_BAUD_ENABLE_STR.len())
        .any(|w| w == BOSMINER_FASTUART_EXT_BAUD_ENABLE_STR)
    {
        return Err("ext_baud_enable missing next to unknown_bits_31_28");
    }
    Ok(())
}

/// dest[5] is W13 (W0[1:0]<<4 | W1[7:4]), not a named 32-bit slice and not 0x3001.
pub fn refuse_legacy_fastuart_dest5_as_bible_3001() -> Result<(), &'static str> {
    Err(
        "FUN_0091af6c dest[5] stores W13=(W0[1:0]<<4)|W1[7:4]; not DATA 0x00003001 and not ext_baud_enable",
    )
}

/// rustc `unknown_bits_*`/`ext_baud_enable` names are 32-bit register fields, not dest bytes.
pub fn refuse_fastuart_field_names_as_dest_byte_map() -> Result<(), &'static str> {
    Err(
        "unknown_bits_31_28..ext_baud_enable..tfs is the 32-bit FastUartReg rustc name blob; not the 14-byte [X8] dest map",
    )
}

/// Two `STR Xt,[X19,#0x88]` of `*(obj+0x30)+0x18` (bm1398 write + hashchain twin).
pub fn admit_bosminer_nested88_plus18_family(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_NESTED88_HITS != 2 {
        return Err("nested +0x88 census drifted");
    }
    for i in 0..BOSMINER_NESTED88_HITS {
        let ldr = le_u32_at(blob, BOSMINER_NESTED88_LDR30_VA[i])
            .ok_or("bosminer shorter than nested88 LDR #0x30")?;
        if ldr != BOSMINER_NESTED88_LDR30_INSN {
            return Err("nested +0x88 site is missing LDR X10,[X19,#0x30]");
        }
        let add = le_u32_at(blob, BOSMINER_NESTED88_ADD18_VA[i])
            .ok_or("bosminer shorter than nested88 ADD #0x18")?;
        if add != BOSMINER_NESTED88_ADD18_INSN[i] {
            return Err("nested +0x88 site is missing ADD #0x18");
        }
        let str88 = le_u32_at(blob, BOSMINER_NESTED88_STR_VA[i])
            .ok_or("bosminer shorter than nested88 STR #0x88")?;
        if str88 != BOSMINER_NESTED88_STR_INSN[i] {
            return Err("nested +0x88 site is not STR Xt,[X19,#0x88]");
        }
    }
    if BOSMINER_NESTED88_ADD_IMM != 0x18 {
        return Err("nested +0x88 ADD immediate drifted");
    }
    Ok(())
}

pub fn refuse_nested88_plus18_as_engine_nonce_fn() -> Result<(), &'static str> {
    Err(
        "0x8b27ec/0x8dea60 store *(obj+0x30)+0x18 at +0x88; nested/fat-ptr, not engine nonce .text",
    )
}

/// rustc FastUartReg slices whose names include an explicit bit range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BosminerFastUartRegNamedBits {
    pub unknown_bits_31_28: u8,
    pub unknown_bits_27_23: u8,
    pub unknown_bit_22: bool,
    pub unknown_bits_21_17: u8,
    pub ext_baud_enable: bool,
    pub unknown_bit_15: bool,
    pub unknown_bit_13: bool,
    pub unknown_bit_7_reserved_bit_6: u8,
}

/// Named 32-bit slices only. Does not assign `rfs`/`tfs` widths.
pub fn decode_bosminer_fastuart_reg_named(value: u32) -> BosminerFastUartRegNamedBits {
    BosminerFastUartRegNamedBits {
        unknown_bits_31_28: ((value >> BOSMINER_FASTUART_NAMED_BITS_31_28_SHIFT) & 0xF) as u8,
        unknown_bits_27_23: ((value >> BOSMINER_FASTUART_NAMED_BITS_27_23_SHIFT) & 0x1F) as u8,
        unknown_bit_22: (value >> BOSMINER_FASTUART_NAMED_BIT_22) & 1 == 1,
        unknown_bits_21_17: ((value >> BOSMINER_FASTUART_NAMED_BITS_21_17_SHIFT) & 0x1F) as u8,
        ext_baud_enable: (value >> BOSMINER_FASTUART_EXT_BAUD_ENABLE_BIT) & 1 == 1,
        unknown_bit_15: (value >> BOSMINER_FASTUART_NAMED_BIT_15) & 1 == 1,
        unknown_bit_13: (value >> BOSMINER_FASTUART_NAMED_BIT_13) & 1 == 1,
        unknown_bit_7_reserved_bit_6: ((value >> BOSMINER_FASTUART_NAMED_BITS_7_6_SHIFT) & 0x3)
            as u8,
    }
}

pub fn admit_bosminer_fastuart_named_bit_blob(blob: &[u8]) -> Result<(), &'static str> {
    let off = BOSMINER_FASTUART_FIELDS_STR_FILE_OFF as usize;
    let want = BOSMINER_FASTUART_NAMED_BIT_BLOB;
    if blob.get(off..off + want.len()) != Some(want) {
        return Err("file 0xf20c4b is not the rustc FastUartReg named-bit blob");
    }
    if !want.windows(BOSMINER_FASTUART_BIT76_STR.len()).any(|w| w == BOSMINER_FASTUART_BIT76_STR)
    {
        return Err("named-bit blob missing unknown_bit_7_reserved_bit_6");
    }
    Ok(())
}

/// Bible `0x00003001` has bit 16 clear — it is not `ext_baud_enable`.
pub fn refuse_bible_3001_as_ext_baud_enable(value: u32) -> Result<(), &'static str> {
    let bits = decode_bosminer_fastuart_reg_named(value);
    if value ==  && !bits.ext_baud_enable {
        return Err(
            "bible 0x00003001 has ext_baud_enable bit16=0; not the FastUartReg enable flag",
        );
    }
    Err("value is not bible 0x00003001 or has ext_baud_enable set")
}

/// `rfs`/`tfs` appear in the rustc blob but their bit widths are not in the identifier.
pub fn refuse_rfs_tfs_width_as_named() -> Result<(), &'static str> {
    Err("rfs/tfs are rustc FastUartReg names without a bit-range; width is unbound")
}

/// `25_000_000 / div` when it divides evenly. `div=8` is bible 3.125 M, not host 3M.
pub fn bosminer_xtal25_divisor_baud(div: u8) -> Option<u32> {
    if div == 0 {
        return None;
    }
    let xtal = BOSMINER_FASTUART_22C_XTAL_HZ;
    if xtal % u32::from(div) != 0 {
        return None;
    }
    Some(xtal / u32::from(div))
}

/// Raw `+0x22c` byte is `W1 + 1` on the FastUartReg pack path.
pub fn bosminer_fastuart_w1_to_div_byte(w1: u32) -> Option<u8> {
    w1.checked_add(1)?.try_into().ok()
}

pub fn admit_bosminer_fastuart_22c_xtal25(blob: &[u8]) -> Result<(), &'static str> {
    let ldrb = le_u32_at(blob, BOSMINER_FASTUART_22C_SIBLING_LDRB_VA)
        .ok_or("bosminer shorter than +0x22c sibling LDRB")?;
    if ldrb != BOSMINER_FASTUART_22C_SIBLING_LDRB_INSN {
        return Err("0x8b24dc is not LDRB W9,[X0,#0x22c]");
    }
    let movz = le_u32_at(blob, BOSMINER_FASTUART_22C_XTAL_MOVZ_VA)
        .ok_or("bosminer shorter than 25M MOVZ")?;
    if movz != BOSMINER_FASTUART_22C_XTAL_MOVZ_INSN {
        return Err("0x8b24f0 is not MOVZ W1,#0x7840");
    }
    let movk = le_u32_at(blob, BOSMINER_FASTUART_22C_XTAL_MOVK_VA)
        .ok_or("bosminer shorter than 25M MOVK")?;
    if movk != BOSMINER_FASTUART_22C_XTAL_MOVK_INSN {
        return Err("0x8b24f4 is not MOVK W1,#0x017D,LSL#16");
    }
    if BOSMINER_FASTUART_22C_XTAL_HZ != 25_000_000 {
        return Err("xtal immediate is not 25_000_000");
    }
    if BOSMINER_FASTUART_22C_LDRB_HITS != 12 {
        return Err("+0x22c LDRB census drifted");
    }
    Ok(())
}

/// `25e6/8=3.125M` is bible BM1366, not Track-1 host `3_000_000`.
pub fn refuse_xtal25_div8_as_s19k_host_3m() -> Result<(), &'static str> {
    Err(
        "FUN_008b24b8 pairs +0x22c with 25_000_000; 25e6/8=3_125_000 bible FastUART, not S19k host 3_000_000",
    )
}

pub fn refuse_plus22c_as_engine_nonce_fn() -> Result<(), &'static str> {
    Err("+0x22c is a baud-div byte (LDRB then SUB#1 / 25 MHz sibling); not engine+0x88 .text")
}

/// Linux ARM `B3000000` (`0010015` octal). Host termios speed, not chip FastUART.
pub fn linux_b3000000_speed_t() -> u32 {
    BOSMINER_B3000000_SPEED_T
}

/// Four first-LOAD `MOVZ #0xC6C0` sites that complete `3_000_000`.
pub fn admit_bosminer_host_3m_movz_sites(blob: &[u8]) -> Result<(), &'static str> {
    if BOSMINER_HOST_3M_MOVZ_HITS != 4 {
        return Err("host-3M MOVZ census drifted");
    }
    if BOSMINER_HOST_3M_BAUD != 3_000_000 {
        return Err("host-3M baud constant drifted");
    }
    for i in 0..BOSMINER_HOST_3M_MOVZ_HITS {
        let w = le_u32_at(blob, BOSMINER_HOST_3M_MOVZ_VA[i])
            .ok_or("bosminer shorter than host-3M MOVZ")?;
        if w != BOSMINER_HOST_3M_MOVZ_INSN[i] {
            return Err("host-3M MOVZ site is not MOVZ #0xC6C0");
        }
    }
    Ok(())
}

/// `FUN_00bbe3d4` compares `3_000_000` then `MOVZ W1,#0x100D` (`B3000000`).
pub fn admit_bosminer_host_3m_termios_b3000000(blob: &[u8]) -> Result<(), &'static str> {
    let movz = le_u32_at(blob, BOSMINER_HOST_3M_MOVZ_VA[0])
        .ok_or("bosminer shorter than termios 3M MOVZ")?;
    if movz != BOSMINER_HOST_3M_MOVZ_INSN[0] {
        return Err("0xbbe5bc is not MOVZ W8,#0xC6C0");
    }
    let movk = le_u32_at(blob, BOSMINER_HOST_3M_TERMIOS_MOVK_VA)
        .ok_or("bosminer shorter than termios 3M MOVK")?;
    if movk != BOSMINER_HOST_3M_TERMIOS_MOVK_INSN {
        return Err("0xbbe5c0 is not MOVK W8,#0x2D,LSL#16");
    }
    let speed = le_u32_at(blob, BOSMINER_B3000000_MOVZ_VA[0])
        .ok_or("bosminer shorter than B3000000 MOVZ")?;
    if speed != BOSMINER_B3000000_MOVZ_INSN[0] {
        return Err("0xbbe5cc is not MOVZ W1,#0x100D");
    }
    if linux_b3000000_speed_t() != 0x100D {
        return Err("B3000000 speed_t drifted");
    }
    Ok(())
}

/// AML serial open materializes host `3_000_000` in `W2` (`FUN_00bc1f28`).
pub fn admit_bosminer_aml_open_host_3m(blob: &[u8]) -> Result<(), &'static str> {
    let movz = le_u32_at(blob, BOSMINER_HOST_3M_MOVZ_VA[2])
        .ok_or("bosminer shorter than AML-open 3M MOVZ")?;
    if movz != BOSMINER_HOST_3M_MOVZ_INSN[2] {
        return Err("0xbc1f94 is not MOVZ W2,#0xC6C0");
    }
    let movk = le_u32_at(blob, BOSMINER_AML_OPEN_3M_MOVK_VA)
        .ok_or("bosminer shorter than AML-open 3M MOVK")?;
    if movk != BOSMINER_AML_OPEN_3M_MOVK_INSN {
        return Err("0xbc1fb4 is not MOVK W2,#0x2D,LSL#16");
    }
    let off = BOSMINER_ANTMINER_AML_RS_FILE_OFF as usize;
    if blob.get(off..off + BOSMINER_ANTMINER_AML_RS.len()) != Some(BOSMINER_ANTMINER_AML_RS) {
        return Err("file 0xf92558 is not antminer_aml.rs");
    }
    Ok(())
}

pub fn admit_bosminer_nix_termios_rs(blob: &[u8]) -> Result<(), &'static str> {
    let off = BOSMINER_NIX_TERMIOS_RS_FILE_OFF as usize;
    if blob.get(off..off + BOSMINER_NIX_TERMIOS_RS.len()) != Some(BOSMINER_NIX_TERMIOS_RS) {
        return Err("file 0xf9b584 is not nix-0.26.4 termios.rs");
    }
    Ok(())
}

/// Host 3M is `tcsetattr` / `B3000000`, not chip `set_config(0x28)`.
pub fn refuse_host_3m_termios_as_chip_fastuart_28() -> Result<(), &'static str> {
    Err(
        "bosminer host 3_000_000 is antminer_aml.rs + nix termios B3000000 (0x100D); 0 packed 51 09 00 28; not chip FastUART",
    )
}

/// The 14-byte bm1398 packer and 25e6/8 sibling are not this host-3M path.
pub fn refuse_legacy_pack_and_xtal25_as_host_3m_writer() -> Result<(), &'static str> {
    Err(
        "FUN_0091af6c dest map and FUN_008b24b8 25e6/8 are bm1398.rs chip fields; host 3M is termios B3000000",
    )
}

/// `bm1366.rs:241` packs `0x28=0x0006000F` through `FUN_00bf328c` (REV-to-BE).
pub fn admit_bosminer_bm1366_reg28_6000f(blob: &[u8]) -> Result<(), &'static str> {
    let movz = le_u32_at(blob, BOSMINER_BM1366_REG28_MOVZ_VA)
        .ok_or("bosminer shorter than bm1366 0x28 MOVZ")?;
    if movz != BOSMINER_BM1366_REG28_MOVZ_INSN {
        return Err("0x8df2b0 is not MOVZ W0,#0x28");
    }
    let vlo = le_u32_at(blob, BOSMINER_BM1366_REG28_VAL_MOVZ_VA)
        .ok_or("bosminer shorter than bm1366 0x28 value MOVZ")?;
    if vlo != BOSMINER_BM1366_REG28_VAL_MOVZ_INSN {
        return Err("0x8df2a8 is not MOVZ W1,#0xF");
    }
    let vhi = le_u32_at(blob, BOSMINER_BM1366_REG28_VAL_MOVK_VA)
        .ok_or("bosminer shorter than bm1366 0x28 value MOVK")?;
    if vhi != BOSMINER_BM1366_REG28_VAL_MOVK_INSN {
        return Err("0x8df2b4 is not MOVK W1,#0x600,LSL#16");
    }
    let bl = le_u32_at(blob, BOSMINER_BM1366_REG28_BL_VA)
        .ok_or("bosminer shorter than bm1366 0x28 BL")?;
    if bl != BOSMINER_BM1366_REG28_BL_INSN {
        return Err("0x8df2b8 is not BL FUN_00bf328c");
    }
    let rev = le_u32_at(blob, BOSMINER_BM1366_REG28_PACK_REV_VA)
        .ok_or("bosminer shorter than bm1366 0x28 REV")?;
    if rev != BOSMINER_BM1366_REG28_PACK_REV_INSN {
        return Err("0xbf32c0 is not REV W8,W21");
    }
    if BOSMINER_BM1366_REG28_VALUE != 0x0006_000F {
        return Err("bm1366 loc-cluster 0x28 value drifted");
    }
    Ok(())
}

pub fn admit_bosminer_bm1366_reg28_clone(blob: &[u8]) -> Result<(), &'static str> {
    let movz = le_u32_at(blob, BOSMINER_BM1366_REG28_CLONE_MOVZ_VA)
        .ok_or("bosminer shorter than 0x28 clone MOVZ")?;
    if movz != BOSMINER_BM1366_REG28_CLONE_MOVZ_INSN {
        return Err("0x8464fc is not MOVZ W0,#0x28");
    }
    let movk = le_u32_at(blob, BOSMINER_BM1366_REG28_CLONE_VAL_MOVK_VA)
        .ok_or("bosminer shorter than 0x28 clone MOVK")?;
    if movk != BOSMINER_BM1366_REG28_CLONE_VAL_MOVK_INSN {
        return Err("0x846500 is not MOVK W1,#0x600,LSL#16");
    }
    let bl = le_u32_at(blob, BOSMINER_BM1366_REG28_CLONE_BL_VA)
        .ok_or("bosminer shorter than 0x28 clone BL")?;
    if bl != BOSMINER_BM1366_REG28_CLONE_BL_INSN {
        return Err("0x846504 is not BL FUN_00bf328c");
    }
    if BOSMINER_BM1366_REG28_PACK_CALL_HITS != 2 {
        return Err("0x28 pack-call census drifted");
    }
    Ok(())
}

pub fn admit_bosminer_bm1366_reg28_loc_line(blob: &[u8]) -> Result<(), &'static str> {
    let fn_ptr = le_u64_at(blob, BOSMINER_BM1366_REG28_LOC_FILE_OFF)
        .ok_or("bosminer shorter than bm1366.rs:241 loc")?;
    if fn_ptr != BOSMINER_BM1366_REG28_FN_VA {
        return Err("loc 0x15b7ff8 is not FUN_008de984");
    }
    let line_col = le_u64_at(blob, BOSMINER_BM1366_REG28_LOC_FILE_OFF + 24)
        .ok_or("bosminer shorter than bm1366.rs:241 line")?;
    let line = (line_col & 0xFFFF_FFFF) as u32;
    let col = (line_col >> 32) as u32;
    if line != BOSMINER_BM1366_REG28_LOC_LINE || col != BOSMINER_BM1366_REG28_LOC_COL {
        return Err("FUN_008de984 loc is not bm1366.rs:241:64");
    }
    Ok(())
}

/// UART frame for the loc-cluster encoding. Not host 3M and not bible 3.125M.
pub fn pack_s19k_bm1366_loc_cluster_reg28_uart() -> [u8; 11] {
    s19k_generic_set_config_uart(0x28, BOSMINER_BM1366_REG28_VALUE)
}

pub fn refuse_bm1366_reg28_6000f_as_host_3m() -> Result<(), &'static str> {
    Err(
        "bm1366.rs:241 packs 0x28=0x0006000F (2 call sites); not termios 3_000_000 and not DATA 0x00003001",
    )
}

pub fn refuse_bm1366_reg28_6000f_as_bible_3001() -> Result<(), &'static str> {
    Err("0x0006000F is not bible 0x00003001 / ESP 0x11300200 / BM1362 0x00003011")
}

/// Integer ESP MiscCtrl formula. Not the ESP return 115749 and not FastUART 0x28.
pub fn esp_bm1366_miscctrl_formula_baud_hz() -> u32 {
    ESP_BM1366_MISCCTRL_XTAL_HZ / ((ESP_BM1366_MISCCTRL_DEFAULT_BAUD_DIV + 1) * 8)
}

/// ESP default ~115200 is MiscCtrl 0x18, not a FastUART 0x28 write.
pub fn refuse_esp_miscctrl_default_baud_as_fastuart_28() -> Result<(), &'static str> {
    Err(
        "ESP BM1366_set_default_baud writes MiscCtrl 0x18=0x00007A31 (div 26); not FastUART 0x28 leave-115200",
    )
}

/// ESP return 115749 ≠ integer 25e6/((26+1)*8)=115740. Neither is 0x28.
pub fn refuse_esp_default_baud_return_as_formula_hz() -> Result<(), &'static str> {
    if esp_bm1366_miscctrl_formula_baud_hz() == ESP_BM1366_SET_DEFAULT_BAUD_RETURN_HZ {
        return Err("ESP return unexpectedly equals integer formula; still not FastUART 0x28");
    }
    Err(
        "ESP BM1366_set_default_baud returns 115749; 25e6/((26+1)*8)=115740; neither is a FastUART 0x28 leave-115200 encoding",
    )
}

/// Every held 0x28 write encoding is not Track-1 leave-115200 → host 3M.
pub fn refuse_s19k_fastuart_28_write_as_leave_115200(
    value: u32,
) -> Result<(), &'static str> {
    match value {
        PUBLIC_FASTUART_VALUE => Err(
            "0x11300200 is ESP BM1366_set_max_baud 1 Mbps; not Track-1 leave-115200 to 3M",
        ),
         => Err(
            "0x00003001 is bible BM1366 3.125M FastUART; not Track-1 host 3_000_000 leave-115200",
        ),
         => Err(
            "0x00003011 is BM1362 3.125M FastUART; not S19k BM1366 leave-115200",
        ),
        BOSMINER_BM1366_REG28_VALUE => Err(
            "0x0006000F is bosminer bm1366.rs:241 pack; baud unbound; not proven leave-115200 to 3M",
        ),
        ESP_BM1366_MISCCTRL_DEFAULT_BAUD_VALUE => Err(
            "0x00007A31 is ESP MiscCtrl 0x18 default baud, not a FastUART 0x28 word",
        ),
        _ => Err(
            "unknown chip FastUART 0x28 value; refuse inventing a leave-115200-to-3M encoding",
        ),
    }
}

/// Track-1 115200 retry must read 0x28 and must not write 0x28 to leave 115200.
pub fn admit_s19k_production_track1_reads_not_writes_fastuart_28(
    src: &str,
) -> Result<(), &'static str> {
    let start = src
        .find("PASSTHROUGH BM1366")
        .ok_or("missing Track-1 PASSTHROUGH BM1366")?;
    let rest = src.get(start..).unwrap_or("");
    let end = rest
        .find("} else if passthrough")
        .unwrap_or(rest.len().min(80_000));
    let win = rest.get(..end).unwrap_or("");
    if !win.contains("send_read_reg_broadcast_bm1397plus") {
        return Err("Track-1 must broadcast-read FastUART 0x28");
    }
    if win.contains("send_write_reg_broadcast_bm1397plus(0x28")
        || win.contains("send_write_reg_broadcast_bm1397plus(PUBLIC_FASTUART_REG")
    {
        return Err("Track-1 must not write FastUART 0x28 to leave 115200 (encoding ungrounded)");
    }
    Ok(())
}

/// Bosminer has no `set_config` ASCII. Writes are packed_struct Command at runtime.
pub fn refuse_bosminer_ascii_set_config_as_packer() -> Result<(), &'static str> {
    Err("bosminer has no set_config symbol; packer is packed_struct-0.10.1 packing.rs + command.rs")
}

/// Generic BM1366 set_config UART (55 AA + 51 09 …). Same SSOT as `cmd_set_config`.
pub fn s19k_generic_set_config_uart(reg: u8, value: u32) -> [u8; 11] {
    let body = cmd_set_config(true, 0, reg, value);
    let mut uart = [0u8; 11];
    uart[0] = 0x55;
    uart[1] = 0xAA;
    uart[2..11].copy_from_slice(&body);
    uart
}

pub fn admit_bosminer_contains_write_verify_str(blob: &[u8]) -> Result<(), &'static str> {
    let off = BOSMINER_WRITE_VERIFY_STR_FILE_OFF as usize;
    let needle = b"values were not written correctly to register";
    if blob.len() < off + needle.len() {
        return Err("bosminer blob shorter than write-verify pin");
    }
    if &blob[off..off + needle.len()] != needle {
        return Err("bosminer file 0xf20197 is not write-verify string");
    }
    Ok(())
}

/// ESP FastUART `0x28=0x11300200` is 1 Mbps. Refuse 3M/115200 host merge.
pub fn admit_s19k_fastuart_with_host_baud(host_baud: u32) -> Result<(), &'static str> {
    if host_baud == ESP_FASTUART_HOST_BAUD {
        Ok(())
    } else {
        Err("ESP FastUART 0x11300200 requires host 1_000_000; refuse 3M/115200 merge")
    }
}

/// Three evidence-backed S19k UART dialects. Do not merge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kUartBaudDialect {
    /// `a lab unit` dmesg: 9600→115200 hold. No chip FastUART observed.
    Dmesg78Hold115200,
    /// 2026-08-12 Track-1: host ttyS `3_000_000` 8N1. Chip FastUART unknown.
    BraiinsHost3M,
    /// ESP-Miner `BM1366_set_max_baud`: chip `0x28=0x11300200`, host 1 Mbps.
    EspChipFastUart1M,
    /// bosminer `bm1366.rs:241` pack `0x28=0x0006000F`. Encoding is not a
    /// proven 3M divisor; only admitted when a 0x28 **read** returned it
    /// at host 3M (chip already heard 3M).
    BosminerBm1366Reg28Experimental,
}

/// packed_struct byte lanes named in bosminer (`unknown_bits_31_24` …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kFastUartRegBytes {
    pub b31_24: u8,
    pub b23_16: u8,
    pub b15_8: u8,
    pub b7_0: u8,
}

pub fn split_s19k_fastuart_reg(value: u32) -> S19kFastUartRegBytes {
    S19kFastUartRegBytes {
        b31_24: (value >> 24) as u8,
        b23_16: (value >> 16) as u8,
        b15_8: (value >> 8) as u8,
        b7_0: value as u8,
    }
}

/// : ESP 1M FastUART is not Braiins 3M host termios.
pub fn refuse_esp_fastuart_as_s19k_braiins_3m(value: u32) -> Result<(), &'static str> {
    if value == PUBLIC_FASTUART_VALUE {
        return Err(
            "0x11300200 is ESP BM1366_set_max_baud 1 Mbps; not Braiins S19k 3M host termios",
        );
    }
    Ok(())
}

/// : bible BM1366 `0x00003001` is 3.125 Mbaud, not Track-1 host 3M.
pub fn refuse_bm1366_3001_as_s19k_braiins_3m(value: u32) -> Result<(), &'static str> {
    if value ==  {
        return Err(
            "0x00003001 is bible BM1366 3.125M FastUART; not Braiins S19k 3_000_000 host termios",
        );
    }
    Ok(())
}

/// : BM1362 live `0x00003011` is a different chip family.
pub fn refuse_bm1362_3011_as_s19k_braiins_3m(value: u32) -> Result<(), &'static str> {
    if value ==  {
        return Err(
            "0x00003011 is BM1362 3.125M FastUART; not Braiins S19k BM1366 3_000_000 host termios",
        );
    }
    Ok(())
}

/// `MOVZ X1,#0x3001` in bosminer is followed by `MOVK` — not chip FastUART.
pub fn refuse_bosminer_movz_3001_as_fastuart() -> Result<(), &'static str> {
    Err("MOVZ X1,#0x3001 @ 0x10ba39c/0x10c49d8 is pointer materialization (MOVK follows); not FastUART")
}

/// AM2 S17 set-baud logger is not the S19k AML chip writer.
pub fn refuse_bosminer_am2_set_baud_as_s19k_aml() -> Result<(), &'static str> {
    Err("FUN_00836934 is AM2 S17 CHAIN/: Set baud rate; not S19k AML FastUART")
}

/// Tuner Display enum is not UART `write_reg`.
pub fn refuse_bosminer_tuner_write_reg_display_as_uart() -> Result<(), &'static str> {
    Err("FUN_00645898 formats write_reg/soft_reset/reset_counters/work_time; not UART write_reg")
}

/// MiscCtrl modify is ASIC `0x18`, not FastUART `0x28`.
pub fn refuse_bosminer_miscctrl_modify_as_fastuart_28() -> Result<(), &'static str> {
    Err("FUN_008b40dc logs Modifying MiscCtrl for chip; not FastUART reg 0x28")
}

/// No packed `51 09 00 28` in the file. FastUART is runtime-packed.
pub fn refuse_bosminer_file_setcfg_28_as_s19k_fastuart(hits: usize) -> Result<(), &'static str> {
    if hits == 0 {
        return Err(
            "0 packed 51 09 00 28 in bosminer.unpacked; not an S19k 3M FastUART SoT",
        );
    }
    Err("unexpected packed set_config 0x28 in bosminer file")
}

/// The four `BL` sites are AM2 set-baud, send-self, and MiscCtrl — not AML FastUART.
pub fn refuse_uart_be4_send_callers_as_s19k_aml_fastuart() -> Result<(), &'static str> {
    Err(
        "4 BL UART_BE4_SEND @ 0x836c3c/0x8a2300/0x8a255c/0x8b4504 are AM2/send-self/MiscCtrl; not S19k AML FastUART",
    )
}

/// `MOVZ #0x28` is a common immediate, not a unique reg-0x28 writer.
pub fn refuse_movz_imm28_as_fastuart_reg(hits: usize) -> Result<(), &'static str> {
    if hits == 0 {
        return Ok(());
    }
    Err("MOVZ #0x28 is a common immediate; not a unique FastUART reg writer")
}

/// Byte-presence of `reg=0x28` + BE FastUART word. Does not prove a write site.
pub fn admit_bosminer_contains_reg28_fastuart_be(
    blob: &[u8],
    file_off: u64,
    value: u32,
) -> Result<(), &'static str> {
    let off = file_off as usize;
    if blob.len() < off + 6 {
        return Err("bosminer blob shorter than reg28 FastUART pin");
    }
    let be = value.to_be_bytes();
    let want = [0x28, 0x00, 0x00, 0x00, be[2], be[3]];
    if blob[off..off + 6] != want {
        return Err("bosminer file is not 28 00 00 00 || FastUART BE low");
    }
    Ok(())
}

/// Bible 3.125M chip FastUART may pair only with host 3.125M — never 3M/115200/1M.
pub fn admit_s19k_bible_fastuart_3125k_with_host_baud(host_baud: u32) -> Result<(), &'static str> {
    if host_baud ==  {
        Ok(())
    } else {
        Err("bible BM1366 0x00003001 requires host 3_125_000; refuse 3M/115200/1M merge")
    }
}

/// Classify host baud + optional chip FastUART. Merge is refused.
pub fn classify_s19k_uart_baud_dialect(
    host_baud: u32,
    chip_fastuart: Option<u32>,
) -> Result<S19kUartBaudDialect, &'static str> {
    if let Some(v) = chip_fastuart {
        if v == PUBLIC_FASTUART_VALUE {
            if host_baud != ESP_FASTUART_HOST_BAUD {
                return Err("ESP FastUART 0x11300200 cannot pair with 3M/115200 host");
            }
            return Ok(S19kUartBaudDialect::EspChipFastUart1M);
        }
        if v ==  {
            return Err(
                "0x00003001 is bible BM1366 3.125M; refuse pairing as S19k Braiins 3M dialect",
            );
        }
        if v ==  {
            return Err("0x00003011 is BM1362 3.125M; refuse pairing as S19k Braiins 3M dialect");
        }
        if v == BOSMINER_BM1366_REG28_VALUE {
            if host_baud == BRAIINS_PASSTHROUGH_BAUD {
                return Ok(S19kUartBaudDialect::BosminerBm1366Reg28Experimental);
            }
            return Err("0x0006000F is bosminer bm1366.rs pack; not proven at this host baud");
        }
        return Err("unknown chip FastUART value; refuse inventing a 3M encoding");
    }
    match host_baud {
        BRAIINS_PASSTHROUGH_BAUD => Ok(S19kUartBaudDialect::BraiinsHost3M),
        S19K_78_DMESG_HOLD_BAUD => Ok(S19kUartBaudDialect::Dmesg78Hold115200),
        ESP_FASTUART_HOST_BAUD => Err("host 1M without chip FastUART is not an S19k dialect"),
         => {
            Err("host 3.125M without an admitted chip FastUART is not an S19k dialect")
        }
        _ => Err("unrecognized S19k host baud"),
    }
}

/// Optional chip FastUART from `DCENT_S19K_CHIP_FASTUART` (hex). Unset = none.
pub fn s19k_track1_chip_fastuart_from_env(value: Option<&str>) -> Option<u32> {
    let s = value?.trim();
    if s.is_empty() {
        return None;
    }
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u32::from_str_radix(hex, 16).ok()
}

/// Type Track-1 host baud + optional FastUART for RX classify.
/// `baud.is_err()` turns GetAddress silence into `UartConfigMismatch`.
pub fn s19k_track1_classify_rx_baud(
    host_baud: u32,
    chip_fastuart_env: Option<&str>,
) -> Result<(), &'static str> {
    s19k_track1_classify_rx_baud_with_reg28(host_baud, chip_fastuart_env, None)
}

/// Observed chip `0x28` outranks the env hint. Unread stays env-only.
pub fn s19k_track1_classify_rx_baud_with_reg28(
    host_baud: u32,
    chip_fastuart_env: Option<&str>,
    observed_reg28: Option<u32>,
) -> Result<(), &'static str> {
    let chip = observed_reg28.or_else(|| s19k_track1_chip_fastuart_from_env(chip_fastuart_env));
    classify_s19k_uart_baud_dialect(host_baud, chip).map(|_| ())
}

/// What a read of chip FastUART `0x28` means. Unread is not 3M proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kChipFastUartKind {
    Unread,
    ZeroOrDefault,
    BibleBm1366_3m125,
    Bm1362_3m125,
    Esp1M,
    BosminerBm1366_6000F,
    Unknown(u32),
}

pub fn classify_s19k_chip_fastuart_word(v: Option<u32>) -> S19kChipFastUartKind {
    match v {
        None => S19kChipFastUartKind::Unread,
        Some(0) => S19kChipFastUartKind::ZeroOrDefault,
        Some => S19kChipFastUartKind::BibleBm1366_3m125,
        Some => S19kChipFastUartKind::Bm1362_3m125,
        Some(PUBLIC_FASTUART_VALUE) => S19kChipFastUartKind::Esp1M,
        Some(BOSMINER_BM1366_REG28_VALUE) => S19kChipFastUartKind::BosminerBm1366_6000F,
        Some(other) => S19kChipFastUartKind::Unknown(other),
    }
}

/// Host 3M + unread `0x28` is not chip-115200 proof and not ASIC-uninit proof.
pub fn refuse_unread_fastuart_28_as_host_3m_chip_state() -> Result<(), &'static str> {
    Err(
        "unread chip FastUART 0x28 cannot distinguish host 3M from 115200 chip; send 52 05 00 28",
    )
}

/// Opt-in EXPERIMENTAL 115200 GetAddress retry after ChipFastUartUnread.
/// Default unset: do not change host baud. Restore is always 3M.
pub const S19K_TRACK1_RETRY_115200_ENV: &str = "DCENT_S19K_TRACK1_RETRY_115200";

pub fn s19k_track1_retry_115200_from_env(
    value: Option<&str>,
) -> Result<bool, &'static str> {
    match value {
        None | Some("") => Ok(false),
        Some("1") => Ok(true),
        Some(_) => Err("DCENT_S19K_TRACK1_RETRY_115200 must be 1 or unset"),
    }
}

/// Host baud after a 115200 retry. Always Track-1 3M, never leave 115200.
pub fn s19k_track1_retry_restore_baud() -> u32 {
    BRAIINS_PASSTHROUGH_BAUD
}

/// Ordered steps. Restore is last even if GetAddress / 0x28 fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kTrack1115200RetryStep {
    SetHost115200,
    GetAddress,
    /// Only after `GetAddressSilenceAt115200`.
    FastUart28IfGetAddressSilent,
    RestoreHost3M,
}

pub fn s19k_track1_115200_retry_steps() -> [S19kTrack1115200RetryStep; 4] {
    [
        S19kTrack1115200RetryStep::SetHost115200,
        S19kTrack1115200RetryStep::GetAddress,
        S19kTrack1115200RetryStep::FastUart28IfGetAddressSilent,
        S19kTrack1115200RetryStep::RestoreHost3M,
    ]
}

/// Probe chip FastUART 0x28 at 115200 only when GetAddress was silent.
pub fn s19k_track1_should_probe_fastuart_28_at_115200(getaddress_115200: S19kRxDiag) -> bool {
    getaddress_115200 == S19kRxDiag::GetAddressSilenceAt115200
}

/// Retry only when 3M GetAddress did not prove ChipAddress, 0x28 is unread,
/// host is 3M, and the env opt-in is set.
pub fn s19k_track1_should_retry_115200(
    getaddress_diag: S19kRxDiag,
    fastuart_diag: S19kRxDiag,
    host_baud: u32,
    env: Option<&str>,
) -> Result<bool, &'static str> {
    let want = s19k_track1_retry_115200_from_env(env)?;
    if !want {
        return Ok(false);
    }
    if host_baud != BRAIINS_PASSTHROUGH_BAUD {
        return Err("115200 retry requires host 3_000_000 so restore is well-defined");
    }
    if getaddress_diag == S19kRxDiag::ChipAddressOk
        || getaddress_diag == S19kRxDiag::ChainFailShortEnum
    {
        return Ok(false);
    }
    if fastuart_diag == S19kRxDiag::FastUartRegOk {
        return Ok(false);
    }
    if fastuart_diag != S19kRxDiag::ChipFastUartUnread
        && getaddress_diag != S19kRxDiag::AsicResetOrUninit
    {
        return Ok(false);
    }
    Ok(true)
}

/// A 115200 ChipAddress is not 3M work-TX proof.
pub fn refuse_chip_heard_at_115200_as_3m_work_proof(
    diag: S19kRxDiag,
) -> Result<(), &'static str> {
    if diag == S19kRxDiag::ChipHeardAt115200 {
        return Err(
            "ChipHeardAt115200 is diagnostic; work TX stays on restored 3M GetAddress",
        );
    }
    Ok(())
}

pub fn refuse_115200_retry_without_restore(steps: &[S19kTrack1115200RetryStep]) -> Result<(), &'static str> {
    match steps.last() {
        Some(S19kTrack1115200RetryStep::RestoreHost3M) => Ok(()),
        _ => Err("115200 retry must end with RestoreHost3M"),
    }
}

/// Host-testable restore obligation. Production Drop calls `set_baud`.
pub struct S19kTrack1BaudRestoreGuard {
    restore_to: u32,
    armed: bool,
}

impl S19kTrack1BaudRestoreGuard {
    pub fn arm_after_115200() -> Self {
        Self {
            restore_to: s19k_track1_retry_restore_baud(),
            armed: true,
        }
    }

    pub fn restore_owed(&self) -> bool {
        self.armed
    }

    /// Explicit restore. Drop is a no-op after this.
    pub fn take_restore(&mut self) -> Option<u32> {
        if !self.armed {
            return None;
        }
        self.armed = false;
        Some(self.restore_to)
    }
}

impl Drop for S19kTrack1BaudRestoreGuard {
    fn drop(&mut self) {
        let _ = self.take_restore();
    }
}

/// Drop while armed must still produce the 3M restore baud.
pub fn s19k_track1_baud_restore_on_drop(armed: bool) -> Option<u32> {
    if armed {
        Some(s19k_track1_retry_restore_baud())
    } else {
        None
    }
}

/// Production 115200 retry is env-gated and must restore 3M after the probe.
pub fn admit_s19k_production_115200_retry_is_gated(src: &str) -> Result<(), &'static str> {
    if !src.contains("s19k_track1_should_retry_115200") {
        return Err("production must consult the 115200 retry gate");
    }
    if !src.contains("S19K_TRACK1_RETRY_115200_ENV") {
        return Err("115200 retry must be DCENT_S19K_TRACK1_RETRY_115200 opt-in");
    }
    if !src.contains("s19k_track1_retry_restore_baud")
        && !src.contains("BRAIINS_TTYS_BAUD")
        && !src.contains("3_000_000")
    {
        return Err("115200 retry must restore Track-1 3M");
    }
    if !src.contains("impl Drop for Track1HostBaudRestore") {
        return Err("115200 retry must restore 3M in Drop, not only sequentially");
    }
    let set115 = src.find("S19K_78_DMESG_HOLD_BAUD").or_else(|| src.find("115_200"));
    let guard = src.find("Track1HostBaudRestore::arm");
    match (set115, guard) {
        (Some(a), Some(b)) if a < b => Ok(()),
        _ => Err("Track1HostBaudRestore must arm after the 115200 set_baud"),
    }
}

/// Production Drop must call restore baud, not only disarm.
pub fn admit_s19k_production_115200_retry_drop_restores(src: &str) -> Result<(), &'static str> {
    let start = src
        .find("impl Drop for Track1HostBaudRestore")
        .ok_or("missing Track1HostBaudRestore Drop")?;
    let rest = &src[start..];
    let end = rest.find("\n}").ok_or("cannot bound Drop impl")?;
    let body = &rest[..end];
    if !body.contains("set_baud") {
        return Err("Drop must call set_baud");
    }
    if !body.contains("s19k_track1_retry_restore_baud") && !body.contains("restore_to") {
        return Err("Drop must restore Track-1 3M");
    }
    Ok(())
}

/// First restore + one retry. Two failures are not 3M work-TX proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kTrack1RestoreBaudAttempt {
    FirstOk,
    RetryOk,
    FailedAfterRetry,
}

pub fn s19k_track1_restore_baud_attempt(
    first_ok: bool,
    retry_ok: bool,
) -> S19kTrack1RestoreBaudAttempt {
    if first_ok {
        S19kTrack1RestoreBaudAttempt::FirstOk
    } else if retry_ok {
        S19kTrack1RestoreBaudAttempt::RetryOk
    } else {
        S19kTrack1RestoreBaudAttempt::FailedAfterRetry
    }
}

/// Host baud after restore. 115200 (or any non-3M) is not work-TX capable.
pub fn refuse_work_tx_if_host_not_3m_after_restore(host_baud: u32) -> Result<(), &'static str> {
    if host_baud == s19k_track1_retry_restore_baud() {
        Ok(())
    } else {
        Err("host UART is not 3M after 115200 restore; refuse work TX at 115200")
    }
}

pub fn refuse_restore_failed_as_3m_work_proof(
    attempt: S19kTrack1RestoreBaudAttempt,
) -> Result<(), &'static str> {
    match attempt {
        S19kTrack1RestoreBaudAttempt::FailedAfterRetry => {
            Err("restore to 3M failed after retry; not 3M work-TX proof")
        }
        S19kTrack1RestoreBaudAttempt::FirstOk | S19kTrack1RestoreBaudAttempt::RetryOk => Ok(()),
    }
}

/// Drop must retry set_baud; production must refuse work TX if host stayed off 3M.
pub fn admit_s19k_production_restore_retries_then_refuses(src: &str) -> Result<(), &'static str> {
    if !src.contains("refuse_work_tx_if_host_not_3m_after_restore") {
        return Err("production must refuse work TX if host baud is not 3M after restore");
    }
    let start = src
        .find("impl Drop for Track1HostBaudRestore")
        .ok_or("missing Track1HostBaudRestore Drop")?;
    let rest = &src[start..];
    let end = rest.find("\n}").ok_or("cannot bound Drop impl")?;
    let body = &rest[..end];
    if body.matches("set_baud").count() < 2 {
        return Err("Drop must retry set_baud after the first restore failure");
    }
    Ok(())
}

/// 50 MHz is the public ramp **start**, not S19k stock mining frequency.
pub fn refuse_pll0_50mhz_as_s19k_stock_mining_freq(mhz: u32) -> Result<(), &'static str> {
    if mhz == PLL_RAMP_START_MHZ {
        return Err("50 MHz is PLL ramp start, not S19k stock mining frequency");
    }
    Ok(())
}

/// PLL0 at an explicit target. Same SSOT as `serial_mining`.
pub fn s19k_native_pll0_write(target_mhz: u16) -> S19kExperimentalInitWrite {
    let (reg, _) = bm1366_pll_reg_and_actual(target_mhz);
    init_write("pll0", REG_PLL0, reg, true, 0)
}

/// Opt-in FastUART write. Not part of the default native program.
pub fn s19k_native_fastuart_write() -> S19kExperimentalInitWrite {
    init_write(
        "fastuart_1m",
        PUBLIC_FASTUART_REG,
        PUBLIC_FASTUART_VALUE,
        true,
        0,
    )
}

/// Opt-in bible BM1366 3.125M FastUART (`0x28=0x00003001`).
/// Not in the default native program. Not Braiins S19k 3M termios.
pub fn s19k_native_fastuart_bible_3125k_write() -> S19kExperimentalInitWrite {
    init_write(
        "fastuart_bible_3125k",
        PUBLIC_FASTUART_REG,
        ,
        true,
        0,
    )
}

/// PLL0 at the public ramp-start (50 MHz). Same SSOT as `serial_mining`.
pub fn s19k_native_pll0_start_write() -> S19kExperimentalInitWrite {
    let (reg, _) = bm1366_pll_reg_and_actual(PLL_RAMP_START_MHZ as u16);
    init_write("pll0_50mhz", REG_PLL0, reg, true, 0)
}

/// Braiins Track-1 stays at host 3 Mbaud. Do not merge with jig 12 M.
pub const BRAIINS_PASSTHROUGH_BAUD: u32 = BRAIINS_TTYS_BAUD;
/// Native / jig class (HashSource PT). Separate dialect — never merge.
pub const NATIVE_JIG_BAUD_HZ: u32 = 12_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kInitDialect {
    /// Rails already up; do not reset; do not change baud.
    BraiinsPassthrough,
    /// Cold native — EXPERIMENTAL, not production-admitted.
    NativeExperimental,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kInitStep {
    pub name: &'static str,
    pub uart: Vec<u8>,
}

/// Ordered program. Passthrough skips reset / baud / analog-mux.
pub fn s19k_bm1366_init_program(dialect: S19kInitDialect) -> Vec<S19kInitStep> {
    let mut steps = Vec::new();
    match dialect {
        S19kInitDialect::BraiinsPassthrough => {
            steps.push(S19kInitStep {
                name: "get_address",
                uart: GET_ADDRESS_UART.to_vec(),
            });
            // After bosminer kill-9, re-arm hashing regs without reset/baud.
            // Ticket 0xFF (diff-256) + HCN 0x115A. Not ESP VR 0xA4=0x9000FFFF.
            for w in s19k_passthrough_rearm_writes() {
                steps.push(S19kInitStep {
                    name: w.name,
                    uart: pack_experimental_init_write(w).to_vec(),
                });
            }
        }
        S19kInitDialect::NativeExperimental => {
            // ESP-Miner BM1366_init order, AML interval 2 (not 256/n).
            // PLL0 @ 50 MHz after per-chip (ESP frequency transition).
            // FastUART 0x28 stays opt-in: 1 Mbps host only.
            steps.push(S19kInitStep {
                name: "get_address",
                uart: GET_ADDRESS_UART.to_vec(),
            });
            steps.push(step_from_write(*INIT_CTRL_A8_BCAST_WRITE));
            steps.push(step_from_write(*MISC_CTRL_BCAST_WRITE));
            steps.push(S19kInitStep {
                name: "chain_inactive",
                uart: CHAIN_INACTIVE_UART.to_vec(),
            });
            for addr in s19k_aml_linear_addresses() {
                steps.push(S19kInitStep {
                    name: "set_address",
                    uart: pack_set_address_uart_trans(addr).to_vec(),
                });
            }
            steps.push(step_from_write(*CORE_HASH_CLOCK_BCAST_WRITE));
            steps.push(step_from_write(*CORE_CLOCK_DELAY_BCAST_WRITE));
            steps.push(step_from_write(*TICKET_MASK_BCAST_WRITE));
            steps.push(step_from_write(*ANALOG_MUX_BCAST_WRITE));
            steps.push(step_from_write(*IO_DRIVER_BCAST_WRITE));
            steps.push(step_from_write(*UART_RELAY_CHIP0_WRITE));
            for addr in s19k_aml_linear_addresses() {
                for w in s19k_native_per_chip_core_writes(addr) {
                    steps.push(step_from_write(w));
                }
            }
            steps.push(step_from_write(s19k_native_pll0_start_write()));
            steps.push(step_from_write(*HASH_COUNTING_BCAST_WRITE));
            // : do not arm ESP 0xA4=0x9000FFFF. Fill hashes packed ver0.
        }
    }
    steps
}

pub fn admit_init_dialect_baud(dialect: S19kInitDialect, baud: u32) -> Result<(), &'static str> {
    match dialect {
        S19kInitDialect::BraiinsPassthrough => {
            if baud != BRAIINS_PASSTHROUGH_BAUD {
                return Err("passthrough must keep bosminer 3_000_000; refuse baud change");
            }
        }
        S19kInitDialect::NativeExperimental => {
            if baud != NATIVE_JIG_BAUD_HZ
                && baud != BRAIINS_PASSTHROUGH_BAUD
                && baud != S19K_78_DMESG_HOLD_BAUD
            {
                return Err(
                    "native experimental baud must be 12M jig, 3M Braiins host, or 115200 .78 hold",
                );
            }
        }
    }
    Ok(())
}

/// ESP-Miner `BM1366_CHIP_ID_RESPONSE_LENGTH` is 11. BM1397 is 9.
pub fn refuse_bm1397_9byte_as_bm1366_getaddress_rx(len: usize) -> Result<(), &'static str> {
    if len == 9 {
        return Err("BM1397 GetAddress RX is 9 bytes; BM1366 ESP CHIP_ID response is 11");
    }
    if len == ESP_BM1366_CHIP_ID_RX_LEN && len == UART_RESP_LEN {
        return Ok(());
    }
    Err("BM1366 GetAddress RX length is 11")
}

pub fn refuse_native_as_production(dialect: S19kInitDialect) -> Result<(), &'static str> {
    match dialect {
        S19kInitDialect::BraiinsPassthrough => Ok(()),
        S19kInitDialect::NativeExperimental => {
            Err("native BM1366 cold-init is EXPERIMENTAL; production still refuses")
        }
    }
}

pub fn init_ports() -> &'static [&'static str] {
    BRAIINS_TTYS_DISCOVER
}

/// Passthrough re-arm after GetAddress on an answering ttyS. No reset, no
/// set_address, no baud change. Ticket+HCN only — not ESP VersionMask.
pub fn s19k_passthrough_rearm_writes() -> impl Iterator<Item = S19kExperimentalInitWrite> {
    S19K_EXPERIMENTAL_INIT_WRITES.iter().copied().filter(|w| {
        matches!(
            w.name,
            "ticket_mask_diff256" | "hash_counting_s19k"
        )
    })
}

/// EXPERIMENTAL register writes (jig + ESP-Miner agree on values).
/// Not a production cold-init. Host baud must match before FastUART 0x28.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kExperimentalInitWrite {
    pub name: &'static str,
    pub reg: u8,
    pub value: u32,
    pub bcast: bool,
    pub chip_addr: u8,
}

const fn init_write(
    name: &'static str,
    reg: u8,
    value: u32,
    bcast: bool,
    chip_addr: u8,
) -> S19kExperimentalInitWrite {
    S19kExperimentalInitWrite {
        name,
        reg,
        value,
        bcast,
        chip_addr,
    }
}

pub const INIT_CTRL_A8_BCAST_WRITE: &S19kExperimentalInitWrite =
    &init_write("init_ctrl_a8_bcast", INIT_REG_INIT_CTRL, INIT_CTRL_A8_BCAST, true, 0);
pub const MISC_CTRL_BCAST_WRITE: &S19kExperimentalInitWrite =
    &init_write("misc_ctrl_bcast", 0x18, 0xFF0F_C100, true, 0);
pub const CORE_HASH_CLOCK_BCAST_WRITE: &S19kExperimentalInitWrite =
    &init_write("core_hash_clock", 0x3C, CORE_REG_HASH_CLOCK, true, 0);
pub const CORE_CLOCK_DELAY_BCAST_WRITE: &S19kExperimentalInitWrite =
    &init_write("core_clock_delay", 0x3C, CORE_REG_CLOCK_DELAY, true, 0);
pub const TICKET_MASK_BCAST_WRITE: &S19kExperimentalInitWrite = &init_write(
    "ticket_mask_diff256",
    INIT_REG_TICKET_MASK,
    TICKET_MASK_PLAIN_DIFF_MINUS_ONE_256,
    true,
    0,
);
pub const ANALOG_MUX_BCAST_WRITE: &S19kExperimentalInitWrite =
    &init_write("analog_mux", 0x54, 0x0000_0003, true, 0);
pub const IO_DRIVER_BCAST_WRITE: &S19kExperimentalInitWrite =
    &init_write("io_driver", 0x58, 0x0211_1111, true, 0);
pub const UART_RELAY_CHIP0_WRITE: &S19kExperimentalInitWrite =
    &init_write("uart_relay_chip0", REG_UART_RELAY, UART_RELAY_CHIP0_PUBLIC, false, 0);
pub const HASH_COUNTING_BCAST_WRITE: &S19kExperimentalInitWrite = &init_write(
    "hash_counting_s19k",
    INIT_REG_HASH_COUNTING,
    S19K_WIRE_HASH_COUNTING,
    true,
    0,
);
/// ESP-Miner `BM1366_init` live default (S19XP). Not the S19k rearm word.
pub const ESP_BM1366_HASH_COUNTING_S19XP: u32 = 0x0000_151C;

/// ESP-Miner BM1366 VersionMask (S19XP / Bitaxe). Not a Braiins fill re-arm.
pub const ESP_BM1366_VERSION_ROLL_MASK: u32 = 0x9000_FFFF;
/// Sole `90 00 FF FF` in first-LOAD is UTF-16 `U+0090` next to `0xFFFF` pad.
pub const BOSMINER_9000FFFF_BE_FILE_OFF: u64 = 0x011F_D4B0;
pub const BOSMINER_9000FFFF_BE_VA: u64 = 0x015F_D4B0;
/// Preceding UTF-16 unit `U+0080` then `U+0090`.
pub const BOSMINER_9000FFFF_PREV_U16: u16 = 0x0080;
/// Sole first-LOAD `MOVZ Wd,#0xA4` is `ldr [x0,x8]` object+0xA4, not set_config.
pub const BOSMINER_MOVZ_A4_VA: u64 = 0x00E7_A568;
pub const BOSMINER_MOVZ_A4_INSN: u32 = 0x5280_1488;
pub const BOSMINER_MOVZ_A4_LDR_INSN: u32 = 0xB868_6808;

/// ESP `0xA4=0x9000FFFF` would roll BIP320 under a packed-ver0 fill job.
pub fn refuse_esp_9000ffff_as_braiins_fill_rearm(
    reg: u8,
    value: u32,
) -> Result<(), &'static str> {
    if reg == INIT_REG_VERSION_ROLL && value == ESP_BM1366_VERSION_ROLL_MASK {
        return Err(
            "Braiins fill hashes packed ver0; refuse ESP 0xA4=0x9000FFFF as fill/native re-arm",
        );
    }
    Ok(())
}

pub fn admit_s19k_passthrough_rearm_omits_version_roll(
    names: &[&str],
) -> Result<(), &'static str> {
    if names.iter().any(|n| *n == "version_roll") {
        return Err("S19k init program must not write ESP VersionMask");
    }
    if !names.iter().any(|n| *n == "ticket_mask_diff256") {
        return Err("passthrough re-arm must keep ticket_mask");
    }
    if !names.iter().any(|n| *n == "hash_counting_s19k") {
        return Err("passthrough re-arm must keep HCN 0x115A");
    }
    Ok(())
}

/// Six-byte window at `BOSMINER_9000FFFF_BE_FILE_OFF-2`: `80 00 90 00 FF FF`.
pub fn refuse_bosminer_9000ffff_utf16_as_version_mask(window: &[u8]) -> Result<(), &'static str> {
    if window.len() < 6 {
        return Err("UTF-16 pad window must be 6 bytes");
    }
    if u16::from_le_bytes([window[0], window[1]]) != BOSMINER_9000FFFF_PREV_U16 {
        return Err("9000FFFF is not preceded by UTF-16 U+0080");
    }
    if window[2..6] != [0x90, 0x00, 0xFF, 0xFF] {
        return Err("expected 90 00 FF FF UTF-16 pad");
    }
    Err("bosminer 90 00 FF FF is UTF-16 U+0090 + 0xFFFF pad, not VersionMask")
}

/// `MOVZ W8,#0xA4` then `LDR W8,[X0,X8]` is a field compare, not set_config.
pub fn refuse_bosminer_movz_a4_as_set_config(movz: u32, ldr: u32) -> Result<(), &'static str> {
    if movz != BOSMINER_MOVZ_A4_INSN {
        return Err("0xe7a568 is not MOVZ W8,#0xA4");
    }
    if ldr != BOSMINER_MOVZ_A4_LDR_INSN {
        return Err("0xe7a56c is not LDR W8,[X0,X8]");
    }
    Err("MOVZ #0xA4 is object+0xA4 compare, not UART set_config(reg=0xA4)")
}

pub fn refuse_esp_s19xp_hcn_as_s19k_rearm(value: u32) -> Result<(), &'static str> {
    if value == ESP_BM1366_HASH_COUNTING_S19XP {
        return Err("S19k rearm HCN must be 0x115A; ESP/S19XP default is 0x151C");
    }
    if value != S19K_WIRE_HASH_COUNTING {
        return Err("S19k HCN must be 0x115A");
    }
    Ok(())
}
pub const VERSION_ROLL_BCAST_WRITE: &S19kExperimentalInitWrite =
    &init_write("version_roll", INIT_REG_VERSION_ROLL, 0x9000_FFFF, true, 0);

pub const S19K_EXPERIMENTAL_INIT_WRITES: &[S19kExperimentalInitWrite] = &[
    *ANALOG_MUX_BCAST_WRITE,
    *CORE_HASH_CLOCK_BCAST_WRITE,
    *CORE_CLOCK_DELAY_BCAST_WRITE,
    *TICKET_MASK_BCAST_WRITE,
    *HASH_COUNTING_BCAST_WRITE,
    *VERSION_ROLL_BCAST_WRITE,
    *MISC_CTRL_BCAST_WRITE,
    *IO_DRIVER_BCAST_WRITE,
    *UART_RELAY_CHIP0_WRITE,
    *INIT_CTRL_A8_BCAST_WRITE,
];

/// ESP-Miner per-chip core program after addressing. Interval-2 AML addrs.
pub fn s19k_native_per_chip_core_writes(chip_addr: u8) -> [S19kExperimentalInitWrite; 5] {
    [
        init_write(
            "init_ctrl_a8_unicast",
            INIT_REG_INIT_CTRL,
            INIT_CTRL_A8_UNICAST,
            false,
            chip_addr,
        ),
        init_write("misc_ctrl_unicast", 0x18, MISC_CTRL_UNICAST, false, chip_addr),
        init_write(
            "core_hash_clock_unicast",
            0x3C,
            CORE_REG_HASH_CLOCK,
            false,
            chip_addr,
        ),
        init_write(
            "core_clock_delay_unicast",
            0x3C,
            CORE_REG_CLOCK_DELAY,
            false,
            chip_addr,
        ),
        init_write(
            "core_asicboost_unicast",
            0x3C,
            CORE_REG_ASICBOOST,
            false,
            chip_addr,
        ),
    ]
}

pub fn refuse_firmware_internals_a8_as_s19k_per_chip(value: u32) -> Result<(), &'static str> {
    if value == REFUSED_INTERNALS_A8_PER_CHIP {
        return Err(
            "FIRMWARE_INTERNALS 0xA8=0xF0010700 contradicts ESP UART 00 07 01 F0; refuse as S19k",
        );
    }
    if value != INIT_CTRL_A8_UNICAST {
        return Err("S19k per-chip 0xA8 must be ESP 0x000701F0");
    }
    Ok(())
}

fn step_from_write(w: S19kExperimentalInitWrite) -> S19kInitStep {
    S19kInitStep {
        name: w.name,
        uart: pack_experimental_init_write(w).to_vec(),
    }
}

/// Compact bench/log summary. Does not execute UART.
pub fn format_s19k_native_init_summary(steps: &[S19kInitStep]) -> String {
    let set_addr = steps.iter().filter(|s| s.name == "set_address").count();
    let a8_u = steps
        .iter()
        .filter(|s| s.name == "init_ctrl_a8_unicast")
        .count();
    format!(
        "S19K_NATIVE_INIT steps={} set_address={} a8_unicast={} experimental=true production=refused",
        steps.len(),
        set_addr,
        a8_u,
    )
}

pub fn pack_experimental_init_write(w: S19kExperimentalInitWrite) -> [u8; 11] {
    let mut uart = [0x55, 0xAA, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let body = cmd_set_config(w.bcast, w.chip_addr, w.reg, w.value);
    uart[2..].copy_from_slice(&body);
    uart
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_inactive_is_53_not_52() {
        assert_eq!(CHAIN_INACTIVE_UART, [0x55, 0xAA, 0x53, 0x05, 0x00, 0x00, 0x03]);
        assert_eq!(GET_ADDRESS_UART[2], 0x52);
        assert_ne!(CHAIN_INACTIVE_UART[2], 0x52);
        assert_eq!(crate::s19k_bm1366_wire_b::S19K_AML_ADDR_INTERVAL, 2);
        assert_eq!(INIT_REG_VERSION_ROLL, 0xA4);
        assert!(refuse_bm1397_9byte_as_bm1366_getaddress_rx(9).is_err());
        assert!(refuse_bm1397_9byte_as_bm1366_getaddress_rx(11).is_ok());
        assert_eq!(ESP_BM1366_CHIP_ID_RX_LEN, 11);
    }

    #[test]
    fn passthrough_program_is_get_address_then_rearm_at_3m() {
        let p = s19k_bm1366_init_program(S19kInitDialect::BraiinsPassthrough);
        assert_eq!(p[0].name, "get_address");
        assert_eq!(p[0].uart, GET_ADDRESS_UART);
        let names: Vec<_> = p.iter().map(|s| s.name).collect();
        assert_eq!(
            names,
            [
                "get_address",
                "ticket_mask_diff256",
                "hash_counting_s19k",
            ]
        );
        assert!(admit_s19k_passthrough_rearm_omits_version_roll(names.as_slice()).is_ok());
        assert!(refuse_esp_9000ffff_as_braiins_fill_rearm(0xA4, ESP_BM1366_VERSION_ROLL_MASK).is_err());
        assert!(refuse_esp_9000ffff_as_braiins_fill_rearm(INIT_REG_TICKET_MASK, 0xFF).is_ok());
        assert!(!p.iter().any(|s| s.name == "chain_inactive" || s.name == "set_address"));
        let ticket = p.iter().find(|s| s.name == "ticket_mask_diff256").unwrap();
        assert_eq!(ticket.uart[2], 0x51);
        assert_eq!(ticket.uart[5], 0x14);
        assert!(admit_init_dialect_baud(S19kInitDialect::BraiinsPassthrough, 3_000_000).is_ok());
        assert!(admit_init_dialect_baud(S19kInitDialect::BraiinsPassthrough, 12_000_000).is_err());
        assert!(refuse_native_as_production(S19kInitDialect::BraiinsPassthrough).is_ok());
        assert!(refuse_native_as_production(S19kInitDialect::NativeExperimental).is_err());
        assert_eq!(init_ports(), &["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"]);
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(
            serial.contains("s19k_passthrough_rearm_writes"),
            "production GetAddress path must call shipped re-arm writes"
        );
        assert!(refuse_bosminer_movz_a4_as_set_config(
            BOSMINER_MOVZ_A4_INSN,
            BOSMINER_MOVZ_A4_LDR_INSN
        )
        .is_err());
        assert!(refuse_bosminer_9000ffff_utf16_as_version_mask(&[
            0x80, 0x00, 0x90, 0x00, 0xFF, 0xFF
        ])
        .is_err());
    }

    #[test]
    fn native_program_set_address_interval_2_and_77_slots() {
        let p = s19k_bm1366_init_program(S19kInitDialect::NativeExperimental);
        assert_eq!(p[0].name, "get_address");
        assert_eq!(p[0].uart, GET_ADDRESS_UART);
        assert_eq!(p[1].name, "init_ctrl_a8_bcast");
        assert_eq!(&p[1].uart[2..8], &[0x51, 0x09, 0x00, 0xA8, 0x00, 0x07]);
        assert_eq!(p[2].name, "misc_ctrl_bcast");
        assert_eq!(p[3].uart, CHAIN_INACTIVE_UART);
        let set_addr: Vec<_> = p.iter().filter(|s| s.name == "set_address").collect();
        assert_eq!(set_addr.len(), 77);
        assert_eq!(&set_addr[0].uart[..6], &[0x55, 0xAA, 0x40, 0x05, 0x00, 0x00]);
        // interval 2: second chip at address 2
        assert_eq!(set_addr[1].uart[4], 2);
        assert!(p.iter().any(|s| s.name == "ticket_mask_diff256"));
        assert!(p.iter().any(|s| s.name == "hash_counting_s19k"));
        assert!(!p.iter().any(|s| s.name == "version_roll"));
        let native_names: Vec<_> = p.iter().map(|s| s.name).collect();
        assert!(admit_s19k_passthrough_rearm_omits_version_roll(native_names.as_slice()).is_ok());
        assert!(refuse_esp_9000ffff_as_braiins_fill_rearm(
            VERSION_ROLL_BCAST_WRITE.reg,
            VERSION_ROLL_BCAST_WRITE.value
        )
        .is_err());
        assert!(p.iter().any(|s| s.name == "analog_mux"));
        assert!(p.iter().any(|s| s.name == "core_hash_clock"));
        assert!(p.iter().any(|s| s.name == "core_clock_delay"));
        let clock = p.iter().find(|s| s.name == "core_hash_clock").unwrap();
        assert_eq!(&clock.uart[2..8], &[0x51, 0x09, 0x00, 0x3c, 0x80, 0x00]);
        assert_eq!(clock.uart[8], 0x85);
        assert_eq!(clock.uart[9], 0x40);
        assert!(p.iter().any(|s| s.name == "misc_ctrl_bcast"));
        assert!(p.iter().any(|s| s.name == "io_driver"));
        let relay = p.iter().find(|s| s.name == "uart_relay_chip0").unwrap();
        assert_eq!(relay.uart[2], 0x41, "UART_RELAY is unicast to chip0");
        assert_eq!(relay.uart[5], 0x2C);
        assert_eq!(VERSION_ROLL_BCAST_WRITE.reg, INIT_REG_VERSION_ROLL);
        assert_eq!(VERSION_ROLL_BCAST_WRITE.value, ESP_BM1366_VERSION_ROLL_MASK);
        assert_eq!(
            pack_experimental_init_write(*VERSION_ROLL_BCAST_WRITE)[5],
            0xA4
        );
        let ticket = *TICKET_MASK_BCAST_WRITE;
        assert_eq!(ticket.reg, 0x14);
        assert_eq!(ticket.value, 0xFF);
        let hcn = *HASH_COUNTING_BCAST_WRITE;
        assert_eq!(hcn.value, 0x0000_115A);
        assert_ne!(hcn.value, 0x0000_151C, "S19XP stock HCN is not S19k");
        assert!(refuse_esp_s19xp_hcn_as_s19k_rearm(hcn.value).is_ok());
        assert!(refuse_esp_s19xp_hcn_as_s19k_rearm(ESP_BM1366_HASH_COUNTING_S19XP).is_err());
        let packed = pack_experimental_init_write(ticket);
        assert_eq!(&packed[..2], &[0x55, 0xAA]);
        assert_eq!(packed[2], 0x51);
        assert_eq!(packed[5], 0x14);
        let a8 = p
            .iter()
            .filter(|s| s.name == "init_ctrl_a8_unicast")
            .collect::<Vec<_>>();
        assert_eq!(a8.len(), 77);
        assert_eq!(a8[0].uart[2], 0x41);
        assert_eq!(a8[0].uart[4], 0);
        assert_eq!(a8[0].uart[5], 0xA8);
        assert_eq!(&a8[0].uart[6..10], &[0x00, 0x07, 0x01, 0xF0]);
        assert_eq!(a8[1].uart[4], 2);
        let boost = p
            .iter()
            .filter(|s| s.name == "core_asicboost_unicast")
            .collect::<Vec<_>>();
        assert_eq!(boost.len(), 77);
        assert_eq!(&boost[0].uart[6..10], &[0x80, 0x00, 0x82, 0xAA]);
        let misc_u = p
            .iter()
            .filter(|s| s.name == "misc_ctrl_unicast")
            .collect::<Vec<_>>();
        assert_eq!(&misc_u[0].uart[6..10], &[0xF0, 0x00, 0xC1, 0x00]);
        assert!(refuse_firmware_internals_a8_as_s19k_per_chip(0xF001_0700).is_err());
        assert!(refuse_firmware_internals_a8_as_s19k_per_chip(INIT_CTRL_A8_UNICAST).is_ok());
        assert!(refuse_native_as_production(S19kInitDialect::NativeExperimental).is_err());
        let get_idx = p.iter().position(|s| s.name == "get_address").unwrap();
        let inact_idx = p.iter().position(|s| s.name == "chain_inactive").unwrap();
        let per_idx = p.iter().position(|s| s.name == "init_ctrl_a8_unicast").unwrap();
        let hcn_idx = p.iter().position(|s| s.name == "hash_counting_s19k").unwrap();
        let pll_idx = p.iter().position(|s| s.name == "pll0_50mhz").unwrap();
        assert!(get_idx < inact_idx);
        assert!(inact_idx < per_idx);
        assert!(per_idx < pll_idx);
        assert!(pll_idx < hcn_idx);
        let pll = p.iter().find(|s| s.name == "pll0_50mhz").unwrap();
        assert_eq!(pll.uart[2], 0x51);
        assert_eq!(pll.uart[5], REG_PLL0);
        let scale = pll.uart[6];
        assert!(scale == 0x40 || scale == 0x50, "pll scale={scale:#04x}");
        assert!(!p.iter().any(|s| s.name == "fastuart_1m"));
        assert!(admit_s19k_fastuart_with_host_baud(ESP_FASTUART_HOST_BAUD).is_ok());
        assert!(admit_s19k_fastuart_with_host_baud(3_000_000).is_err());
        assert!(admit_s19k_fastuart_with_host_baud(115_200).is_err());
        let fu = s19k_native_fastuart_write();
        assert_eq!(fu.reg, PUBLIC_FASTUART_REG);
        assert_eq!(fu.value, PUBLIC_FASTUART_VALUE);
        let fu_uart = pack_experimental_init_write(fu);
        assert_eq!(&fu_uart[..2], &[0x55, 0xAA]);
        assert_eq!(&fu_uart[2..10], &[0x51, 0x09, 0x00, 0x28, 0x11, 0x30, 0x02, 0x00]);
        assert_eq!(s19k_hcn_set_config_uart()[5], INIT_REG_HASH_COUNTING);
        assert_eq!(&s19k_hcn_set_config_uart()[6..10], &[0x00, 0x00, 0x11, 0x5A]);
        assert!(refuse_bosminer_movz51_as_set_config_packer().is_err());
        assert_eq!(BOSMINER_MOVZ51_HITS, 33);
        assert_eq!(BOSMINER_MOVZ51_VOLTAGE_ALLOC_VA, 0x008C_4BFC);
        assert!(refuse_pll0_50mhz_as_s19k_stock_mining_freq(50).is_err());
        assert!(refuse_pll0_50mhz_as_s19k_stock_mining_freq(400).is_ok());
        let pll400 = s19k_native_pll0_write(400);
        assert_eq!(pll400.reg, REG_PLL0);
        assert_eq!(pll400.value, 0x40A0_0240);
        assert!(refuse_esp_fastuart_as_s19k_braiins_3m(PUBLIC_FASTUART_VALUE).is_err());
        assert!(refuse_esp_fastuart_as_s19k_braiins_3m(0).is_ok());
        let lanes = split_s19k_fastuart_reg(PUBLIC_FASTUART_VALUE);
        assert_eq!(
            (lanes.b31_24, lanes.b23_16, lanes.b15_8, lanes.b7_0),
            (0x11, 0x30, 0x02, 0x00)
        );
        assert_eq!(
            classify_s19k_uart_baud_dialect(3_000_000, None).unwrap(),
            S19kUartBaudDialect::BraiinsHost3M
        );
        assert_eq!(
            classify_s19k_uart_baud_dialect(115_200, None).unwrap(),
            S19kUartBaudDialect::Dmesg78Hold115200
        );
        assert_eq!(
            classify_s19k_uart_baud_dialect(1_000_000, Some(PUBLIC_FASTUART_VALUE)).unwrap(),
            S19kUartBaudDialect::EspChipFastUart1M
        );
        assert!(s19k_track1_classify_rx_baud(3_000_000, None).is_ok());
        assert!(s19k_track1_classify_rx_baud(3_000_000, Some("")).is_ok());
        assert!(s19k_track1_classify_rx_baud(3_000_000, Some("0x00003001")).is_err());
        assert!(s19k_track1_classify_rx_baud(1_000_000, None).is_err());
        assert_eq!(
            classify_s19k_chip_fastuart_word(None),
            S19kChipFastUartKind::Unread
        );
        assert_eq!(
            classify_s19k_chip_fastuart_word(Some(0)),
            S19kChipFastUartKind::ZeroOrDefault
        );
        assert_eq!(
            classify_s19k_chip_fastuart_word(Some),
            S19kChipFastUartKind::BibleBm1366_3m125
        );
        assert_eq!(
            classify_s19k_chip_fastuart_word(Some(BOSMINER_BM1366_REG28_VALUE)),
            S19kChipFastUartKind::BosminerBm1366_6000F
        );
        assert!(refuse_unread_fastuart_28_as_host_3m_chip_state().is_err());
        assert!(s19k_track1_classify_rx_baud_with_reg28(3_000_000, None, None).is_ok());
        assert!(s19k_track1_classify_rx_baud_with_reg28(
            3_000_000,
            None,
            Some
        )
        .is_err());
        assert_eq!(
            classify_s19k_uart_baud_dialect(3_000_000, Some(BOSMINER_BM1366_REG28_VALUE)).unwrap(),
            S19kUartBaudDialect::BosminerBm1366Reg28Experimental
        );
        assert!(s19k_track1_classify_rx_baud_with_reg28(
            3_000_000,
            Some("0x00003001"),
            Some(BOSMINER_BM1366_REG28_VALUE)
        )
        .is_ok());
        assert!(!s19k_track1_retry_115200_from_env(None).unwrap());
        assert!(s19k_track1_retry_115200_from_env(Some("1")).unwrap());
        assert!(s19k_track1_retry_115200_from_env(Some("true")).is_err());
        assert_eq!(s19k_track1_retry_restore_baud(), 3_000_000);
        assert!(refuse_115200_retry_without_restore(&s19k_track1_115200_retry_steps()).is_ok());
        assert_eq!(
            s19k_track1_115200_retry_steps()[2],
            S19kTrack1115200RetryStep::FastUart28IfGetAddressSilent
        );
        assert!(s19k_track1_should_probe_fastuart_28_at_115200(
            S19kRxDiag::GetAddressSilenceAt115200
        ));
        assert!(!s19k_track1_should_probe_fastuart_28_at_115200(
            S19kRxDiag::ChipHeardAt115200
        ));
        assert!(!s19k_track1_should_probe_fastuart_28_at_115200(
            S19kRxDiag::ChipAddressOk
        ));
        assert!(refuse_115200_retry_without_restore(&[
            S19kTrack1115200RetryStep::SetHost115200,
            S19kTrack1115200RetryStep::GetAddress
        ])
        .is_err());
        assert!(s19k_track1_should_retry_115200(
            S19kRxDiag::AsicResetOrUninit,
            S19kRxDiag::ChipFastUartUnread,
            3_000_000,
            Some("1")
        )
        .unwrap());
        assert!(!s19k_track1_should_retry_115200(
            S19kRxDiag::AsicResetOrUninit,
            S19kRxDiag::ChipFastUartUnread,
            3_000_000,
            None
        )
        .unwrap());
        assert!(!s19k_track1_should_retry_115200(
            S19kRxDiag::ChipAddressOk,
            S19kRxDiag::ChipFastUartUnread,
            3_000_000,
            Some("1")
        )
        .unwrap());
        assert!(s19k_track1_should_retry_115200(
            S19kRxDiag::AsicResetOrUninit,
            S19kRxDiag::ChipFastUartUnread,
            115_200,
            Some("1")
        )
        .is_err());
        assert!(refuse_chip_heard_at_115200_as_3m_work_proof(S19kRxDiag::ChipHeardAt115200).is_err());
        assert!(refuse_chip_heard_at_115200_as_3m_work_proof(S19kRxDiag::ChipAddressOk).is_ok());
        const SERIAL: &str = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_production_115200_retry_is_gated(SERIAL).is_ok());
        assert!(admit_s19k_production_115200_retry_drop_restores(SERIAL).is_ok());
        assert!(admit_s19k_production_restore_retries_then_refuses(SERIAL).is_ok());
        assert_eq!(
            s19k_track1_restore_baud_attempt(true, false),
            S19kTrack1RestoreBaudAttempt::FirstOk
        );
        assert_eq!(
            s19k_track1_restore_baud_attempt(false, true),
            S19kTrack1RestoreBaudAttempt::RetryOk
        );
        assert_eq!(
            s19k_track1_restore_baud_attempt(false, false),
            S19kTrack1RestoreBaudAttempt::FailedAfterRetry
        );
        assert!(refuse_restore_failed_as_3m_work_proof(
            S19kTrack1RestoreBaudAttempt::FirstOk
        )
        .is_ok());
        assert!(refuse_restore_failed_as_3m_work_proof(
            S19kTrack1RestoreBaudAttempt::RetryOk
        )
        .is_ok());
        assert!(refuse_restore_failed_as_3m_work_proof(
            S19kTrack1RestoreBaudAttempt::FailedAfterRetry
        )
        .is_err());
        assert!(refuse_work_tx_if_host_not_3m_after_restore(3_000_000).is_ok());
        assert!(refuse_work_tx_if_host_not_3m_after_restore(115_200).is_err());
        assert!(refuse_work_tx_if_host_not_3m_after_restore(1_000_000).is_err());
        let mut guard = S19kTrack1BaudRestoreGuard::arm_after_115200();
        assert!(guard.restore_owed());
        assert_eq!(guard.take_restore(), Some(3_000_000));
        assert!(!guard.restore_owed());
        assert_eq!(guard.take_restore(), None);
        {
            let g = S19kTrack1BaudRestoreGuard::arm_after_115200();
            assert!(g.restore_owed());
        }
        assert_eq!(s19k_track1_baud_restore_on_drop(true), Some(3_000_000));
        assert_eq!(s19k_track1_baud_restore_on_drop(false), None);
        assert_eq!(
            s19k_track1_chip_fastuart_from_env(Some("0x00003001")),
            Some(0x0000_3001)
        );
        assert_eq!(s19k_track1_chip_fastuart_from_env(None), None);
        assert!(classify_s19k_uart_baud_dialect(3_000_000, Some(PUBLIC_FASTUART_VALUE)).is_err());
        assert!(classify_s19k_uart_baud_dialect(115_200, Some(PUBLIC_FASTUART_VALUE)).is_err());
        assert!(refuse_bm1366_3001_as_s19k_braiins_3m.is_err());
        assert!(refuse_bm1366_3001_as_s19k_braiins_3m(0).is_ok());
        assert!(refuse_bm1362_3011_as_s19k_braiins_3m.is_err());
        assert!(refuse_bm1362_3011_as_s19k_braiins_3m(0).is_ok());
        assert!(refuse_bosminer_movz_3001_as_fastuart().is_err());
        assert!(refuse_bosminer_am2_set_baud_as_s19k_aml().is_err());
        assert!(refuse_bosminer_tuner_write_reg_display_as_uart().is_err());
        assert!(refuse_bosminer_miscctrl_modify_as_fastuart_28().is_err());
        assert!(classify_s19k_uart_baud_dialect(3_000_000, Some).is_err());
        assert!(classify_s19k_uart_baud_dialect(3_000_000, Some).is_err());
        assert!(classify_s19k_uart_baud_dialect(3_125_000, None).is_err());
        assert!(admit_s19k_bible_fastuart_3125k_with_host_baud.is_ok());
        assert!(admit_s19k_bible_fastuart_3125k_with_host_baud(3_000_000).is_err());
        assert!(admit_s19k_bible_fastuart_3125k_with_host_baud(115_200).is_err());
        let fu3125 = s19k_native_fastuart_bible_3125k_write();
        assert_eq!(fu3125.reg, PUBLIC_FASTUART_REG);
        assert_eq!(fu3125.value, );
        let fu3125_uart = pack_experimental_init_write(fu3125);
        assert_eq!(
            &fu3125_uart[2..10],
            &[0x51, 0x09, 0x00, 0x28, 0x00, 0x00, 0x30, 0x01]
        );
        assert!(!p.iter().any(|s| s.name == "fastuart_bible_3125k"));
        let constructed_3011 = {
            let mut v = vec![0u8; BOSMINER_REG28_3011_FILE_OFF as usize + 6];
            v[BOSMINER_REG28_3011_FILE_OFF as usize..]
                .copy_from_slice(&[0x28, 0x00, 0x00, 0x00, 0x30, 0x11]);
            v
        };
        assert!(admit_bosminer_contains_reg28_fastuart_be(
            &constructed_3011,
            BOSMINER_REG28_3011_FILE_OFF,
            
        )
        .is_ok());
        let constructed_3001 = {
            let mut v = vec![0u8; BOSMINER_REG28_3001_FILE_OFF as usize + 6];
            v[BOSMINER_REG28_3001_FILE_OFF as usize..]
                .copy_from_slice(&[0x28, 0x00, 0x00, 0x00, 0x30, 0x01]);
            v
        };
        assert!(admit_bosminer_contains_reg28_fastuart_be(
            &constructed_3001,
            BOSMINER_REG28_3001_FILE_OFF,
            
        )
        .is_ok());
        assert!(admit_bosminer_contains_reg28_fastuart_be(&[0u8; 8], 0, ).is_err());
        assert_eq!(BOSMINER_REG28_3011_VA, 0x017C_0A28);
        assert_eq!(BOSMINER_REG28_3001_VA, 0x0182_FA28);
        assert_eq!(BOSMINER_COMMAND_RS_READ_REGISTER_FN_VA, 0x008A_9044);
        assert_eq!(BOSMINER_UART_BE4_SEND_FN_VA, 0x008A_200C);
        assert_eq!(BOSMINER_MISCCTRL_MODIFY_FN_VA, 0x008B_40DC);
        assert_eq!(BOSMINER_AM2_SET_BAUD_FN_VA, 0x0083_6934);
        assert_eq!(BOSMINER_SETCFG_51_09_00_28_HITS, 0);
        assert_eq!(BOSMINER_UART_BE4_SEND_BL_HITS, 4);
        assert_eq!(BOSMINER_UART_BE4_SEND_BL_VA[0], 0x0083_6C3C);
        assert!(refuse_bosminer_file_setcfg_28_as_s19k_fastuart(0).is_err());
        assert!(refuse_uart_be4_send_callers_as_s19k_aml_fastuart().is_err());
        assert!(refuse_movz_imm28_as_fastuart_reg(1897).is_err());
        assert_eq!(BOSMINER_HOST_TERMIOS_CALLER_FN_VA, 0x008F_E748);
        assert_eq!(BOSMINER_HOST_TERMIOS_FN_VA, 0x00BB_E3D4);
        assert_eq!(BOSMINER_ANTMINER_AML_RS_VA, 0x0139_2558);
        assert_eq!(BOSMINER_MOVZ_X1_3001_VA_A, 0x010B_A39C);
        assert_eq!(BOSMINER_MOVZ_X1_3001_VA_B, 0x010C_49D8);
        assert!(refuse_bosminer_be4_send_as_s19k_set_config().is_err());
        assert!(refuse_bosminer_ascii_set_config_as_packer().is_err());
        assert_eq!(BOSMINER_PACKED_STRUCT_PACKING_RS_VA, 0x0131_BE45);
        assert_eq!(BOSMINER_WRITE_VERIFY_STR_FILE_OFF, 0x00F2_0197);
        assert_eq!(BOSMINER_WRITE_VERIFY_STR_VA, 0x0132_0197);
        let generic = s19k_generic_set_config_uart(0x10, 0x0000_115A);
        assert_eq!(&generic[..2], &[0x55, 0xAA]);
        assert_eq!(&generic[2..10], &[0x51, 0x09, 0x00, 0x10, 0x00, 0x00, 0x11, 0x5A]);
        assert_eq!(generic, s19k_hcn_set_config_uart());
        let constructed_wv = {
            let mut v = vec![0u8; BOSMINER_WRITE_VERIFY_STR_FILE_OFF as usize + 48];
            let n = b"values were not written correctly to register";
            v[BOSMINER_WRITE_VERIFY_STR_FILE_OFF as usize
                ..BOSMINER_WRITE_VERIFY_STR_FILE_OFF as usize + n.len()]
                .copy_from_slice(n);
            v
        };
        assert!(admit_bosminer_contains_write_verify_str(&constructed_wv).is_ok());
        assert!(admit_bosminer_contains_write_verify_str(&[0u8; 8]).is_err());
        assert_eq!(BOSMINER_PACKED_STRUCT_PACK_FN_VA, 0x008A_8D28);
        assert_eq!(BOSMINER_COMMAND_RS_WRITE_FN_VA, 0x008B_1B98);
        assert_eq!(BOSMINER_BM1398_READ_FN_VA, 0x008B_2B34);
        assert_eq!(BOSMINER_PACK_BL_HITS, 3);
        assert!(admit_bosminer_pack_bl_sites().is_ok());
        assert!(refuse_command_rs_write_as_s19k_aml_set_config().is_err());
        assert!(refuse_pack_fn_as_s19k_exclusive_set_config().is_err());
        assert!(refuse_write_loc_ptr_as_aml_vtable().is_err());
        assert_eq!(BOSMINER_BM1398_RS_LOC_STR.len(), BOSMINER_BM1398_RS_LOC_STR_LEN as usize);
        let mut loc = vec![0u8; BOSMINER_READ_LOC_PTR_FILE_OFF as usize + 24];
        let woff = BOSMINER_WRITE_LOC_PTR_FILE_OFF as usize;
        loc[woff..woff + 8]
            .copy_from_slice(&BOSMINER_COMMAND_RS_WRITE_FN_VA.to_le_bytes());
        loc[woff + 8..woff + 16]
            .copy_from_slice(&BOSMINER_BM1398_RS_LOC_STR_VA.to_le_bytes());
        loc[woff + 16..woff + 24]
            .copy_from_slice(&u64::from(BOSMINER_BM1398_RS_LOC_STR_LEN).to_le_bytes());
        let soff = BOSMINER_BM1398_RS_LOC_STR_FILE_OFF as usize;
        loc[soff..soff + BOSMINER_BM1398_RS_LOC_STR.len()]
            .copy_from_slice(BOSMINER_BM1398_RS_LOC_STR);
        let roff = BOSMINER_READ_LOC_PTR_FILE_OFF as usize;
        loc[roff..roff + 8].copy_from_slice(&BOSMINER_BM1398_READ_FN_VA.to_le_bytes());
        loc[roff + 8..roff + 16]
            .copy_from_slice(&BOSMINER_BM1398_RS_LOC_STR_VA.to_le_bytes());
        assert!(admit_bosminer_write_loc_is_bm1398_rs(&loc).is_ok());
        assert!(admit_bosminer_read_loc_is_bm1398_rs(&loc).is_ok());
        loc[woff] ^= 1;
        assert!(admit_bosminer_write_loc_is_bm1398_rs(&loc).is_err());
        assert_eq!(
            BOSMINER_BM1366_RS_LOC_STR,
            crate::s19k_braiins_job::BOSMINER_BM1366_RS.as_bytes()
        );
        assert_eq!(BOSMINER_BM1366_LOC_FNS[1], BOSMINER_BM1366_FIRST_METHOD_FN_VA);
        assert_eq!(BOSMINER_BM1366_DISPATCH_BL_HITS, 48);
        assert_eq!(BOSMINER_BM1366_DISPATCH_BL_IN_LOC_CLUSTER, 39);
        assert!(refuse_bm1366_loc_fns_as_direct_pack_callers().is_err());
        assert!(refuse_bm1366_packed_dispatch_as_named_fastuart().is_err());
        let dfile = (BOSMINER_BM1366_PACKED_DISPATCH_FN_VA - 0x400_000) as usize;
        let pfile = (BOSMINER_PACK_LDRB_VA - 0x400_000) as usize;
        let moff = BOSMINER_BM1366_FIRST_METHOD_LOC_FILE_OFF as usize;
        let s66 = BOSMINER_BM1366_RS_LOC_STR_FILE_OFF as usize;
        let afile = (BOSMINER_DISPATCH_ARC_LIKE_FN_VA - 0x400_000) as usize;
        let need = (moff + 24)
            .max(dfile + 0x98)
            .max(pfile + 4)
            .max(afile + 4)
            .max(s66 + BOSMINER_BM1366_RS_LOC_STR.len());
        let mut loc66 = vec![0u8; need];
        loc66[moff..moff + 8]
            .copy_from_slice(&BOSMINER_BM1366_FIRST_METHOD_FN_VA.to_le_bytes());
        loc66[moff + 8..moff + 16]
            .copy_from_slice(&BOSMINER_BM1366_RS_LOC_STR_VA.to_le_bytes());
        loc66[moff + 16..moff + 24]
            .copy_from_slice(&u64::from(BOSMINER_BM1366_RS_LOC_STR_LEN).to_le_bytes());
        loc66[s66..s66 + BOSMINER_BM1366_RS_LOC_STR.len()]
            .copy_from_slice(BOSMINER_BM1366_RS_LOC_STR);
        loc66[dfile + 8..dfile + 12]
            .copy_from_slice(&BOSMINER_BM1366_PACKED_DISPATCH_LDRB_INSN.to_le_bytes());
        loc66[dfile + 0x10..dfile + 0x14]
            .copy_from_slice(&BOSMINER_BM1366_DISPATCH_CMP3_INSN.to_le_bytes());
        loc66[dfile + 0x14..dfile + 0x18]
            .copy_from_slice(&BOSMINER_BM1366_DISPATCH_BEQ3_INSN.to_le_bytes());
        loc66[dfile + 0x18..dfile + 0x1C]
            .copy_from_slice(&BOSMINER_BM1366_DISPATCH_CMP4_INSN.to_le_bytes());
        loc66[dfile + 0x20..dfile + 0x24]
            .copy_from_slice(&BOSMINER_BM1366_DISPATCH_LDP_INSN.to_le_bytes());
        loc66[dfile + 0x24..dfile + 0x28]
            .copy_from_slice(&BOSMINER_BM1366_DISPATCH_LDR_V0_INSN.to_le_bytes());
        loc66[dfile + 0x30..dfile + 0x34]
            .copy_from_slice(&BOSMINER_BM1366_PACKED_DISPATCH_BLR_INSN.to_le_bytes());
        loc66[dfile + 0x90..dfile + 0x94]
            .copy_from_slice(&BOSMINER_BM1366_DISPATCH_TAG3_SLOT_LDR_INSN.to_le_bytes());
        loc66[dfile + 0x94..dfile + 0x98]
            .copy_from_slice(&BOSMINER_BM1366_PACKED_DISPATCH_BLR_INSN.to_le_bytes());
        loc66[pfile..pfile + 4]
            .copy_from_slice(&BOSMINER_BM1366_PACKED_DISPATCH_LDRB_INSN.to_le_bytes());
        loc66[afile..afile + 4]
            .copy_from_slice(&BOSMINER_DISPATCH_ARC_LIKE_CBZ_INSN.to_le_bytes());
        assert!(admit_bosminer_bm1366_first_method_loc(&loc66).is_ok());
        assert!(admit_bosminer_bm1366_packed_dispatch(&loc66).is_ok());
        assert!(admit_bosminer_dispatch_tag_3_or_4(&loc66).is_ok());
        assert!(admit_bosminer_blr_x8_is_fat_ptr_vtable0(&loc66).is_ok());
        assert!(admit_bosminer_tag3_blr_is_vtable_plus18(&loc66).is_ok());
        assert!(refuse_blr_x8_as_named_text_write_reg().is_err());
        assert!(refuse_dispatch_arc_like_as_uart_write(&loc66).is_err());
        assert_eq!(BOSMINER_BM1366_DISPATCH_FAT_PTR_OFF, 0x78);
        assert_eq!(BOSMINER_BM1366_DISPATCH_VTABLE_SLOT, 0x18);
        let voff = BOSMINER_FAT_PTR_VTABLE_FILE_OFF as usize;
        let need2 = need
            .max(voff + 32)
            .max(BOSMINER_PSU_PROTOCOL_RS_FILE_OFF as usize + BOSMINER_PSU_PROTOCOL_RS.len())
            .max((BOSMINER_FAT_PTR_VTABLE_METHOD_VA - 0x400_000) as usize + 0x1C)
            .max((BOSMINER_FAT_PTR_VTABLE_ADD_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_FAT_PTR_STP_VA - 0x400_000) as usize + 4);
        loc66.resize(need2, 0);
        loc66[voff..voff + 8].copy_from_slice(&BOSMINER_FAT_PTR_VTABLE_DROP.to_le_bytes());
        loc66[voff + 8..voff + 16]
            .copy_from_slice(&BOSMINER_FAT_PTR_VTABLE_SIZE.to_le_bytes());
        loc66[voff + 16..voff + 24]
            .copy_from_slice(&BOSMINER_FAT_PTR_VTABLE_ALIGN.to_le_bytes());
        loc66[voff + 24..voff + 32]
            .copy_from_slice(&BOSMINER_FAT_PTR_VTABLE_METHOD_VA.to_le_bytes());
        let psu = BOSMINER_PSU_PROTOCOL_RS_FILE_OFF as usize;
        loc66[psu..psu + BOSMINER_PSU_PROTOCOL_RS.len()]
            .copy_from_slice(BOSMINER_PSU_PROTOCOL_RS);
        let mva = (BOSMINER_FAT_PTR_VTABLE_METHOD_VA - 0x400_000) as usize;
        loc66[mva..mva + 4].copy_from_slice(&BOSMINER_VTABLE_METHOD_MOV_INSN.to_le_bytes());
        loc66[mva + 0x18..mva + 0x1C]
            .copy_from_slice(&BOSMINER_VTABLE_METHOD_BR_INSN.to_le_bytes());
        let addf = (BOSMINER_FAT_PTR_VTABLE_ADD_VA - 0x400_000) as usize;
        loc66[addf..addf + 4].copy_from_slice(&BOSMINER_FAT_PTR_VTABLE_ADD_INSN.to_le_bytes());
        let stpf = (BOSMINER_FAT_PTR_STP_VA - 0x400_000) as usize;
        loc66[stpf..stpf + 4].copy_from_slice(&BOSMINER_FAT_PTR_STP_INSN.to_le_bytes());
        assert!(admit_bosminer_fat_ptr_vtable_layout(&loc66).is_ok());
        assert!(admit_bosminer_fat_ptr_vtable_loc_is_psu_protocol(&loc66).is_ok());
        assert!(admit_bosminer_fat_ptr_vtable_install(&loc66).is_ok());
        assert!(refuse_vtable_method_as_uart_write_reg(&loc66).is_err());
        let hstr = BOSMINER_HASHCHAIN_RS_LOC_STR_FILE_OFF as usize;
        let hloc = BOSMINER_HASHCHAIN_PLUS78_LOC_FILE_OFF as usize;
        let stp78 = (BOSMINER_HASHCHAIN_PLUS78_STP_VA - 0x400_000) as usize;
        let sib = (BOSMINER_HASHCHAIN_SIBLING_PACK_FN_VA - 0x400_000) as usize;
        let alt = (BOSMINER_HASHCHAIN_ALT_STP_VA - 0x400_000) as usize;
        let need3 = need2
            .max(hstr + BOSMINER_HASHCHAIN_RS_LOC_STR.len())
            .max(hloc + 32)
            .max(stp78 + 4)
            .max((BOSMINER_HASHCHAIN_PLUS78_INNER_LDR_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_HASHCHAIN_PLUS78_DEREF_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_HASHCHAIN_PLUS78_ADD158_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_HASHCHAIN_PLUS78_ADD10_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_HASHCHAIN_PACKED_X0_ADD_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_HASHCHAIN_DISPATCH_BL_VA - 0x400_000) as usize + 4)
            .max(sib + 0x38)
            .max(alt + 4);
        loc66.resize(need3, 0);
        loc66[hstr..hstr + BOSMINER_HASHCHAIN_RS_LOC_STR.len()]
            .copy_from_slice(BOSMINER_HASHCHAIN_RS_LOC_STR);
        loc66[hloc..hloc + 8]
            .copy_from_slice(&BOSMINER_HASHCHAIN_PLUS78_FN_VA.to_le_bytes());
        loc66[hloc + 8..hloc + 16]
            .copy_from_slice(&BOSMINER_HASHCHAIN_RS_LOC_STR_VA.to_le_bytes());
        loc66[hloc + 16..hloc + 24]
            .copy_from_slice(&u64::from(BOSMINER_HASHCHAIN_RS_LOC_STR_LEN).to_le_bytes());
        let line_col = u64::from(BOSMINER_HASHCHAIN_PLUS78_LOC_LINE)
            | (u64::from(BOSMINER_HASHCHAIN_PLUS78_LOC_COL) << 32);
        loc66[hloc + 24..hloc + 32].copy_from_slice(&line_col.to_le_bytes());
        let put_insn = |buf: &mut [u8], va: u64, insn: u32| {
            let o = (va - 0x400_000) as usize;
            buf[o..o + 4].copy_from_slice(&insn.to_le_bytes());
        };
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_PLUS78_INNER_LDR_VA,
            BOSMINER_HASHCHAIN_PLUS78_INNER_LDR_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_PLUS78_DEREF_VA,
            BOSMINER_HASHCHAIN_PLUS78_DEREF_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_PLUS78_ADD158_VA,
            BOSMINER_HASHCHAIN_PLUS78_ADD158_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_PLUS78_ADD10_VA,
            BOSMINER_HASHCHAIN_PLUS78_ADD10_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_PLUS78_STP_VA,
            BOSMINER_HASHCHAIN_PLUS78_STP_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_PACKED_X0_ADD_VA,
            BOSMINER_HASHCHAIN_PACKED_X0_ADD_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_SIBLING_PACK_BL_VA[1],
            BOSMINER_HASHCHAIN_SIBLING_PACK_BL_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_DISPATCH_BL_VA,
            BOSMINER_HASHCHAIN_DISPATCH_BL_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_SIBLING_PACK_MOV_X19_VA,
            BOSMINER_HASHCHAIN_SIBLING_PACK_MOV_X19_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_SIBLING_PACK_LDRB_VA,
            BOSMINER_BM1366_PACKED_DISPATCH_LDRB_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_SIBLING_PACK_CMP2_VA,
            BOSMINER_HASHCHAIN_SIBLING_PACK_CMP2_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_SIBLING_PACK_CMP3_VA,
            BOSMINER_BM1366_DISPATCH_CMP3_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_SIBLING_PACK_LDP10_VA,
            BOSMINER_HASHCHAIN_SIBLING_PACK_LDP10_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_ALT_STP_VA,
            BOSMINER_HASHCHAIN_ALT_STP_INSN,
        );
        assert!(admit_bosminer_plus78_fn_loc_is_hashchain_rs(&loc66).is_ok());
        assert!(admit_bosminer_hashchain_plus78_operands(&loc66).is_ok());
        assert!(admit_bosminer_sibling_pack_tag_dispatch(&loc66).is_ok());
        assert!(admit_bosminer_hashchain_plus78_calls_sibling_then_dispatch(&loc66).is_ok());
        assert!(admit_bosminer_hashchain_alt_fat_ptr_pattern(&loc66).is_ok());
        assert!(refuse_hashchain_plus78_as_psu_rodata_vtable().is_err());
        assert!(refuse_hashchain_plus78_second_as_text_fastuart().is_err());
        assert_eq!(BOSMINER_HASHCHAIN_PLUS78_INLINE_OFF, 0x158);
        assert_eq!(BOSMINER_HASHCHAIN_PACKED_OBJ_OFF, 0x68);
        let fu_str = BOSMINER_LEGACY_FASTUART_FAIL_STR_FILE_OFF as usize;
        let fu_rs = BOSMINER_BM139X_RS_LOC_STR_FILE_OFF as usize;
        let fu_loc = BOSMINER_BM139X_FASTUART_LOC_FILE_OFF as usize;
        let need4 = need3
            .max(fu_str + BOSMINER_LEGACY_FASTUART_FAIL_STR.len())
            .max(fu_rs + BOSMINER_BM139X_RS_LOC_STR.len())
            .max(fu_loc + 24)
            .max((BOSMINER_LEGACY_FASTUART_PANIC_ADD_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_LEGACY_FASTUART_PACK_RET_VA - 0x400_000) as usize + 4);
        loc66.resize(need4, 0);
        loc66[fu_str..fu_str + BOSMINER_LEGACY_FASTUART_FAIL_STR.len()]
            .copy_from_slice(BOSMINER_LEGACY_FASTUART_FAIL_STR);
        loc66[fu_rs..fu_rs + BOSMINER_BM139X_RS_LOC_STR.len()]
            .copy_from_slice(BOSMINER_BM139X_RS_LOC_STR);
        loc66[fu_loc..fu_loc + 8]
            .copy_from_slice(&BOSMINER_BM139X_RS_LOC_STR_VA.to_le_bytes());
        loc66[fu_loc + 8..fu_loc + 16]
            .copy_from_slice(&u64::from(BOSMINER_BM139X_RS_LOC_STR_LEN).to_le_bytes());
        let fu_lc = u64::from(BOSMINER_BM139X_FASTUART_LOC_LINE)
            | (u64::from(BOSMINER_BM139X_FASTUART_LOC_COL) << 32);
        loc66[fu_loc + 16..fu_loc + 24].copy_from_slice(&fu_lc.to_le_bytes());
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_PANIC_ADD_VA,
            BOSMINER_LEGACY_FASTUART_PANIC_ADD_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_PACK_BEQ_VA,
            BOSMINER_LEGACY_FASTUART_PACK_BEQ_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_PACK_RET_VA,
            BOSMINER_LEGACY_FASTUART_PACK_RET_INSN,
        );
        assert!(admit_bosminer_legacy_fastuart_fail_str(&loc66).is_ok());
        assert!(admit_bosminer_legacy_fastuart_loc_is_bm139x_rs(&loc66).is_ok());
        assert!(admit_bosminer_legacy_fastuart_panic_former(&loc66).is_ok());
        assert!(admit_bosminer_legacy_fastuart_pack_beq_panic(&loc66).is_ok());
        assert!(refuse_legacy_fastuart_panic_as_uart_write().is_err());
        assert!(refuse_legacy_fastuart_as_s19k_host_3m().is_err());
        let need5 = need4
            .max((BOSMINER_LEGACY_FASTUART_DIV_UDIV_RET_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_LEGACY_FASTUART_FIELDS_BL_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_LEGACY_FASTUART_STRB_D_VA - 0x400_000) as usize + 4);
        loc66.resize(need5, 0);
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_DIV_FN_VA + 4,
            BOSMINER_LEGACY_FASTUART_DIV_LDRB7_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_DIV_LSR24_VA,
            BOSMINER_LEGACY_FASTUART_DIV_LSR24_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_DIV_CMP255_VA,
            BOSMINER_LEGACY_FASTUART_DIV_CMP255_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_DIV_UDIV_RET_VA,
            BOSMINER_LEGACY_FASTUART_DIV_UDIV_RET_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_FIELDS_FN_VA,
            BOSMINER_LEGACY_FASTUART_FIELDS_UBFX_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_FIELDS_CMP1_VA,
            BOSMINER_LEGACY_FASTUART_FIELDS_CMP1_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_STRH0_VA,
            BOSMINER_LEGACY_FASTUART_STRH0_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_STRB_C_VA,
            BOSMINER_LEGACY_FASTUART_STRB_C_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_STRB_D_VA,
            BOSMINER_LEGACY_FASTUART_STRB_D_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_FIELDS_BL_VA,
            BOSMINER_LEGACY_FASTUART_FIELDS_BL_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0_VA,
            BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0_INSN,
        );
        assert!(admit_bosminer_legacy_fastuart_divisor_path(&loc66).is_ok());
        assert!(admit_bosminer_legacy_fastuart_fields_layout(&loc66).is_ok());
        assert!(admit_bosminer_legacy_fastuart_fields_caller(&loc66).is_ok());
        assert!(refuse_reg28_3001_as_legacy_fastuart_pack().is_err());
        assert!(refuse_legacy_fastuart_divisor_as_3001().is_err());
        assert!(refuse_bm1398_pack_call_as_bible_3001().is_err());
        assert_ne!(
            BOSMINER_LEGACY_FASTUART_PACKED_LEN,
            BOSMINER_REG28_FASTUART_DATA_LEN
        );
        assert_ne!(BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0, );
        assert_ne!(BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0, );
        assert_eq!(BOSMINER_LEGACY_FASTUART_DIV_FN_VA, BOSMINER_LEGACY_FASTUART_PACK_FN_VA);
        let fptr = BOSMINER_LEGACY_FASTUART_DIV_FPTR_FILE_OFF as usize;
        let need6 = need5
            .max(fptr + 16)
            .max((BOSMINER_HASHCHAIN_DUP88_STP_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_HASHCHAIN_BLR78_STP_VA - 0x400_000) as usize + 4);
        loc66.resize(need6, 0);
        loc66[fptr..fptr + 8]
            .copy_from_slice(&BOSMINER_LEGACY_FASTUART_DIV_FN_VA.to_le_bytes());
        loc66[fptr - 8..fptr]
            .copy_from_slice(&BOSMINER_LEGACY_FASTUART_DIV_FPTR_PREV.to_le_bytes());
        loc66[fptr + 8..fptr + 16]
            .copy_from_slice(&BOSMINER_LEGACY_FASTUART_DIV_FPTR_NEXT.to_le_bytes());
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_DUP78_LDP_VA,
            BOSMINER_HASHCHAIN_DUP78_LDP_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_DUP78_STP_VA,
            BOSMINER_HASHCHAIN_DUP78_STP_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_DUP88_STP_VA,
            BOSMINER_HASHCHAIN_DUP88_STP_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_HASHCHAIN_BLR78_STP_VA,
            BOSMINER_HASHCHAIN_BLR78_STP_INSN,
        );
        assert!(admit_bosminer_legacy_fastuart_div_fptr(&loc66).is_ok());
        assert!(refuse_div_fptr_neighbors_as_uart_write().is_err());
        assert!(admit_bosminer_hashchain_dup78_88_copy(&loc66).is_ok());
        assert!(refuse_hashchain_dup88_as_engine_nonce_fn().is_err());
        assert!(admit_bosminer_hashchain_blr78_consume(&loc66).is_ok());
        let mut need7 = need6;
        for &va in &BOSMINER_HASHCHAIN_BLR78_FAMILY_VA {
            need7 = need7.max((va - 0x400_000) as usize + 4);
        }
        loc66.resize(need7, 0);
        for &va in &BOSMINER_HASHCHAIN_BLR78_FAMILY_VA {
            put_insn(&mut loc66, va - 8, BOSMINER_HASHCHAIN_BLR78_MOV_INSN);
            put_insn(&mut loc66, va - 4, BOSMINER_HASHCHAIN_BLR78_BLR_INSN);
            put_insn(&mut loc66, va, BOSMINER_HASHCHAIN_BLR78_STP_INSN);
        }
        assert!(admit_bosminer_hashchain_blr78_family(&loc66).is_ok());
        assert!(refuse_blr78_family_as_engine_plus88().is_err());
        assert_eq!(BOSMINER_HASHCHAIN_BLR78_FAMILY_HITS, 7);
        assert_eq!(
            crate::s19k_braiins_job::BOSMINER_HASHCHAIN_STR88_SELF_PTR_HITS,
            5
        );
        let need8 = need7
            .max((BOSMINER_LEGACY_FASTUART_STRB_5_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_LEGACY_FASTUART_W1_LDR8_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_NESTED88_STR_VA[1] - 0x400_000) as usize + 4)
            .max(
                BOSMINER_FASTUART_FIELDS_STR_FILE_OFF as usize
                    + BOSMINER_FASTUART_NAMED_BIT_BLOB.len(),
            );
        loc66.resize(need8, 0);
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_W13_UBFIZ_VA,
            BOSMINER_LEGACY_FASTUART_W13_UBFIZ_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_W13_BFXIL_VA,
            BOSMINER_LEGACY_FASTUART_W13_BFXIL_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_STRB_5_VA,
            BOSMINER_LEGACY_FASTUART_STRB_5_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2_VA,
            BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W3_VA,
            BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W3_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_W1_LDR8_VA,
            BOSMINER_LEGACY_FASTUART_W1_LDR8_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_W1_LDRB_VA,
            BOSMINER_LEGACY_FASTUART_W1_LDRB_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_LEGACY_FASTUART_W1_SUB1_VA,
            BOSMINER_LEGACY_FASTUART_W1_SUB1_INSN,
        );
        for i in 0..BOSMINER_NESTED88_HITS {
            put_insn(
                &mut loc66,
                BOSMINER_NESTED88_LDR30_VA[i],
                BOSMINER_NESTED88_LDR30_INSN,
            );
            put_insn(
                &mut loc66,
                BOSMINER_NESTED88_ADD18_VA[i],
                BOSMINER_NESTED88_ADD18_INSN[i],
            );
            put_insn(
                &mut loc66,
                BOSMINER_NESTED88_STR_VA[i],
                BOSMINER_NESTED88_STR_INSN[i],
            );
        }
        let fname = BOSMINER_FASTUART_FIELDS_STR_FILE_OFF as usize;
        loc66[fname..fname + BOSMINER_FASTUART_NAMED_BIT_BLOB.len()]
            .copy_from_slice(BOSMINER_FASTUART_NAMED_BIT_BLOB);
        assert!(admit_bosminer_legacy_fastuart_w13_map(&loc66).is_ok());
        assert!(admit_bosminer_legacy_fastuart_w1_ldrb_sub1(&loc66).is_ok());
        assert!(admit_bosminer_fastuart_field_name_blob(&loc66).is_ok());
        assert!(admit_bosminer_fastuart_named_bit_blob(&loc66).is_ok());
        assert!(admit_bosminer_nested88_plus18_family(&loc66).is_ok());
        assert!(refuse_legacy_fastuart_dest5_as_bible_3001().is_err());
        assert!(refuse_fastuart_field_names_as_dest_byte_map().is_err());
        assert!(refuse_nested88_plus18_as_engine_nonce_fn().is_err());
        assert!(bosminer_legacy_fastuart_enum_ok(
            BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W0
        ));
        assert!(!bosminer_legacy_fastuart_enum_ok(0b1000));
        assert_eq!(bosminer_legacy_fastuart_w13(6, 0), 0x20);
        assert_eq!(bosminer_legacy_fastuart_w13(6, 0x53), 0x25);
        let packed0 = pack_bosminer_legacy_fastuart_bm1398_write_instance(0);
        assert_eq!(
            packed0,
            [0x80, 0, 0, 0, 1, 0x20, 0, 0, 0, 0, 0, 0x0F, 0, 0]
        );
        assert_eq!(
            packed0[BOSMINER_LEGACY_FASTUART_DEST_W13_OFF],
            bosminer_legacy_fastuart_w13(6, 0)
        );
        assert_eq!(
            packed0[BOSMINER_LEGACY_FASTUART_DEST_W2_OFF],
            BOSMINER_LEGACY_FASTUART_FIELDS_CALLER_W2 as u8
        );
        assert_eq!(
            packed0[BOSMINER_LEGACY_FASTUART_DEST_ENUM_OFF],
            bosminer_legacy_fastuart_enum_field(6)
        );
        assert_ne!(
            u32::from_be_bytes([packed0[0], packed0[1], packed0[2], packed0[3]]),
            
        );
        let packed53 = pack_bosminer_legacy_fastuart_bm1398_write_instance(0x53);
        assert_eq!(packed53[1], 1);
        assert_eq!(packed53[5], 0x25);
        assert_eq!(packed53[6], 0);
        assert_eq!(packed53[7], 1);
        assert_eq!(BOSMINER_NESTED88_HITS, 2);
        assert_eq!(BOSMINER_LEGACY_FASTUART_W1_LDRB_OFF, 0x22C);
        let named_3001 = decode_bosminer_fastuart_reg_named;
        assert!(!named_3001.ext_baud_enable);
        assert!(named_3001.unknown_bit_13);
        assert!(!named_3001.unknown_bit_15);
        assert_eq!(named_3001.unknown_bits_31_28, 0);
        let named_3011 = decode_bosminer_fastuart_reg_named;
        assert!(!named_3011.ext_baud_enable);
        assert!(named_3011.unknown_bit_13);
        assert!(refuse_bible_3001_as_ext_baud_enable.is_err());
        assert!(refuse_rfs_tfs_width_as_named().is_err());
        assert!(BOSMINER_FASTUART_NAMED_BIT_BLOB.windows(3).any(|w| w == BOSMINER_FASTUART_RFS_STR));
        assert!(BOSMINER_FASTUART_NAMED_BIT_BLOB.windows(3).any(|w| w == BOSMINER_FASTUART_TFS_STR));
        assert_eq!(BOSMINER_FASTUART_EXT_BAUD_ENABLE_BIT, 16);
        let need9 = need8
            .max((BOSMINER_FASTUART_22C_XTAL_MOVK_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_FASTUART_22C_SIBLING_LDRB_VA - 0x400_000) as usize + 4);
        loc66.resize(need9, 0);
        put_insn(
            &mut loc66,
            BOSMINER_FASTUART_22C_SIBLING_LDRB_VA,
            BOSMINER_FASTUART_22C_SIBLING_LDRB_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_FASTUART_22C_XTAL_MOVZ_VA,
            BOSMINER_FASTUART_22C_XTAL_MOVZ_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_FASTUART_22C_XTAL_MOVK_VA,
            BOSMINER_FASTUART_22C_XTAL_MOVK_INSN,
        );
        assert!(admit_bosminer_fastuart_22c_xtal25(&loc66).is_ok());
        assert!(refuse_xtal25_div8_as_s19k_host_3m().is_err());
        assert!(refuse_plus22c_as_engine_nonce_fn().is_err());
        assert_eq!(
            bosminer_xtal25_divisor_baud(BOSMINER_FASTUART_22C_),
            Some
        );
        assert_ne!(
            bosminer_xtal25_divisor_baud(BOSMINER_FASTUART_22C_).unwrap(),
            3_000_000
        );
        assert_eq!(bosminer_xtal25_divisor_baud(25), Some(ESP_FASTUART_HOST_BAUD));
        assert_eq!(bosminer_fastuart_w1_to_div_byte(7), Some(8));
        assert_eq!(BOSMINER_FASTUART_22C_LDRB_HITS, 12);
        assert_eq!(BOSMINER_FASTUART_22C_XTAL_HZ, 25_000_000);
        let mut need10 = need9
            .max(BOSMINER_ANTMINER_AML_RS_FILE_OFF as usize + BOSMINER_ANTMINER_AML_RS.len())
            .max(BOSMINER_NIX_TERMIOS_RS_FILE_OFF as usize + BOSMINER_NIX_TERMIOS_RS.len());
        for &va in BOSMINER_HOST_3M_MOVZ_VA
            .iter()
            .chain(BOSMINER_B3000000_MOVZ_VA.iter())
        {
            need10 = need10.max((va - 0x400_000) as usize + 4);
        }
        loc66.resize(need10, 0);
        for i in 0..BOSMINER_HOST_3M_MOVZ_HITS {
            put_insn(
                &mut loc66,
                BOSMINER_HOST_3M_MOVZ_VA[i],
                BOSMINER_HOST_3M_MOVZ_INSN[i],
            );
        }
        put_insn(
            &mut loc66,
            BOSMINER_HOST_3M_TERMIOS_MOVK_VA,
            BOSMINER_HOST_3M_TERMIOS_MOVK_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_AML_OPEN_3M_MOVK_VA,
            BOSMINER_AML_OPEN_3M_MOVK_INSN,
        );
        for i in 0..BOSMINER_B3000000_MOVZ_HITS {
            put_insn(
                &mut loc66,
                BOSMINER_B3000000_MOVZ_VA[i],
                BOSMINER_B3000000_MOVZ_INSN[i],
            );
        }
        let aml = BOSMINER_ANTMINER_AML_RS_FILE_OFF as usize;
        loc66[aml..aml + BOSMINER_ANTMINER_AML_RS.len()]
            .copy_from_slice(BOSMINER_ANTMINER_AML_RS);
        let nix = BOSMINER_NIX_TERMIOS_RS_FILE_OFF as usize;
        loc66[nix..nix + BOSMINER_NIX_TERMIOS_RS.len()]
            .copy_from_slice(BOSMINER_NIX_TERMIOS_RS);
        assert!(admit_bosminer_host_3m_movz_sites(&loc66).is_ok());
        assert!(admit_bosminer_host_3m_termios_b3000000(&loc66).is_ok());
        assert!(admit_bosminer_aml_open_host_3m(&loc66).is_ok());
        assert!(admit_bosminer_nix_termios_rs(&loc66).is_ok());
        assert!(refuse_host_3m_termios_as_chip_fastuart_28().is_err());
        assert!(refuse_legacy_pack_and_xtal25_as_host_3m_writer().is_err());
        assert_eq!(linux_b3000000_speed_t(), 0x100D);
        assert_eq!(BOSMINER_HOST_3M_BAUD, 3_000_000);
        assert_eq!(BOSMINER_HOST_3M_MOVZ_HITS, 4);
        assert_eq!(BOSMINER_B3000000_MOVZ_HITS, 3);
        assert_eq!(BOSMINER_HOST_3M_MOVZ_VA[2], 0x00BC_1F94);
        assert_eq!(BOSMINER_SETCFG_51_09_00_28_HITS, 0);
        let loc28 = BOSMINER_BM1366_REG28_LOC_FILE_OFF as usize;
        let need11 = need10
            .max(loc28 + 32)
            .max((BOSMINER_BM1366_REG28_PACK_REV_VA - 0x400_000) as usize + 4)
            .max((BOSMINER_BM1366_REG28_CLONE_BL_VA - 0x400_000) as usize + 4);
        loc66.resize(need11, 0);
        loc66[loc28..loc28 + 8]
            .copy_from_slice(&BOSMINER_BM1366_REG28_FN_VA.to_le_bytes());
        let lc28 = u64::from(BOSMINER_BM1366_REG28_LOC_LINE)
            | (u64::from(BOSMINER_BM1366_REG28_LOC_COL) << 32);
        loc66[loc28 + 24..loc28 + 32].copy_from_slice(&lc28.to_le_bytes());
        put_insn(
            &mut loc66,
            BOSMINER_BM1366_REG28_MOVZ_VA,
            BOSMINER_BM1366_REG28_MOVZ_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_BM1366_REG28_VAL_MOVZ_VA,
            BOSMINER_BM1366_REG28_VAL_MOVZ_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_BM1366_REG28_VAL_MOVK_VA,
            BOSMINER_BM1366_REG28_VAL_MOVK_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_BM1366_REG28_BL_VA,
            BOSMINER_BM1366_REG28_BL_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_BM1366_REG28_PACK_REV_VA,
            BOSMINER_BM1366_REG28_PACK_REV_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_BM1366_REG28_CLONE_MOVZ_VA,
            BOSMINER_BM1366_REG28_CLONE_MOVZ_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_BM1366_REG28_CLONE_VAL_MOVK_VA,
            BOSMINER_BM1366_REG28_CLONE_VAL_MOVK_INSN,
        );
        put_insn(
            &mut loc66,
            BOSMINER_BM1366_REG28_CLONE_BL_VA,
            BOSMINER_BM1366_REG28_CLONE_BL_INSN,
        );
        assert!(admit_bosminer_bm1366_reg28_6000f(&loc66).is_ok());
        assert!(admit_bosminer_bm1366_reg28_clone(&loc66).is_ok());
        assert!(admit_bosminer_bm1366_reg28_loc_line(&loc66).is_ok());
        assert!(refuse_bm1366_reg28_6000f_as_host_3m().is_err());
        assert!(refuse_bm1366_reg28_6000f_as_bible_3001().is_err());
        assert_ne!(BOSMINER_BM1366_REG28_VALUE, );
        assert_ne!(BOSMINER_BM1366_REG28_VALUE, );
        assert_ne!(BOSMINER_BM1366_REG28_VALUE, PUBLIC_FASTUART_VALUE);
        let u28 = pack_s19k_bm1366_loc_cluster_reg28_uart();
        assert_eq!(&u28[..2], &[0x55, 0xAA]);
        assert_eq!(&u28[2..10], &[0x51, 0x09, 0x00, 0x28, 0x00, 0x06, 0x00, 0x0F]);
        assert_eq!(u28, s19k_generic_set_config_uart(0x28, 0x0006_000F));
        assert_eq!(BOSMINER_BM1366_REG28_PACK_CALL_HITS, 2);
        assert_eq!(BOSMINER_BM1366_LOC_FNS[7], BOSMINER_BM1366_REG28_FN_VA);
        assert_eq!(BOSMINER_AML_PACKING_RS_VA, 0x0131_E7BC);
        assert_eq!(BOSMINER_ANTMINER_AML_OPEN_FN_VA, 0x00BC_1F28);
        assert_eq!(BOSMINER_AML_SERIAL_SESSION_FN_VA, 0x008F_8018);
        assert!(refuse_bosminer_aml_open_as_set_config().is_err());
        assert!(admit_init_dialect_baud(S19kInitDialect::NativeExperimental, 115_200).is_ok());
        assert_eq!(BOSMINER_HAL_COMMAND_RS_VA, 0x0130_3F89);
        assert_eq!(BOSMINER_SET_BAUD_RATE_STR_VA, 0x0131_B8D5);
        assert_eq!(BOSMINER_FASTUART_FIELDS_STR_VA, 0x0132_0C4B);
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        let bm1366_init = serial
            .split("fn init_bm1366_chain(")
            .nth(1)
            .and_then(|s| s.split("fn init_bm1370_chain(").next())
            .expect("init_bm1366_chain");
        assert!(
            bm1366_init.contains("send_write_reg_broadcast_bm1397plus(0x10, hash_counting)"),
            "shipped native init must write HCN via generic set_config 0x10"
        );
        assert!(
            !bm1366_init.contains("0x28"),
            "BM1366 native init stays at 115200; must not emit ESP 1M FastUART 0x28"
        );
        let summary = format_s19k_native_init_summary(&p);
        assert!(summary.contains("set_address=77"));
        assert!(summary.contains("a8_unicast=77"));
        assert!(summary.contains("production=refused"));
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(
            serial.contains("BM1366_REG_A8_PER_CHIP: u32 = 0x0007_01F0"),
            "serial_mining native init must not drift from ESP 0x000701F0"
        );
        assert!(serial.contains("BM1366_HASH_COUNTING_S19K: u32 = 0x0000_115A"));
        assert!(serial.contains("BM1366_MISC_CTRL_PER_CHIP: u32 = 0xF000_C100"));
        let constructed = {
            let mut v = vec![0u8; BOSMINER_115A_BE_FILE_OFF as usize + 4];
            v[BOSMINER_115A_BE_FILE_OFF as usize..].copy_from_slice(&[0x00, 0x00, 0x11, 0x5A]);
            v
        };
        assert!(admit_bosminer_contains_s19k_hcn_be(&constructed).is_ok());
        assert!(admit_bosminer_contains_s19k_hcn_be(&[0u8; 8]).is_err());
        assert!(refuse_bosminer_115a_file_pin_as_hcn_writer().is_err());
        assert!(refuse_bosminer_hcn_divider_log_as_reg10_writer().is_err());
        assert_eq!(BOSMINER_115A_BE_VA, 0x019A_20A6);
        assert_eq!(BOSMINER_115A_TUNER_XREF_VA, 0x0066_4C0C);
        assert_eq!(BOSMINER_HCN_DIVIDER_LOG_FN_VA, 0x0084_34E0);
        assert_eq!(BOSMINER_HCN_DIVIDER_LOG_XTAL_HZ, 12_500_000);
        assert!(refuse_bosminer_hash_counting_number_string_as_hcn_writer().is_err());
        assert!(refuse_bosminer_ticket_mask_serde_as_uart_writer().is_err());
        assert_eq!(BOSMINER_HASH_COUNTING_NUMBER_STR_VA, 0x0139_DB65);
        assert_eq!(BOSMINER_HASH_COUNTING_NUMBER_XREF_FN_VA, 0x0041_EA18);
        assert_eq!(BOSMINER_TICKET_MASK_SERDE_FN_VA, 0x0086_F5E0);
    }

    #[test]
    fn s19k_fastuart_28_write_is_not_leave_115200_to_track1_3m() {
        assert_eq!(ESP_BM1366_MISCCTRL_DEFAULT_BAUD_REG, 0x18);
        assert_eq!(ESP_BM1366_MISCCTRL_DEFAULT_BAUD_VALUE, 0x0000_7A31);
        assert_eq!(ESP_BM1366_MISCCTRL_DEFAULT_BAUD_DIV, 26);
        assert_eq!(esp_bm1366_miscctrl_formula_baud_hz(), 115_740);
        assert_ne!(
            esp_bm1366_miscctrl_formula_baud_hz(),
            ESP_BM1366_SET_DEFAULT_BAUD_RETURN_HZ
        );
        assert!(refuse_esp_miscctrl_default_baud_as_fastuart_28().is_err());
        assert!(refuse_esp_default_baud_return_as_formula_hz().is_err());
        assert!(refuse_s19k_fastuart_28_write_as_leave_115200(PUBLIC_FASTUART_VALUE).is_err());
        assert!(refuse_s19k_fastuart_28_write_as_leave_115200.is_err());
        assert!(refuse_s19k_fastuart_28_write_as_leave_115200.is_err());
        assert!(refuse_s19k_fastuart_28_write_as_leave_115200(BOSMINER_BM1366_REG28_VALUE).is_err());
        assert!(refuse_s19k_fastuart_28_write_as_leave_115200(
            ESP_BM1366_MISCCTRL_DEFAULT_BAUD_VALUE
        )
        .is_err());
        assert!(refuse_s19k_fastuart_28_write_as_leave_115200(0).is_err());
        assert!(refuse_s19k_fastuart_28_write_as_leave_115200(0xDEAD_BEEF).is_err());
        let serial = include_str!("../../dcentrald/src/serial_mining.rs");
        assert!(admit_s19k_production_track1_reads_not_writes_fastuart_28(serial).is_ok());
        assert!(admit_s19k_production_track1_reads_not_writes_fastuart_28(
            "PASSTHROUGH BM1366\nsend_write_reg_broadcast_bm1397plus(0x28, 1)\n} else if passthrough"
        )
        .is_err());
        assert!(admit_s19k_production_track1_reads_not_writes_fastuart_28(
            "PASSTHROUGH BM1366\n} else if passthrough"
        )
        .is_err());
    }
}
