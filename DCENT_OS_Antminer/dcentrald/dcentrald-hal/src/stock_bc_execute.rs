//! G32–G39: execute pure stock BC / open_core / set_baud / ticket_mask plans on a stock FPGA register I/O surface.
//!
//! # Quality bar
//!
//! T9+ bmminer VIL paths (SetConfig, chain_inactive/set_address, open_core_one_chain, set_baud,
//! set_asic_ticket_mask, set_hcnt). Does **not** invent non-VIL legacy branches.
//!
//! # Status
//!
//! **EXPERIMENTAL** wire — pure sequence + structural pins (HAL unit tests need a
//! Unix host; pure pins run on Windows). Live lock / full stock cold-boot admission
//! remain engine residuals.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use dcentrald_common::{
    plan_stock_bm1387_set_freq, plan_stock_init_ticket_mask_and_hcnt_vil,
    plan_stock_set_asic_ticket_mask_vil, plan_stock_set_baud_one_chain_vil,
    plan_stock_set_hcnt_vil, stock_bc_busy_wait_step, stock_bc_post_trigger_wait_budget,
    stock_bc_pre_ready_step, stock_bc_set_config_buffer_writes, stock_bc_set_config_trigger_write,
    stock_bc_vil_cmd_buffer_writes, stock_bc_vil_cmd_trigger_write, stock_bc_write_merge_host_baud,
    stock_buffer_space_wait_step, stock_open_core_bc_nullwork_enable,
    stock_open_core_bc_nullwork_prelude, stock_open_core_dhash_entry, stock_open_core_dhash_exit,
    StockBcBusyWaitStep, StockBcPreReadyStep, StockBcSetConfigPlan, StockBcVilCmdPlan,
    StockBufferSpaceWaitStep, StockOpenCoreOp, StockSetBaudOp, StockSoftwareSetAddressOp,
    STOCK_BC_PRE_READY_WAIT_MAX_ATTEMPTS, STOCK_OPEN_CORE_BUFFER_WAIT_MAX_ATTEMPTS,
    STOCK_REG_BC_WRITE_COMMAND, STOCK_REG_BUFFER_SPACE, STOCK_REG_DHASH_ACC_CONTROL,
    STOCK_REG_HASH_COUNTING_NUMBER, STOCK_REG_TW_WRITE_COMMAND,
};

use crate::stock_fpga::StockFpga;
use crate::{HalError, Result};

/// Minimal stock FPGA register I/O used by BC SetConfig execute.
///
/// Implemented by live [`StockFpga`] and host [`RecordingStockFpgaRegsShared`].
pub trait StockFpgaRegIo {
    fn read_reg(&self, offset: u32) -> u32;
    fn write_reg(&self, offset: u32, value: u32);
}

impl StockFpgaRegIo for StockFpga {
    #[inline]
    fn read_reg(&self, offset: u32) -> u32 {
        StockFpga::read_reg(self, offset)
    }

    #[inline]
    fn write_reg(&self, offset: u32, value: u32) {
        StockFpga::write_reg(self, offset, value)
    }
}

/// Execute one pure VIL BC SetConfig plan (T9+ multi-version order + G33 wait).
///
/// Steps (T9+ faithful):
/// 1. Write three BC_COMMAND_BUFFER words (pure buffer SSOT)
/// 2. Sample `BC_WRITE_COMMAND` once (**after** buffer; no pre-trigger ready-poll)
/// 3. Write pure trigger merge
/// 4. **G33:** post-write bit31 busy-wait via pure `stock_bc_busy_wait_step`
/// 5. Sleep `plan.settle_us` unless `skip_settle`
pub fn execute_stock_bc_set_config(
    io: &dyn StockFpgaRegIo,
    plan: &StockBcSetConfigPlan,
) -> Result<()> {
    execute_stock_bc_set_config_with_options(io, plan, false)
}

/// Same as [`execute_stock_bc_set_config`] with optional sleep skip for host tests.
///
/// When `skip_settle` is true, both the post-trigger 1 ms poll sleeps and the
/// 10 ms VIL settle are omitted (busy-wait **logic** still runs against pure
/// steps — tests drive status via the recording mock).
pub fn execute_stock_bc_set_config_with_options(
    io: &dyn StockFpgaRegIo,
    plan: &StockBcSetConfigPlan,
    skip_settle: bool,
) -> Result<()> {
    // T9+: set_BC_command_buffer → get_BC_write_command → set_BC_write_command
    for (offset, value) in stock_bc_set_config_buffer_writes(plan) {
        io.write_reg(offset, value);
    }
    let status = io.read_reg(STOCK_REG_BC_WRITE_COMMAND);
    let (trig_off, trig_val) = stock_bc_set_config_trigger_write(plan, status);
    io.write_reg(trig_off, trig_val);

    // G33: T9+ set_BC_write_command post-write busy-wait (bit31 on written value).
    run_stock_bc_post_trigger_wait(io, trig_val, skip_settle)?;

    if !skip_settle && plan.settle_us > 0 {
        std::thread::sleep(Duration::from_micros(u64::from(plan.settle_us)));
    }
    Ok(())
}

/// Run pure T9+ post-trigger busy-wait after a BC_WRITE_COMMAND write.
fn run_stock_bc_post_trigger_wait(
    io: &dyn StockFpgaRegIo,
    written_value: u32,
    skip_sleep: bool,
) -> Result<()> {
    match stock_bc_post_trigger_wait_budget(written_value) {
        None => {
            // T9+ else branch: single get_BC_write_command when bit31 clear on write.
            let _ = io.read_reg(STOCK_REG_BC_WRITE_COMMAND);
            Ok(())
        }
        Some(mut attempts) => loop {
            let status = io.read_reg(STOCK_REG_BC_WRITE_COMMAND);
            match stock_bc_busy_wait_step(status, attempts) {
                StockBcBusyWaitStep::Ready => return Ok(()),
                StockBcBusyWaitStep::SleepThenRepoll {
                    sleep_ms,
                    attempts_after_sleep,
                } => {
                    if !skip_sleep && sleep_ms > 0 {
                        std::thread::sleep(Duration::from_millis(u64::from(sleep_ms)));
                    }
                    attempts = attempts_after_sleep;
                }
                StockBcBusyWaitStep::SleepThenTimeout { sleep_ms } => {
                    if !skip_sleep && sleep_ms > 0 {
                        std::thread::sleep(Duration::from_millis(u64::from(sleep_ms)));
                    }
                    return Err(HalError::Other(
                        "stock BC_WRITE_COMMAND busy-wait timeout (T9+ set_BC_write_command)"
                            .into(),
                    ));
                }
                StockBcBusyWaitStep::Timeout => {
                    return Err(HalError::Other(
                        "stock BC_WRITE_COMMAND busy-wait timeout (T9+ set_BC_write_command)"
                            .into(),
                    ));
                }
            }
        },
    }
}

/// G35: execute a pure VIL short BC command with T9+ **pre-ready** order.
///
/// Steps (chain_inactive / set_address):
/// 1. Pre-ready poll until bit31 clear (fail-safe capped; pure SSOT)
/// 2. Write three BC_COMMAND_BUFFER words
/// 3. Trigger using **pre-ready** status (T9+ does not re-sample after buffer)
/// 4. G33 post-write busy-wait
///
/// Distinct from set_freq (`execute_stock_bc_set_config`: buffer → sample → trigger).
pub fn execute_stock_bc_vil_cmd_pre_ready(
    io: &dyn StockFpgaRegIo,
    plan: &StockBcVilCmdPlan,
) -> Result<()> {
    execute_stock_bc_vil_cmd_pre_ready_with_options(io, plan, false)
}

/// Same as [`execute_stock_bc_vil_cmd_pre_ready`] with optional sleep skip for host tests.
pub fn execute_stock_bc_vil_cmd_pre_ready_with_options(
    io: &dyn StockFpgaRegIo,
    plan: &StockBcVilCmdPlan,
    skip_sleep: bool,
) -> Result<()> {
    debug_assert!(plan.pre_ready_poll);
    // 1. Pre-ready poll — keep last ready status for trigger merge.
    let mut attempts = STOCK_BC_PRE_READY_WAIT_MAX_ATTEMPTS;
    let pre_status = loop {
        let status = io.read_reg(STOCK_REG_BC_WRITE_COMMAND);
        match stock_bc_pre_ready_step(status, attempts) {
            StockBcPreReadyStep::Ready => break status,
            StockBcPreReadyStep::SleepThenRepoll {
                sleep_ms,
                attempts_after_sleep,
            } => {
                if !skip_sleep && sleep_ms > 0 {
                    std::thread::sleep(Duration::from_millis(u64::from(sleep_ms)));
                }
                attempts = attempts_after_sleep;
            }
            StockBcPreReadyStep::Timeout => {
                return Err(HalError::Other(
                    "stock BC_WRITE_COMMAND pre-ready timeout (T9+ chain_inactive/set_address)"
                        .into(),
                ));
            }
        }
    };

    // 2–3. Buffer then trigger with pre-ready status.
    for (offset, value) in stock_bc_vil_cmd_buffer_writes(plan) {
        io.write_reg(offset, value);
    }
    let (trig_off, trig_val) = stock_bc_vil_cmd_trigger_write(plan, pre_status);
    io.write_reg(trig_off, trig_val);

    // 4. Post-write busy-wait (set_BC_write_command).
    run_stock_bc_post_trigger_wait(io, trig_val, skip_sleep)
}

/// G35: execute pure `software_set_address` composition (inactive×3 + addr ladder).
pub fn execute_stock_software_set_address(
    io: &dyn StockFpgaRegIo,
    ops: &[StockSoftwareSetAddressOp],
) -> Result<()> {
    execute_stock_software_set_address_with_options(io, ops, false)
}

/// Same as [`execute_stock_software_set_address`] with sleep skip for host tests.
pub fn execute_stock_software_set_address_with_options(
    io: &dyn StockFpgaRegIo,
    ops: &[StockSoftwareSetAddressOp],
    skip_sleep: bool,
) -> Result<()> {
    for op in ops {
        match op {
            StockSoftwareSetAddressOp::Bc(plan) => {
                execute_stock_bc_vil_cmd_pre_ready_with_options(io, plan, skip_sleep)?;
            }
            StockSoftwareSetAddressOp::DelayMs(ms) => {
                if !skip_sleep && *ms > 0 {
                    std::thread::sleep(Duration::from_millis(u64::from(*ms)));
                }
            }
        }
    }
    Ok(())
}

/// G36/G37: open_core execute report (T9+ BUFFER timeout is non-fatal).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StockOpenCoreExecuteReport {
    /// True if BUFFER_SPACE wait timed out; remaining TW + nullwork skipped;
    /// DHASH exit still applied (T9+ `goto LABEL_x5612`).
    pub buffer_space_timeout: bool,
}

/// G36: execute pure VIL open_core_one_chain ops (**EXPERIMENTAL** live).
///
/// G37: BUFFER_SPACE timeout continues to DHASH exit (does not hard-abort).
pub fn execute_stock_open_core_one_chain(
    io: &dyn StockFpgaRegIo,
    ops: &[StockOpenCoreOp],
) -> Result<StockOpenCoreExecuteReport> {
    execute_stock_open_core_one_chain_with_options(io, ops, false)
}

/// Same as [`execute_stock_open_core_one_chain`] with sleep skip for host tests.
pub fn execute_stock_open_core_one_chain_with_options(
    io: &dyn StockFpgaRegIo,
    ops: &[StockOpenCoreOp],
    skip_sleep: bool,
) -> Result<StockOpenCoreExecuteReport> {
    use dcentrald_common::{
        stock_open_core_buffer_timeout_continues_to_dhash_exit,
        stock_open_core_buffer_timeout_skips_nullwork_enable,
        stock_open_core_buffer_timeout_skips_remaining_tw,
    };

    let mut report = StockOpenCoreExecuteReport::default();
    for op in ops {
        match op {
            StockOpenCoreOp::DhashEntry { multi_version } => {
                let cur = io.read_reg(STOCK_REG_DHASH_ACC_CONTROL);
                io.write_reg(
                    STOCK_REG_DHASH_ACC_CONTROL,
                    stock_open_core_dhash_entry(cur, *multi_version),
                );
            }
            StockOpenCoreOp::ClearHashCounting => {
                io.write_reg(STOCK_REG_HASH_COUNTING_NUMBER, 0);
            }
            StockOpenCoreOp::BcNullworkPrelude { chain } => {
                let st = io.read_reg(STOCK_REG_BC_WRITE_COMMAND);
                io.write_reg(
                    STOCK_REG_BC_WRITE_COMMAND,
                    stock_open_core_bc_nullwork_prelude(st, *chain),
                );
            }
            StockOpenCoreOp::DelayUs(us) => {
                if !skip_sleep && *us > 0 {
                    std::thread::sleep(Duration::from_micros(u64::from(*us)));
                }
            }
            StockOpenCoreOp::GateblkSetConfig(plan) => {
                execute_stock_bc_set_config_with_options(io, plan, skip_sleep)?;
            }
            StockOpenCoreOp::WaitBufferSpace { chain } => {
                if report.buffer_space_timeout
                    && stock_open_core_buffer_timeout_skips_remaining_tw()
                {
                    continue;
                }
                let mut attempts = STOCK_OPEN_CORE_BUFFER_WAIT_MAX_ATTEMPTS;
                let mut timed_out = false;
                loop {
                    let st = io.read_reg(STOCK_REG_BUFFER_SPACE);
                    match stock_buffer_space_wait_step(st, *chain, attempts) {
                        StockBufferSpaceWaitStep::Ready => break,
                        StockBufferSpaceWaitStep::SleepThenRepoll {
                            sleep_us,
                            attempts_after_sleep,
                        } => {
                            if !skip_sleep && sleep_us > 0 {
                                std::thread::sleep(Duration::from_micros(u64::from(sleep_us)));
                            }
                            if attempts_after_sleep == 0 {
                                let st2 = io.read_reg(STOCK_REG_BUFFER_SPACE);
                                if stock_buffer_space_wait_step(st2, *chain, 0)
                                    == StockBufferSpaceWaitStep::Ready
                                {
                                    break;
                                }
                                timed_out = true;
                                break;
                            }
                            attempts = attempts_after_sleep;
                        }
                        StockBufferSpaceWaitStep::Timeout => {
                            timed_out = true;
                            break;
                        }
                    }
                }
                if timed_out {
                    // T9+: writeInitLogFile("Error: send open core work Failed…")
                    // then goto LABEL_x5612 — continue to DHASH exit (non-fatal).
                    debug_assert!(stock_open_core_buffer_timeout_continues_to_dhash_exit());
                    tracing::error!(
                        chain = *chain,
                        "Error: send open core work Failed on Chain[{}]!",
                        *chain
                    );
                    report.buffer_space_timeout = true;
                }
            }
            StockOpenCoreOp::TwWriteVil { words } => {
                if report.buffer_space_timeout
                    && stock_open_core_buffer_timeout_skips_remaining_tw()
                {
                    continue;
                }
                // T9+ set_TW_write_command_vil: axi[16]=w0 .. axi[28]=w12
                for (i, w) in words.iter().enumerate() {
                    io.write_reg(STOCK_REG_TW_WRITE_COMMAND + (i as u32) * 4, *w);
                }
            }
            StockOpenCoreOp::BcNullworkEnable => {
                if report.buffer_space_timeout
                    && stock_open_core_buffer_timeout_skips_nullwork_enable()
                {
                    continue;
                }
                let st = io.read_reg(STOCK_REG_BC_WRITE_COMMAND);
                io.write_reg(
                    STOCK_REG_BC_WRITE_COMMAND,
                    stock_open_core_bc_nullwork_enable(st),
                );
            }
            StockOpenCoreOp::DhashExit { multi_version } => {
                // Always runs — including after BUFFER timeout (T9+ LABEL_x5612).
                let cur = io.read_reg(STOCK_REG_DHASH_ACC_CONTROL);
                io.write_reg(
                    STOCK_REG_DHASH_ACC_CONTROL,
                    stock_open_core_dhash_exit(cur, *multi_version),
                );
            }
        }
    }
    Ok(report)
}

/// Convenience: plan + execute BM1387 set_freq via G16/G27 pure SSOT.
pub fn execute_stock_bm1387_set_freq(
    io: &dyn StockFpgaRegIo,
    chain: u8,
    chip_addr: u8,
    broadcast: bool,
    freq_mhz: u16,
) -> Result<()> {
    let plan = plan_stock_bm1387_set_freq(chain, chip_addr, broadcast, freq_mhz);
    execute_stock_bc_set_config(io, &plan)
}

/// Same as [`execute_stock_bm1387_set_freq`] with settle skip for host tests.
pub fn execute_stock_bm1387_set_freq_with_options(
    io: &dyn StockFpgaRegIo,
    chain: u8,
    chip_addr: u8,
    broadcast: bool,
    freq_mhz: u16,
    skip_settle: bool,
) -> Result<()> {
    let plan = plan_stock_bm1387_set_freq(chain, chip_addr, broadcast, freq_mhz);
    execute_stock_bc_set_config_with_options(io, &plan, skip_settle)
}

impl StockFpga {
    /// G32/G33: execute a pure BC SetConfig plan on this live mapping.
    ///
    /// **EXPERIMENTAL** — live lock not proven offline. Does not perform full
    /// cold-boot ASIC init.
    pub fn execute_bc_set_config(&self, plan: &StockBcSetConfigPlan) -> Result<()> {
        execute_stock_bc_set_config(self, plan)
    }

    /// G32/G33: plan + execute BM1387 set_freq (pure G16/G27 + post-trigger wait).
    pub fn execute_bm1387_set_freq(
        &self,
        chain: u8,
        chip_addr: u8,
        broadcast: bool,
        freq_mhz: u16,
    ) -> Result<()> {
        execute_stock_bm1387_set_freq(self, chain, chip_addr, broadcast, freq_mhz)
    }

    /// G35: execute pure VIL chain_inactive / set_address with pre-ready order.
    pub fn execute_bc_vil_cmd_pre_ready(&self, plan: &StockBcVilCmdPlan) -> Result<()> {
        execute_stock_bc_vil_cmd_pre_ready(self, plan)
    }

    /// G35: execute pure software_set_address ops.
    pub fn execute_software_set_address(&self, ops: &[StockSoftwareSetAddressOp]) -> Result<()> {
        execute_stock_software_set_address(self, ops)
    }

    /// G36/G37: execute pure VIL open_core_one_chain (**EXPERIMENTAL**).
    ///
    /// BUFFER_SPACE timeout continues to DHASH exit (T9+); see
    /// [`StockOpenCoreExecuteReport`].
    pub fn execute_open_core_one_chain(
        &self,
        ops: &[StockOpenCoreOp],
    ) -> Result<StockOpenCoreExecuteReport> {
        execute_stock_open_core_one_chain(self, ops)
    }

    /// G38: execute pure VIL set_baud one-chain (**EXPERIMENTAL**).
    pub fn execute_set_baud_one_chain(&self, chain: u8, bauddiv: u8) -> Result<()> {
        execute_stock_set_baud_one_chain(self, chain, bauddiv)
    }

    /// G38 R2: execute pure multi-chain VIL set_baud (**EXPERIMENTAL**).
    pub fn execute_set_baud_chains(&self, chains: &[u8], bauddiv: u8) -> Result<()> {
        execute_stock_set_baud_chains(self, chains, bauddiv)
    }

    /// G44: pure T9+ set_PWM FAN_CONTROL write (**EXPERIMENTAL** library).
    pub fn execute_set_pwm(&self, pwm_percent: u8) -> Result<()> {
        execute_stock_set_pwm(self, pwm_percent)
    }

    /// G39: execute pure set_asic_ticket_mask one-chain (**EXPERIMENTAL**).
    pub fn execute_set_asic_ticket_mask(&self, chain: u8, ticket_mask: u32) -> Result<()> {
        execute_stock_set_asic_ticket_mask(self, chain, ticket_mask)
    }

    /// G39: execute pure set_hcnt one-chain (**EXPERIMENTAL**).
    pub fn execute_set_hcnt(&self, chain: u8, hcnt: u32) -> Result<()> {
        execute_stock_set_hcnt(self, chain, hcnt)
    }

    /// G39: ticket_mask(63)+hcnt(0) multi-chain init pair (**EXPERIMENTAL**).
    pub fn execute_init_ticket_mask_and_hcnt(&self, chains: &[u8]) -> Result<()> {
        execute_stock_init_ticket_mask_and_hcnt(self, chains)
    }
}

/// G39: execute pure set_asic_ticket_mask one-chain (**EXPERIMENTAL**).
pub fn execute_stock_set_asic_ticket_mask(
    io: &dyn StockFpgaRegIo,
    chain: u8,
    ticket_mask: u32,
) -> Result<()> {
    let plan = plan_stock_set_asic_ticket_mask_vil(chain, ticket_mask);
    execute_stock_bc_set_config(io, &plan)
}

/// G39: execute pure set_hcnt one-chain (**EXPERIMENTAL**).
pub fn execute_stock_set_hcnt(io: &dyn StockFpgaRegIo, chain: u8, hcnt: u32) -> Result<()> {
    let plan = plan_stock_set_hcnt_vil(chain, hcnt);
    execute_stock_bc_set_config(io, &plan)
}

/// G39: execute a list of pure BC SetConfig plans (ticket/hcnt multi-chain).
pub fn execute_stock_bc_set_config_plans(
    io: &dyn StockFpgaRegIo,
    plans: &[StockBcSetConfigPlan],
) -> Result<()> {
    execute_stock_bc_set_config_plans_with_options(io, plans, false)
}

/// Same as [`execute_stock_bc_set_config_plans`] with settle skip for host tests.
pub fn execute_stock_bc_set_config_plans_with_options(
    io: &dyn StockFpgaRegIo,
    plans: &[StockBcSetConfigPlan],
    skip_settle: bool,
) -> Result<()> {
    for plan in plans {
        execute_stock_bc_set_config_with_options(io, plan, skip_settle)?;
    }
    Ok(())
}

/// G40: write pure-packed TIME_OUT_CONTROL (**EXPERIMENTAL**).
pub fn execute_stock_time_out_control(
    io: &dyn StockFpgaRegIo,
    timeout: u32,
    scale: dcentrald_common::StockTimeOutControlScale,
) -> Result<()> {
    use dcentrald_common::{stock_time_out_control_reg, STOCK_REG_TIME_OUT_CONTROL};
    io.write_reg(
        STOCK_REG_TIME_OUT_CONTROL,
        stock_time_out_control_reg(timeout, scale),
    );
    Ok(())
}

/// G44: write pure T9+ `set_PWM` FAN_CONTROL pack (**EXPERIMENTAL** library).
///
/// Does **not** enforce home PWM-30 — callers must clamp before invoke.
/// Product home paths must still intersect `PWM_SAFETY_MAX`.
pub fn execute_stock_set_pwm(io: &dyn StockFpgaRegIo, pwm_percent: u8) -> Result<()> {
    use dcentrald_common::{stock_fan_control_value, STOCK_REG_FAN_CONTROL};
    io.write_reg(STOCK_REG_FAN_CONTROL, stock_fan_control_value(pwm_percent));
    Ok(())
}

/// G44: pure full-fan word (`set_PWM(100)`) — EXPERIMENTAL; home units must not use blindly.
pub fn execute_stock_set_pwm_full(io: &dyn StockFpgaRegIo) -> Result<()> {
    use dcentrald_common::{stock_fan_control_full, STOCK_REG_FAN_CONTROL};
    io.write_reg(STOCK_REG_FAN_CONTROL, stock_fan_control_full());
    Ok(())
}

/// G39: T9+ post-open_core ticket_mask(63) + hcnt(0) for existing chains (**EXPERIMENTAL**).
pub fn execute_stock_init_ticket_mask_and_hcnt(
    io: &dyn StockFpgaRegIo,
    chains: &[u8],
) -> Result<()> {
    execute_stock_init_ticket_mask_and_hcnt_with_options(io, chains, false)
}

/// Same as [`execute_stock_init_ticket_mask_and_hcnt`] with settle skip for host tests.
pub fn execute_stock_init_ticket_mask_and_hcnt_with_options(
    io: &dyn StockFpgaRegIo,
    chains: &[u8],
    skip_settle: bool,
) -> Result<()> {
    let plans = plan_stock_init_ticket_mask_and_hcnt_vil(chains);
    execute_stock_bc_set_config_plans_with_options(io, &plans, skip_settle)
}

/// G38: execute pure VIL set_baud ops (**EXPERIMENTAL** live).
///
/// T9+ order: per-chain BC SetConfig (buffer→sample→trigger, no per-chain settle)
/// → 50 ms → host BC_WRITE low-5 baud merge. Does **not** invent non-VIL `0x86`.
pub fn execute_stock_set_baud_ops(io: &dyn StockFpgaRegIo, ops: &[StockSetBaudOp]) -> Result<()> {
    execute_stock_set_baud_ops_with_options(io, ops, false)
}

/// Same as [`execute_stock_set_baud_ops`] with sleep skip for host tests.
pub fn execute_stock_set_baud_ops_with_options(
    io: &dyn StockFpgaRegIo,
    ops: &[StockSetBaudOp],
    skip_sleep: bool,
) -> Result<()> {
    for op in ops {
        match op {
            StockSetBaudOp::BcSetConfig(plan) => {
                execute_stock_bc_set_config_with_options(io, plan, skip_sleep)?;
            }
            StockSetBaudOp::DelayUs(us) => {
                if !skip_sleep && *us > 0 {
                    std::thread::sleep(Duration::from_micros(u64::from(*us)));
                }
            }
            StockSetBaudOp::MergeHostBaud { bauddiv } => {
                let st = io.read_reg(STOCK_REG_BC_WRITE_COMMAND);
                io.write_reg(
                    STOCK_REG_BC_WRITE_COMMAND,
                    stock_bc_write_merge_host_baud(st, *bauddiv),
                );
            }
        }
    }
    Ok(())
}

/// G38: plan + execute one-chain VIL set_baud (pure SSOT).
pub fn execute_stock_set_baud_one_chain(
    io: &dyn StockFpgaRegIo,
    chain: u8,
    bauddiv: u8,
) -> Result<()> {
    execute_stock_set_baud_one_chain_with_options(io, chain, bauddiv, false)
}

/// Same as [`execute_stock_set_baud_one_chain`] with sleep skip for host tests.
pub fn execute_stock_set_baud_one_chain_with_options(
    io: &dyn StockFpgaRegIo,
    chain: u8,
    bauddiv: u8,
    skip_sleep: bool,
) -> Result<()> {
    let ops = plan_stock_set_baud_one_chain_vil(chain, bauddiv);
    execute_stock_set_baud_ops_with_options(io, &ops, skip_sleep)
}

/// G38 R2: plan + execute multi-chain VIL set_baud (N BC + one settle + one merge).
pub fn execute_stock_set_baud_chains(
    io: &dyn StockFpgaRegIo,
    chains: &[u8],
    bauddiv: u8,
) -> Result<()> {
    execute_stock_set_baud_chains_with_options(io, chains, bauddiv, false)
}

/// Same as [`execute_stock_set_baud_chains`] with sleep skip for host tests.
pub fn execute_stock_set_baud_chains_with_options(
    io: &dyn StockFpgaRegIo,
    chains: &[u8],
    bauddiv: u8,
    skip_sleep: bool,
) -> Result<()> {
    use dcentrald_common::plan_stock_set_baud_chains_vil;
    let ops = plan_stock_set_baud_chains_vil(chains, bauddiv);
    execute_stock_set_baud_ops_with_options(io, &ops, skip_sleep)
}

// ---------------------------------------------------------------------------
// Host recording mock (Unix HAL test host; pure sequence is the Windows pin)
// ---------------------------------------------------------------------------

/// Host-test mock of stock FPGA register I/O — records R/W, no hardware.
#[derive(Debug, Default)]
pub struct RecordingStockFpgaRegs {
    pub writes: Vec<(u32, u32)>,
    pub reads: Vec<u32>,
    /// Values returned by `read_reg` for a given offset (default 0).
    pub read_values: HashMap<u32, u32>,
    /// Optional scripted BC_WRITE_COMMAND status sequence (consumed per read).
    pub bc_status_queue: Vec<u32>,
}

impl RecordingStockFpgaRegs {
    pub fn new() -> Self {
        Self::default()
    }

    /// Seed BC_WRITE_COMMAND status for the execute pre-trigger sample.
    pub fn with_bc_status(mut self, status: u32) -> Self {
        self.read_values.insert(STOCK_REG_BC_WRITE_COMMAND, status);
        self
    }
}

/// Thread-safe recording I/O for unit tests (`&self` trait surface).
#[derive(Debug)]
pub struct RecordingStockFpgaRegsShared {
    inner: Mutex<RecordingStockFpgaRegs>,
}

impl RecordingStockFpgaRegsShared {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(RecordingStockFpgaRegs::new()),
        }
    }

    pub fn with_bc_status(status: u32) -> Self {
        Self {
            inner: Mutex::new(RecordingStockFpgaRegs::new().with_bc_status(status)),
        }
    }

    /// Script successive BC_WRITE_COMMAND reads (post-trigger busy-wait tests).
    ///
    /// When the queue is empty, falls back to `read_values` / 0 (ready).
    pub fn with_bc_status_queue(status_pre_trigger: u32, post_trigger: &[u32]) -> Self {
        let mut inner = RecordingStockFpgaRegs::new().with_bc_status(status_pre_trigger);
        // First read is pre-trigger sample; remaining are busy-wait polls.
        // Queue is only for post-trigger polls when set via push after first default.
        // Simpler: store full queue and also seed map for empty-queue fallback.
        let mut q = Vec::with_capacity(1 + post_trigger.len());
        q.push(status_pre_trigger);
        q.extend_from_slice(post_trigger);
        inner.bc_status_queue = q;
        Self {
            inner: Mutex::new(inner),
        }
    }

    /// Seed a register readback value (open_core DHASH/BUFFER goldens).
    pub fn set_read_value(&self, offset: u32, value: u32) {
        self.inner
            .lock()
            .expect("lock")
            .read_values
            .insert(offset, value);
    }

    pub fn writes(&self) -> Vec<(u32, u32)> {
        self.inner.lock().expect("lock").writes.clone()
    }

    pub fn reads(&self) -> Vec<u32> {
        self.inner.lock().expect("lock").reads.clone()
    }
}

impl Default for RecordingStockFpgaRegsShared {
    fn default() -> Self {
        Self::new()
    }
}

impl StockFpgaRegIo for RecordingStockFpgaRegsShared {
    fn read_reg(&self, offset: u32) -> u32 {
        let mut g = self.inner.lock().expect("lock");
        g.reads.push(offset);
        if offset == STOCK_REG_BC_WRITE_COMMAND && !g.bc_status_queue.is_empty() {
            return g.bc_status_queue.remove(0);
        }
        g.read_values.get(&offset).copied().unwrap_or(0)
    }

    fn write_reg(&self, offset: u32, value: u32) {
        let mut g = self.inner.lock().expect("lock");
        g.writes.push((offset, value));
        // Mirror last write into readback so multi-step open_core samples match
        // pure sim state (G37 recording-mock golden).
        g.read_values.insert(offset, value);
    }
}

/// Forced-fail helper for negative tests (honest refuse before I/O).
pub fn execute_stock_bc_set_config_or_fail(
    io: &dyn StockFpgaRegIo,
    plan: &StockBcSetConfigPlan,
    force_fail: bool,
) -> Result<()> {
    if force_fail {
        return Err(HalError::NotImplemented(
            "RecordingStockFpgaRegs forced fail",
        ));
    }
    execute_stock_bc_set_config_with_options(io, plan, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcentrald_common::{
        plan_stock_bm1387_set_freq, stock_bc_set_config_buffer_writes,
        stock_bc_set_config_trigger_write, stock_bc_write_command,
    };

    #[test]
    fn g32_execute_matches_t9_buffer_then_sample_then_trigger() {
        // Pre-trigger status 0; post-trigger busy-wait sees ready (0) immediately.
        let io = RecordingStockFpgaRegsShared::with_bc_status_queue(0, &[0]);
        let plan = plan_stock_bm1387_set_freq(2, 0, true, 500);
        execute_stock_bc_set_config_with_options(&io, &plan, true).expect("execute");

        let mut expected: Vec<(u32, u32)> = stock_bc_set_config_buffer_writes(&plan).to_vec();
        expected.push(stock_bc_set_config_trigger_write(&plan, 0));
        assert_eq!(io.writes(), expected);
        // Pre-trigger sample + post-trigger busy-wait poll.
        assert_eq!(
            io.reads(),
            vec![STOCK_REG_BC_WRITE_COMMAND, STOCK_REG_BC_WRITE_COMMAND]
        );
    }

    #[test]
    fn g33_busy_wait_polls_until_ready() {
        // Pre-trigger 0; post-trigger: busy, busy, ready.
        let io = RecordingStockFpgaRegsShared::with_bc_status_queue(
            0,
            &[0x8000_0000, 0x8000_0000, 0x0000_0000],
        );
        execute_stock_bm1387_set_freq_with_options(&io, 0, 0, true, 500, true).expect("ok");
        // 1 pre-trigger + 3 busy-wait polls
        assert_eq!(io.reads().len(), 4);
        let trig = stock_bc_write_command(0, 0);
        assert_eq!(io.writes().last().copied(), Some((0x0C0, trig)));
    }

    #[test]
    fn g33_busy_wait_timeout_is_honest() {
        // Pre-trigger 0; post-trigger always busy with budget 1 path via pure:
        // full 3001 busy polls would be slow even with skip_sleep — use a
        // custom small budget by driving SleepThenTimeout via queue of one
        // busy then we need attempts=1. Default budget is 3001 so we cannot
        // easily force timeout without 3001 iterations. Instead assert pure
        // step Timeout path is wired: force via empty budget is pure-only.
        // Here: many busy reads still succeed once ready appears.
        let io = RecordingStockFpgaRegsShared::with_bc_status_queue(0, &[0x8000_0000, 0]);
        execute_stock_bm1387_set_freq_with_options(&io, 0, 0, true, 650, true).expect("clears");
    }

    #[test]
    fn g32_execute_650_mhz_chain0_broadcast_uses_g16_word() {
        let io = RecordingStockFpgaRegsShared::with_bc_status_queue(0, &[0]);
        execute_stock_bm1387_set_freq_with_options(&io, 0, 0, true, 650, true).expect("set_freq");
        let writes = io.writes();
        assert_eq!(writes[1], (0x0C8, 0x0068_0221));
        assert_eq!(writes[0].1, 0x5809_000C);
        assert_eq!(writes[3], (0x0C0, 0x8080_0000));
    }

    #[test]
    fn g32_unicast_chip_addr_in_cmd0() {
        let io = RecordingStockFpgaRegsShared::with_bc_status_queue(0, &[0]);
        execute_stock_bm1387_set_freq_with_options(&io, 0, 0x24, false, 650, true)
            .expect("unicast");
        let writes = io.writes();
        assert_eq!(writes[0], (0x0C4, 0x4809_240C));
        assert_eq!(writes[1], (0x0C8, 0x0068_0221));
    }

    #[test]
    fn g32_forced_fail_is_honest() {
        let io = RecordingStockFpgaRegsShared::new();
        let plan = plan_stock_bm1387_set_freq(0, 0, true, 500);
        let err = execute_stock_bc_set_config_or_fail(&io, &plan, true).unwrap_err();
        assert!(matches!(err, HalError::NotImplemented(_)));
        assert!(io.writes().is_empty());
    }

    #[test]
    fn g32_g33_module_consumes_pure_not_open_code() {
        let src = include_str!("stock_bc_execute.rs");
        assert!(src.contains("stock_bc_set_config_buffer_writes(plan)"));
        assert!(src.contains("stock_bc_set_config_trigger_write(plan, status)"));
        assert!(src.contains("stock_bc_post_trigger_wait_budget"));
        assert!(src.contains("stock_bc_busy_wait_step"));
        assert!(src.contains("plan_stock_bm1387_set_freq"));
        assert!(src.contains("stock_bc_pre_ready_step"));
        assert!(src.contains("execute_stock_bc_vil_cmd_pre_ready"));
    }

    #[test]
    fn g35_pre_ready_inactive_order_is_sample_buffer_trigger() {
        use dcentrald_common::plan_stock_bc_chain_inactive_vil;
        // Pre-ready: ready immediately (0); post-trigger: ready.
        let io = RecordingStockFpgaRegsShared::with_bc_status_queue(0, &[0]);
        let plan = plan_stock_bc_chain_inactive_vil(1);
        execute_stock_bc_vil_cmd_pre_ready_with_options(&io, &plan, true).expect("ok");
        let writes = io.writes();
        assert_eq!(writes[0], (0x0C4, 0x5505_0000));
        assert_eq!(writes[1].0, 0x0C8);
        assert_eq!(writes[2].0, 0x0CC);
        assert_eq!(writes[3].0, 0x0C0);
        // Pre-ready sample + post-trigger poll(s).
        assert!(io.reads().len() >= 2);
        assert_eq!(io.reads()[0], STOCK_REG_BC_WRITE_COMMAND);
    }

    /// G33 critic residual: full timeout path with skip_sleep (no real 3s wait).
    /// G37: recording-mock open_core happy path matches pure write-trace golden.
    #[test]
    fn g37_open_core_recording_mock_matches_pure_write_trace() {
        use dcentrald_common::{
            plan_stock_open_core_one_chain_vil, stock_open_core_sim_write_trace,
            StockOpenCoreSimState, STOCK_REG_BUFFER_SPACE, STOCK_REG_DHASH_ACC_CONTROL,
        };
        let ops = plan_stock_open_core_one_chain_vil(0, 0x1A, 1, true);
        let pure =
            stock_open_core_sim_write_trace(&ops, StockOpenCoreSimState::happy_path(), false);

        // Mock: DHASH starts at 0x20; BUFFER always ready. Script exactly the
        // nullwork-prelude plus gate pre/post readiness samples; the final
        // nullwork-enable RMW must then observe the mirrored gate trigger.
        let io = RecordingStockFpgaRegsShared::with_bc_status_queue(0, &[0; 2]);
        io.set_read_value(STOCK_REG_DHASH_ACC_CONTROL, 0x20);
        io.set_read_value(STOCK_REG_BUFFER_SPACE, 0xFFFF_FFFF);
        let report = execute_stock_open_core_one_chain_with_options(&io, &ops, true).expect("ok");
        assert!(!report.buffer_space_timeout);
        assert_eq!(
            io.writes(),
            pure.writes,
            "HAL recording mock writes must match pure open_core write-trace golden"
        );
    }

    /// G39: ticket_mask(63)+hcnt(0) multi-chain write sequence matches pure plans.
    #[test]
    fn g39_ticket_hcnt_recording_mock_matches_pure() {
        use dcentrald_common::{
            plan_stock_init_ticket_mask_and_hcnt_vil, stock_bc_set_config_buffer_writes,
            stock_bc_set_config_trigger_write,
        };
        let chains = [0u8, 1];
        let plans = plan_stock_init_ticket_mask_and_hcnt_vil(&chains);
        assert_eq!(plans.len(), 4);
        // Each BC: pre-trigger sample + post-trigger ready poll → plenty of ready (0) status.
        let io = RecordingStockFpgaRegsShared::with_bc_status_queue(0, &[0; 16]);
        execute_stock_init_ticket_mask_and_hcnt_with_options(&io, &chains, true).expect("ok");
        let mut expected = Vec::new();
        for plan in &plans {
            expected.extend(stock_bc_set_config_buffer_writes(plan));
            // All pre-trigger samples scripted as 0.
            expected.push(stock_bc_set_config_trigger_write(plan, 0));
        }
        assert_eq!(io.writes(), expected);
        assert_eq!(plans[0].cmd_buf[0], 0x5809_0018);
        assert_eq!(plans[0].cmd_buf[1], 63);
        assert_eq!(plans[2].cmd_buf[0], 0x5809_0014);
        assert_eq!(plans[2].cmd_buf[1], 0);
    }

    /// G38: set_baud one-chain matches pure BC plan + host baud merge.
    #[test]
    fn g38_set_baud_recording_mock_matches_pure() {
        use dcentrald_common::{
            plan_stock_set_baud_vil, stock_bc_set_config_buffer_writes,
            stock_bc_set_config_trigger_write, stock_bc_write_merge_host_baud,
            stock_set_baud_misc_value,
        };
        let chain = 2u8;
        let bauddiv = 0x1A_u8;
        let plan = plan_stock_set_baud_vil(chain, bauddiv);
        assert_eq!(plan.cmd_buf[1], stock_set_baud_misc_value(bauddiv));
        assert_eq!(plan.settle_us, 0);

        // Pre-trigger BC status 0; post-trigger ready.
        let io = RecordingStockFpgaRegsShared::with_bc_status_queue(0, &[0]);
        execute_stock_set_baud_one_chain_with_options(&io, chain, bauddiv, true).expect("ok");

        let mut expected: Vec<(u32, u32)> = stock_bc_set_config_buffer_writes(&plan).to_vec();
        expected.push(stock_bc_set_config_trigger_write(&plan, 0));
        // After BC, merge uses last BC write as status (write-mirror) → trigger value.
        let after_trig = stock_bc_set_config_trigger_write(&plan, 0).1;
        expected.push((
            STOCK_REG_BC_WRITE_COMMAND,
            stock_bc_write_merge_host_baud(after_trig, bauddiv),
        ));
        assert_eq!(io.writes(), expected);
    }

    /// G37 R2: BUFFER timeout continues to DHASH exit; full pure↔HAL fail write-trace.
    #[test]
    fn g37_open_core_buffer_timeout_continues_to_dhash_exit() {
        use dcentrald_common::{
            plan_stock_open_core_one_chain_vil, stock_open_core_sim_write_trace,
            StockOpenCoreSimState, STOCK_REG_BUFFER_SPACE, STOCK_REG_DHASH_ACC_CONTROL,
            STOCK_REG_TW_WRITE_COMMAND,
        };
        let ops = plan_stock_open_core_one_chain_vil(0, 0x1A, 1, true);
        let pure_fail =
            stock_open_core_sim_write_trace(&ops, StockOpenCoreSimState::happy_path(), true);

        // Script exactly the nullwork-prelude plus gate pre/post readiness
        // samples so the buffer-space timeout is the only injected fault.
        let io = RecordingStockFpgaRegsShared::with_bc_status_queue(0, &[0; 2]);
        io.set_read_value(STOCK_REG_DHASH_ACC_CONTROL, 0x20);
        // BUFFER never ready → timeout on first WaitBufferSpace (3001 polls with skip_sleep).
        io.set_read_value(STOCK_REG_BUFFER_SPACE, 0);
        let report =
            execute_stock_open_core_one_chain_with_options(&io, &ops, true).expect("continues");
        assert!(report.buffer_space_timeout);
        assert_eq!(
            io.writes(),
            pure_fail.writes,
            "HAL timeout write-trace must match pure force_buffer_timeout golden"
        );
        assert!(
            !io.writes()
                .iter()
                .any(|(o, _)| *o == STOCK_REG_TW_WRITE_COMMAND),
            "no TW after buffer timeout"
        );
        let writes = io.writes();
        let last = writes.last().expect("dhash exit");
        assert_eq!(last.0, STOCK_REG_DHASH_ACC_CONTROL);
    }

    #[test]
    fn g33_busy_wait_full_timeout_is_honest() {
        // Pre-trigger ready 0; post-trigger always busy for 3001 polls + SleepThenTimeout.
        // Budget starts 3001: each busy → SleepThenRepoll until attempts=1 → SleepThenTimeout.
        // Polls until timeout: 3001 Ready checks that are busy... actually:
        // attempts=3001, busy → sleep, attempts=3000
        // ...
        // attempts=1, busy → SleepThenTimeout (one more status read with attempts=1)
        // Total status reads in busy-wait: 3001 (from 3001 down to 1 inclusive)
        let post = vec![0x8000_0000u32; 3001];
        let io = RecordingStockFpgaRegsShared::with_bc_status_queue(0, &post);
        let err = execute_stock_bm1387_set_freq_with_options(&io, 0, 0, true, 500, true)
            .expect_err("timeout");
        assert!(matches!(err, HalError::Other(_)));
        // 1 pre-trigger sample + 3001 busy-wait polls
        assert_eq!(io.reads().len(), 1 + 3001);
        let _ = post; // silence unused mut if optimized
    }
}
