//! Reproducible Braiins Track-1 `/tmp` deploy policy (host-testable).
//!
//! Userspace is **armhf ELF32**. Kernel aarch64 is not the ABI.
//! Does not SSH. The sibling script `scripts/dcentrald_s19k_tmp_deploy.sh`
//! executes this policy.

use crate::s19k_am3_gpio437::passthrough_must_keep_gpio437_engaged;
use crate::s19k_am3_install::S19K_LIVE_IDENTITY_ALIASES;
use crate::s19k_braiins_chain_discover::admit_braiins_mining_on_ports;
use crate::s19k_braiins_job::{classify_job_wire_prefix, JobWirePrefixKind};
use crate::s19k_uart_trans_job::{BRAIINS_TTYS_BAUD, BRAIINS_TTYS_CANDIDATES};

pub const REQUIRED_TARGET_TRIPLE: &str = "armv7-unknown-linux-musleabihf";
pub const REQUIRED_ELF_CLASS: &str = "ELF32";
pub const REQUIRED_MACHINE: &str = "ARM";
/// ELF `e_ident[EI_CLASS]` ELF32.
pub const ELF_CLASS_32: u8 = 1;
/// ELF `e_ident[EI_DATA]` ELFDATA2LSB.
pub const ELF_DATA_LSB: u8 = 1;
/// ELF `e_machine` EM_ARM (not EM_AARCH64=183).
pub const ELF_MACHINE_ARM: u16 = 40;
pub const ELF32_EHDR_LEN: usize = 52;
pub const ELF32_PHDR_LEN: usize = 32;
pub const ELF_TYPE_EXEC: u16 = 2;
pub const ELF_TYPE_DYN: u16 = 3;
pub const PT_INTERP: u32 = 3;
/// ARM EABI hard-float (`EF_ARM_ABI_FLOAT_HARD`).
pub const EF_ARM_ABI_FLOAT_HARD: u32 = 0x0000_0400;
pub const GLIBC_INTERP_NEEDLE: &str = "ld-linux";
pub const TMP_DEPLOY_PLAN_SCHEMA: &str = "dcentos.s19k-tmp-deploy/v2";
/// Empty SHA-256 (FIPS 180-4). Pins the local hasher.
pub const S19K_SHA256_EMPTY: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// SHA-256("abc").
pub const S19K_SHA256_ABC: &str =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum S19kTmpDeployError {
    WrongTriple,
    /// Path claimed armv7 but the file is not ELF32 ARM (L1).
    WrongElf,
    /// `mining.enabled=true` with `passthrough=false` is native BM1366 (refused).
    NativeMiningOnForbidden,
    SinglePortRegression,
    RailsNotEngaged,
    WrongJobPrefix,
    UartTransOnBraiins,
    /// Config/`/etc/dcentos/board_target` is not a live S19k AML alias.
    WrongBoardTarget,
    /// ELF32 ARM but `EI_DATA` is not LSB.
    BadEndian,
    /// Missing `EF_ARM_ABI_FLOAT_HARD` — Braiins userspace is armhf.
    SoftFloat,
    /// `PT_INTERP` names glibc `ld-linux` — not the musl `/tmp` ABI.
    GlibcInterp,
    /// Any `PT_INTERP` — Track-1 `/tmp` admits static musl only.
    DynamicInterp,
    /// Plan missing `sha256=` / not 64 hex / `bytes=` missing.
    HashMissing,
    /// Post-scp `sha256sum` does not match the plan.
    HashMismatch,
    /// Post-scp byte count does not match the plan.
    SizeMismatch,
}

/// L1: Braiins userspace is armhf ELF32. Kernel aarch64 ≠ ABI.
/// Path containing the rustc triple is **not** sufficient.
pub fn admit_s19k_armhf_elf(hdr: &[u8]) -> Result<(), S19kTmpDeployError> {
    if hdr.len() < 20 {
        return Err(S19kTmpDeployError::WrongElf);
    }
    if hdr[0] != 0x7F || hdr[1] != b'E' || hdr[2] != b'L' || hdr[3] != b'F' {
        return Err(S19kTmpDeployError::WrongElf);
    }
    if hdr[4] != ELF_CLASS_32 {
        return Err(S19kTmpDeployError::WrongElf);
    }
    let machine = u16::from_le_bytes([hdr[18], hdr[19]]);
    if machine != ELF_MACHINE_ARM {
        return Err(S19kTmpDeployError::WrongElf);
    }
    Ok(())
}

/// Parsed ELF32 ARM identity for Track-1 `/tmp` (musl-static armhf).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kArmhfElf {
    pub class: u8,
    pub machine: u16,
    pub elf_type: u16,
    pub flags: u32,
    pub hard_float: bool,
    pub interp: Option<String>,
}

pub fn parse_s19k_armhf_elf(blob: &[u8]) -> Result<S19kArmhfElf, S19kTmpDeployError> {
    admit_s19k_armhf_elf(blob)?;
    if blob.len() < ELF32_EHDR_LEN {
        return Err(S19kTmpDeployError::WrongElf);
    }
    if blob[5] != ELF_DATA_LSB {
        return Err(S19kTmpDeployError::BadEndian);
    }
    let elf_type = u16::from_le_bytes([blob[16], blob[17]]);
    if elf_type != ELF_TYPE_EXEC && elf_type != ELF_TYPE_DYN {
        return Err(S19kTmpDeployError::WrongElf);
    }
    let flags = u32::from_le_bytes([blob[36], blob[37], blob[38], blob[39]]);
    let phoff = u32::from_le_bytes([blob[28], blob[29], blob[30], blob[31]]) as usize;
    let phentsize = u16::from_le_bytes([blob[42], blob[43]]) as usize;
    let phnum = u16::from_le_bytes([blob[44], blob[45]]) as usize;
    if phnum > 0 && phentsize < 20 {
        return Err(S19kTmpDeployError::WrongElf);
    }
    let mut interp = None;
    for i in 0..phnum {
        let off = phoff.saturating_add(i.saturating_mul(phentsize));
        if blob.len() < off.saturating_add(20) {
            return Err(S19kTmpDeployError::WrongElf);
        }
        let p_type = u32::from_le_bytes([
            blob[off],
            blob[off + 1],
            blob[off + 2],
            blob[off + 3],
        ]);
        if p_type != PT_INTERP {
            continue;
        }
        let p_offset = u32::from_le_bytes([
            blob[off + 4],
            blob[off + 5],
            blob[off + 6],
            blob[off + 7],
        ]) as usize;
        let p_filesz = u32::from_le_bytes([
            blob[off + 16],
            blob[off + 17],
            blob[off + 18],
            blob[off + 19],
        ]) as usize;
        if p_filesz == 0 || blob.len() < p_offset.saturating_add(p_filesz) {
            return Err(S19kTmpDeployError::WrongElf);
        }
        let raw = &blob[p_offset..p_offset + p_filesz];
        let text = std::str::from_utf8(raw).unwrap_or("").trim_end_matches('\0');
        interp = Some(text.to_string());
    }
    Ok(S19kArmhfElf {
        class: ELF_CLASS_32,
        machine: ELF_MACHINE_ARM,
        elf_type,
        flags,
        hard_float: flags & EF_ARM_ABI_FLOAT_HARD != 0,
        interp,
    })
}

/// Track-1 `/tmp` admits static musl armhf only: hard-float, no `PT_INTERP`.
pub fn admit_s19k_armhf_musl_static(elf: &S19kArmhfElf) -> Result<(), S19kTmpDeployError> {
    if !elf.hard_float {
        return Err(S19kTmpDeployError::SoftFloat);
    }
    match elf.interp.as_deref() {
        None | Some("") => Ok(()),
        Some(interp) if interp.contains(GLIBC_INTERP_NEEDLE) => {
            Err(S19kTmpDeployError::GlibcInterp)
        }
        Some(_) => Err(S19kTmpDeployError::DynamicInterp),
    }
}

/// FIPS 180-4 SHA-256. Used so the plan hash is host-testable without a crate.
pub fn s19k_sha256_hex(data: &[u8]) -> String {
    let h = s19k_sha256(data);
    let mut out = String::with_capacity(64);
    for b in h {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn s19k_sha256(data: &[u8]) -> [u8; 32] {
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
        0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
        0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
        0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
        0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];
    let mut state = [
        0x6a09e667u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (data.len() as u64).saturating_mul(8);
    let mut buf = data.to_vec();
    buf.push(0x80);
    while (buf.len() % 64) != 56 {
        buf.push(0);
    }
    buf.extend_from_slice(&bit_len.to_be_bytes());
    for chunk in buf.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub fn admit_s19k_tmp_deploy_sha256_hex(hex: &str) -> Result<(), S19kTmpDeployError> {
    if hex.len() != 64 {
        return Err(S19kTmpDeployError::HashMissing);
    }
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(S19kTmpDeployError::HashMissing);
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S19kTmpDeployContentHash {
    pub sha256: String,
    pub bytes: u64,
}

pub fn parse_s19k_tmp_deploy_content_hash(
    plan: &str,
) -> Result<S19kTmpDeployContentHash, S19kTmpDeployError> {
    let mut sha256 = None;
    let mut bytes = None;
    for line in plan.lines() {
        if let Some(rest) = line.strip_prefix("sha256=") {
            sha256 = Some(rest.trim().to_ascii_lowercase());
        }
        if let Some(rest) = line.strip_prefix("bytes=") {
            bytes = rest.trim().parse::<u64>().ok();
        }
    }
    let sha256 = sha256.ok_or(S19kTmpDeployError::HashMissing)?;
    admit_s19k_tmp_deploy_sha256_hex(&sha256)?;
    let bytes = bytes.ok_or(S19kTmpDeployError::HashMissing)?;
    if bytes == 0 {
        return Err(S19kTmpDeployError::HashMissing);
    }
    Ok(S19kTmpDeployContentHash { sha256, bytes })
}

/// Post-scp: remote `sha256sum` + size must match the plan, then re-admit ELF.
pub fn admit_s19k_tmp_deploy_post_scp(
    plan: &str,
    remote_sha256: &str,
    remote_bytes: u64,
    remote_elf: &[u8],
) -> Result<(), S19kTmpDeployError> {
    admit_s19k_tmp_deploy_launch_plan(plan)?;
    let expected = parse_s19k_tmp_deploy_content_hash(plan)?;
    let got = remote_sha256.trim().to_ascii_lowercase();
    admit_s19k_tmp_deploy_sha256_hex(&got)?;
    if got != expected.sha256 {
        return Err(S19kTmpDeployError::HashMismatch);
    }
    if remote_bytes != expected.bytes || remote_elf.len() as u64 != expected.bytes {
        return Err(S19kTmpDeployError::SizeMismatch);
    }
    let elf = parse_s19k_armhf_elf(remote_elf)?;
    admit_s19k_armhf_musl_static(&elf)
}

/// Machine-readable launch plan. Does not SSH or flash.
pub fn format_s19k_tmp_deploy_launch_plan(
    remote_dir: &str,
    mining_on: bool,
    hard_float: bool,
    interp: Option<&str>,
    sha256_hex: &str,
    bytes: u64,
) -> String {
    let mode = if mining_on {
        "mining-on-passthrough"
    } else {
        "stage-only"
    };
    let interp_field = interp.unwrap_or("none");
    format!(
        "schema={TMP_DEPLOY_PLAN_SCHEMA}\n\
triple={REQUIRED_TARGET_TRIPLE}\n\
elf_class=32\n\
e_machine=40\n\
hard_float={hard_float}\n\
pt_interp={interp_field}\n\
musl_static=true\n\
sha256={sha256_hex}\n\
bytes={bytes}\n\
post_scp=sha256sum\n\
re_admit=elf32_arm_musl_static\n\
remote_dir={remote_dir}\n\
remote_bin={remote_dir}/dcentrald\n\
launch={remote_dir}/dcentrald --config {remote_dir}/dcentrald_s19k.toml\n\
chmod=755\n\
ports=/dev/ttyS1,/dev/ttyS2\n\
baud=3000000\n\
keep_rails={KEEP_RAILS_BOSMINER_STOP}\n\
forbidden_stop={FORBIDDEN_RAILS_DROP_STOP}\n\
mode={mode}\n\
native_bm1366=refused\n\
clear_for_flash=false\n\
execute=CLEAR_FOR_FLASH\n"
    )
}

pub fn admit_s19k_tmp_deploy_launch_plan(plan: &str) -> Result<(), S19kTmpDeployError> {
    for needle in [
        TMP_DEPLOY_PLAN_SCHEMA,
        REQUIRED_TARGET_TRIPLE,
        "elf_class=32",
        "e_machine=40",
        "hard_float=true",
        "pt_interp=none",
        "musl_static=true",
        "post_scp=sha256sum",
        "re_admit=elf32_arm_musl_static",
        "keep_rails=kill -9",
        "clear_for_flash=false",
        "native_bm1366=refused",
    ] {
        if !plan.contains(needle) {
            return Err(S19kTmpDeployError::WrongElf);
        }
    }
    parse_s19k_tmp_deploy_content_hash(plan)?;
    if plan.contains("ld-linux") {
        return Err(S19kTmpDeployError::GlibcInterp);
    }
    Ok(())
}

/// Deploy helper must admit musl-static armhf and write a launch plan.
pub fn admit_s19k_tmp_deploy_script_musl_static(script: &str) -> Result<(), &'static str> {
    if !script.contains("--dry-run") {
        return Err("deploy must accept --dry-run");
    }
    if !script.contains("TMP_DEPLOY_PLAN") {
        return Err("deploy must write TMP_DEPLOY_PLAN");
    }
    if !script.contains("hard_float") {
        return Err("deploy must check EF_ARM_ABI_FLOAT_HARD");
    }
    if !script.contains("ld-linux") {
        return Err("deploy must refuse glibc ld-linux interp");
    }
    if !script.contains("pt_interp=none") {
        return Err("deploy plan must name pt_interp=none");
    }
    if !script.contains("musl_static=true") {
        return Err("deploy plan must name musl_static=true");
    }
    if !script.contains("sha256=") {
        return Err("deploy plan must name sha256=");
    }
    if !script.contains("bytes=") {
        return Err("deploy plan must name bytes=");
    }
    if !script.contains("post_scp=sha256sum") {
        return Err("deploy plan must name post_scp=sha256sum");
    }
    if !script.contains("admit_s19k_tmp_deploy_post_scp") {
        return Err("deploy must name the post-scp re-admit");
    }
    let dry = script.find("[DRY RUN]").ok_or("missing DRY RUN marker")?;
    let ssh = script.find("ssh $SSH_OPTS").ok_or("missing ssh")?;
    if dry > ssh {
        return Err("dry-run must write the plan before SSH");
    }
    let scp = script.find("scp -O").ok_or("missing scp")?;
    let post = script
        .find("admit_s19k_tmp_deploy_post_scp")
        .ok_or("missing post-scp admit")?;
    let chmod = script.find("chmod 755").ok_or("missing chmod")?;
    if scp > post || post > chmod {
        return Err("post-scp hash re-admit must run after scp and before chmod");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct S19kTmpDeployRequest<'a> {
    pub binary_path_hint: &'a str,
    pub mining_enabled: bool,
    /// Required true when `mining_enabled` (Braiins kill -9 handoff).
    pub passthrough: bool,
    pub open_ports: &'a [&'a str],
    pub gpio437_value: Option<u8>,
    pub uart_trans_present: bool,
    pub first_job_prefix: Option<&'a [u8]>,
    /// Live `/etc/dcentos/board_target` / toml identity.
    pub board_target: &'a str,
}

/// Overlay/S37 may write `am3-s19kpro`. Do not refuse that as `/tmp` identity.
pub fn admit_s19k_tmp_deploy_board_target(name: &str) -> Result<(), S19kTmpDeployError> {
    if S19K_LIVE_IDENTITY_ALIASES.contains(&name) {
        Ok(())
    } else {
        Err(S19kTmpDeployError::WrongBoardTarget)
    }
}

pub fn admit_s19k_tmp_deploy(req: S19kTmpDeployRequest<'_>) -> Result<(), S19kTmpDeployError> {
    if !req.binary_path_hint.contains(REQUIRED_TARGET_TRIPLE) {
        return Err(S19kTmpDeployError::WrongTriple);
    }
    admit_s19k_tmp_deploy_board_target(req.board_target)?;
    if req.mining_enabled && !req.passthrough {
        return Err(S19kTmpDeployError::NativeMiningOnForbidden);
    }
    if admit_braiins_mining_on_ports(req.open_ports).is_err() {
        return Err(S19kTmpDeployError::SinglePortRegression);
    }
    match req.gpio437_value {
        Some(v) => passthrough_must_keep_gpio437_engaged(v)
            .map_err(|_| S19kTmpDeployError::RailsNotEngaged)?,
        None => {}
    }
    if req.uart_trans_present {
        return Err(S19kTmpDeployError::UartTransOnBraiins);
    }
    if let Some(p) = req.first_job_prefix {
        if classify_job_wire_prefix(p) != JobWirePrefixKind::Closed11d {
            return Err(S19kTmpDeployError::WrongJobPrefix);
        }
    }
    Ok(())
}

pub fn required_baud() -> u32 {
    BRAIINS_TTYS_BAUD
}

pub fn required_ports() -> &'static [&'static str] {
    BRAIINS_TTYS_CANDIDATES
}

/// How to free ttyS without dropping rails.
pub const KEEP_RAILS_BOSMINER_STOP: &str = "kill -9";
pub const FORBIDDEN_RAILS_DROP_STOP: &str = "/etc/init.d/S99bosminer stop";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deploy_refuses_single_port_and_21_56_and_s99_stop() {
        let ok = S19kTmpDeployRequest {
            binary_path_hint: "target/armv7-unknown-linux-musleabihf/release/dcentrald",
            mining_enabled: false,
            passthrough: false,
            open_ports: &["/dev/ttyS1", "/dev/ttyS2"],
            gpio437_value: Some(0),
            uart_trans_present: false,
            first_job_prefix: Some(&crate::s19k_braiins_job::CLOSED_11D_PREFIX),
            board_target: "am3-s19k",
        };
        assert!(admit_s19k_tmp_deploy_board_target("am3-s19kpro").is_ok());
        assert!(admit_s19k_tmp_deploy_board_target("am3-aml-s19kpro").is_ok());
        assert_eq!(
            admit_s19k_tmp_deploy_board_target("am3-s21"),
            Err(S19kTmpDeployError::WrongBoardTarget)
        );
        let mut pro = ok;
        pro.board_target = "am3-s19kpro";
        assert!(admit_s19k_tmp_deploy(pro).is_ok());
        assert!(admit_s19k_tmp_deploy(ok).is_ok());
        let mut mining_on = ok;
        mining_on.mining_enabled = true;
        mining_on.passthrough = true;
        assert!(admit_s19k_tmp_deploy(mining_on).is_ok());
        let mut bad = ok;
        bad.open_ports = &["/dev/ttyS1"];
        assert_eq!(
            admit_s19k_tmp_deploy(bad),
            Err(S19kTmpDeployError::SinglePortRegression)
        );
        bad = ok;
        bad.first_job_prefix = Some(&[0x55, 0xAA, 0x21, 0x56]);
        assert_eq!(
            admit_s19k_tmp_deploy(bad),
            Err(S19kTmpDeployError::WrongJobPrefix)
        );
        bad = ok;
        bad.gpio437_value = Some(1);
        assert_eq!(
            admit_s19k_tmp_deploy(bad),
            Err(S19kTmpDeployError::RailsNotEngaged)
        );
        bad = ok;
        bad.mining_enabled = true;
        bad.passthrough = false;
        assert_eq!(
            admit_s19k_tmp_deploy(bad),
            Err(S19kTmpDeployError::NativeMiningOnForbidden)
        );
        bad = ok;
        bad.board_target = "am3-s21";
        assert_eq!(
            admit_s19k_tmp_deploy(bad),
            Err(S19kTmpDeployError::WrongBoardTarget)
        );
        assert_eq!(required_baud(), 3_000_000);
        assert_eq!(required_ports(), &["/dev/ttyS1", "/dev/ttyS2"]);
        let mut three = ok;
        three.open_ports = &["/dev/ttyS1", "/dev/ttyS2", "/dev/ttyS3"];
        assert!(admit_s19k_tmp_deploy(three).is_ok());
        assert_eq!(KEEP_RAILS_BOSMINER_STOP, "kill -9");
        assert!(FORBIDDEN_RAILS_DROP_STOP.contains("S99bosminer"));
        let ckpool = include_str!("../../dcentrald_s19k_braiins_ckpool.toml");
        assert!(ckpool.contains("passthrough = true"));
        assert!(ckpool.contains("enabled = true"));
        let deploy_sh = include_str!("../../../scripts/dcentrald_s19k_tmp_deploy.sh");
        assert!(
            deploy_sh.contains("mining_key passthrough true"),
            "deploy helper must admit mining-on only from an assignment line, not a comment"
        );
        assert!(
            deploy_sh.contains("refuse single-port /tmp deploy"),
            "deploy helper must refuse a missing ttyS2"
        );
        assert!(deploy_sh.contains("NativeMiningOn"));
        assert!(
            deploy_sh.contains("admit_s19k_armhf_elf"),
            "deploy helper must parse ELF class/machine, not just the rustc triple in the path"
        );
        assert!(
            deploy_sh.contains("/etc/dcentos/tmp_deploy"),
            "deploy must stamp tmp_deploy so restore cannot treat Braiins /tmp as installed DCENT"
        );
        assert!(
            deploy_sh.contains("admit_s19k_tmp_deploy_board_target"),
            "deploy must admit live identity aliases, not only am3-s19k"
        );
        assert!(deploy_sh.contains("am3-s19kpro"));
        assert!(deploy_sh.contains("am3-aml-s19kpro"));
        let trial_sh = include_str!("../../../scripts/dcentrald_s19k_tmp_trial.sh");
        assert!(
            trial_sh.contains("/etc/dcentos/tmp_deploy"),
            "tmp_trial must stamp tmp_deploy; it also writes /etc/dcentos identity"
        );
        assert!(
            trial_sh.contains("admit_s19k_tmp_deploy_board_target"),
            "tmp_trial must admit the same live identity aliases"
        );
        assert!(trial_sh.contains("am3-s19kpro"));
        let mut elf32_arm = [0u8; 20];
        elf32_arm[0] = 0x7F;
        elf32_arm[1] = b'E';
        elf32_arm[2] = b'L';
        elf32_arm[3] = b'F';
        elf32_arm[4] = ELF_CLASS_32;
        elf32_arm[5] = 1;
        elf32_arm[18..20].copy_from_slice(&ELF_MACHINE_ARM.to_le_bytes());
        assert!(admit_s19k_armhf_elf(&elf32_arm).is_ok());
        let mut elf64 = elf32_arm;
        elf64[4] = 2;
        assert_eq!(admit_s19k_armhf_elf(&elf64), Err(S19kTmpDeployError::WrongElf));
        let mut aarch64 = elf32_arm;
        aarch64[4] = 2;
        aarch64[18..20].copy_from_slice(&183u16.to_le_bytes());
        assert_eq!(
            admit_s19k_armhf_elf(&aarch64),
            Err(S19kTmpDeployError::WrongElf)
        );
        assert_eq!(
            admit_s19k_armhf_elf(b"MZ"),
            Err(S19kTmpDeployError::WrongElf)
        );
        bad = ok;
        bad.uart_trans_present = true;
        assert_eq!(
            admit_s19k_tmp_deploy(bad),
            Err(S19kTmpDeployError::UartTransOnBraiins)
        );
        bad = ok;
        bad.open_ports = &["/dev/ttyS0", "/dev/ttyS1", "/dev/ttyS2"];
        assert_eq!(
            admit_s19k_tmp_deploy(bad),
            Err(S19kTmpDeployError::SinglePortRegression)
        );

        fn make_elf32_arm(hard: bool, interp: Option<&[u8]>) -> Vec<u8> {
            let mut blob = vec![0u8; ELF32_EHDR_LEN + ELF32_PHDR_LEN + 64];
            blob[0] = 0x7F;
            blob[1] = b'E';
            blob[2] = b'L';
            blob[3] = b'F';
            blob[4] = ELF_CLASS_32;
            blob[5] = ELF_DATA_LSB;
            blob[16..18].copy_from_slice(&ELF_TYPE_EXEC.to_le_bytes());
            blob[18..20].copy_from_slice(&ELF_MACHINE_ARM.to_le_bytes());
            blob[20..24].copy_from_slice(&1u32.to_le_bytes());
            blob[28..32].copy_from_slice(&(ELF32_EHDR_LEN as u32).to_le_bytes());
            let flags = if hard { EF_ARM_ABI_FLOAT_HARD } else { 0 };
            blob[36..40].copy_from_slice(&flags.to_le_bytes());
            blob[40..42].copy_from_slice(&(ELF32_EHDR_LEN as u16).to_le_bytes());
            blob[42..44].copy_from_slice(&(ELF32_PHDR_LEN as u16).to_le_bytes());
            if let Some(path) = interp {
                blob[44..46].copy_from_slice(&1u16.to_le_bytes());
                let ph = ELF32_EHDR_LEN;
                blob[ph..ph + 4].copy_from_slice(&PT_INTERP.to_le_bytes());
                let str_off = ELF32_EHDR_LEN + ELF32_PHDR_LEN;
                blob[ph + 4..ph + 8].copy_from_slice(&(str_off as u32).to_le_bytes());
                blob[ph + 16..ph + 20].copy_from_slice(&(path.len() as u32).to_le_bytes());
                blob[str_off..str_off + path.len()].copy_from_slice(path);
            } else {
                blob[44..46].copy_from_slice(&0u16.to_le_bytes());
            }
            blob
        }

        let static_hf = parse_s19k_armhf_elf(&make_elf32_arm(true, None)).unwrap();
        assert!(static_hf.hard_float);
        assert!(static_hf.interp.is_none());
        assert!(admit_s19k_armhf_musl_static(&static_hf).is_ok());
        let soft = parse_s19k_armhf_elf(&make_elf32_arm(false, None)).unwrap();
        assert_eq!(
            admit_s19k_armhf_musl_static(&soft),
            Err(S19kTmpDeployError::SoftFloat)
        );
        let glibc = parse_s19k_armhf_elf(&make_elf32_arm(
            true,
            Some(b"/lib/ld-linux-armhf.so.3\0"),
        ))
        .unwrap();
        assert_eq!(
            admit_s19k_armhf_musl_static(&glibc),
            Err(S19kTmpDeployError::GlibcInterp)
        );
        let dyn_musl = parse_s19k_armhf_elf(&make_elf32_arm(
            true,
            Some(b"/lib/ld-musl-armhf.so.1\0"),
        ))
        .unwrap();
        assert_eq!(
            admit_s19k_armhf_musl_static(&dyn_musl),
            Err(S19kTmpDeployError::DynamicInterp)
        );
        assert_eq!(s19k_sha256_hex(b""), S19K_SHA256_EMPTY);
        assert_eq!(s19k_sha256_hex(b"abc"), S19K_SHA256_ABC);
        let static_blob = make_elf32_arm(true, None);
        let digest = s19k_sha256_hex(&static_blob);
        assert!(admit_s19k_tmp_deploy_sha256_hex(&digest).is_ok());
        assert!(admit_s19k_tmp_deploy_sha256_hex("dead").is_err());
        let plan = format_s19k_tmp_deploy_launch_plan(
            "/tmp/dcentrald_bench_t1_DRYRUN",
            false,
            true,
            None,
            &digest,
            static_blob.len() as u64,
        );
        assert!(admit_s19k_tmp_deploy_launch_plan(&plan).is_ok());
        assert!(plan.contains("schema=dcentos.s19k-tmp-deploy/v2"));
        assert!(plan.contains(&format!("sha256={digest}")));
        assert!(plan.contains(&format!("bytes={}", static_blob.len())));
        assert!(plan.contains("post_scp=sha256sum"));
        assert!(admit_s19k_tmp_deploy_post_scp(
            &plan,
            &digest,
            static_blob.len() as u64,
            &static_blob,
        )
        .is_ok());
        assert_eq!(
            admit_s19k_tmp_deploy_post_scp(
                &plan,
                S19K_SHA256_EMPTY,
                static_blob.len() as u64,
                &static_blob,
            ),
            Err(S19kTmpDeployError::HashMismatch)
        );
        assert_eq!(
            admit_s19k_tmp_deploy_post_scp(&plan, &digest, 1, &static_blob),
            Err(S19kTmpDeployError::SizeMismatch)
        );
        let swapped = make_elf32_arm(true, Some(b"/lib/ld-linux-armhf.so.3\0"));
        let swapped_plan = format_s19k_tmp_deploy_launch_plan(
            "/tmp/x",
            false,
            true,
            None,
            &s19k_sha256_hex(&swapped),
            swapped.len() as u64,
        );
        assert_eq!(
            admit_s19k_tmp_deploy_post_scp(
                &swapped_plan,
                &s19k_sha256_hex(&swapped),
                swapped.len() as u64,
                &swapped,
            ),
            Err(S19kTmpDeployError::GlibcInterp)
        );
        assert!(admit_s19k_tmp_deploy_launch_plan("schema=only").is_err());
        assert!(parse_s19k_tmp_deploy_content_hash("sha256=aa\nbytes=1\n").is_err());
        assert!(admit_s19k_tmp_deploy_script_musl_static(deploy_sh).is_ok());
        assert!(admit_s19k_tmp_deploy_script_musl_static("ssh $SSH_OPTS").is_err());
        assert!(trial_sh.contains("admit_s19k_tmp_deploy_post_scp"));
    }
}
