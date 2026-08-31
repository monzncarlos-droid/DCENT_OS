use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::thread;
use std::time::{Duration, Instant};

const ROOT_PREFIX: &str = "/tmp/dcent-s19k-ptrace-kat.";
const FIXTURE_SCHEMA: &str = "s19k-ptrace-fixture-v1";
const RECEIPT_SCHEMA: &str = "s19k-ptrace-kat-receipt-v1";
const POLL: Duration = Duration::from_millis(5);
const OP_TIMEOUT: Duration = Duration::from_secs(15);
const OPTIONS: libc::c_int = libc::PTRACE_O_TRACEFORK
    | libc::PTRACE_O_TRACEVFORK
    | libc::PTRACE_O_TRACECLONE
    | libc::PTRACE_O_TRACEEXEC
    | libc::PTRACE_O_TRACEEXIT;

type AnyError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, AnyError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    ExerciseRollback,
    PrecommitHold,
    CommitKill,
}

impl Mode {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "exercise-rollback" => Ok(Self::ExerciseRollback),
            "precommit-hold" => Ok(Self::PrecommitHold),
            "commit-kill" => Ok(Self::CommitKill),
            _ => Err(format!("unknown mode: {value}").into()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::ExerciseRollback => "exercise-rollback",
            Self::PrecommitHold => "precommit-hold",
            Self::CommitKill => "commit-kill",
        }
    }
}

#[derive(Debug)]
struct Args {
    mode: Mode,
    root: PathBuf,
    nonce: String,
}

#[derive(Clone, Debug)]
struct Fixture {
    nonce: String,
    executable: PathBuf,
    executable_dev: u64,
    executable_ino: u64,
    supervisor_pid: i32,
    supervisor_start: u64,
    child_pid: i32,
    child_start: u64,
}

#[derive(Clone, Debug)]
struct ProcIdentity {
    tid: i32,
    tgid: i32,
    start: u64,
    tracer_pid: i32,
    executable: PathBuf,
    executable_dev: u64,
    executable_ino: u64,
    cmdline: Vec<Vec<u8>>,
}

#[derive(Clone, Debug)]
struct Task {
    tgid: i32,
    owner_tgid: i32,
    start: u64,
    stopped: bool,
    interrupt_sent: bool,
    terminal: bool,
    pending_signal: Option<i32>,
    auto_initial_stop_pending: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WaitPhase {
    Running,
    Freeze,
    Commit,
}

#[derive(Default, Debug)]
struct LifecycleCounts {
    fork: u64,
    vfork: u64,
    clone: u64,
    exec: u64,
    exit: u64,
}

impl LifecycleCounts {
    fn complete(&self) -> bool {
        self.fork > 0 && self.vfork > 0 && self.clone > 0 && self.exec > 0 && self.exit > 0
    }
}

#[derive(Default, Debug)]
struct EventCounts {
    fork: u64,
    vfork: u64,
    clone: u64,
    exec: u64,
    exit: u64,
    interrupt_stop: u64,
    terminal: u64,
    geteventmsg: u64,
    supervisor: LifecycleCounts,
    child: LifecycleCounts,
}

impl EventCounts {
    fn required_churn_seen(&self) -> bool {
        self.supervisor.complete() && self.child.complete()
    }
}

#[derive(Debug)]
struct Lease {
    fixture: Fixture,
    root: PathBuf,
    tasks: BTreeMap<i32, Task>,
    events: EventCounts,
}

fn parse_args() -> Result<Args> {
    let mut iter = env::args().skip(1);
    let mut values = BTreeMap::new();
    while let Some(key) = iter.next() {
        if !key.starts_with("--") {
            return Err(format!("unexpected argument: {key}").into());
        }
        let value = iter
            .next()
            .ok_or_else(|| format!("missing value for {key}"))?;
        if values.insert(key.clone(), value).is_some() {
            return Err(format!("duplicate argument: {key}").into());
        }
    }
    let mode = Mode::parse(&values.remove("--mode").ok_or("missing --mode")?)?;
    let root = PathBuf::from(values.remove("--root").ok_or("missing --root")?);
    let nonce = values.remove("--nonce").ok_or("missing --nonce")?;
    if !values.is_empty() {
        return Err(format!("unknown arguments: {values:?}").into());
    }
    if nonce.is_empty()
        || nonce.len() > 64
        || !nonce.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err("nonce must be 1..64 ASCII alphanumeric bytes".into());
    }
    Ok(Args { mode, root, nonce })
}

fn validate_root(root: &Path) -> Result<()> {
    let text = root.to_str().ok_or("root is not UTF-8")?;
    if !text.starts_with(ROOT_PREFIX) || text.contains("/../") || text.ends_with("/..") {
        return Err(format!("root outside private KAT prefix: {text}").into());
    }
    let metadata = fs::symlink_metadata(root)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err("root must be a non-symlink directory".into());
    }
    if metadata.uid() != 0 || metadata.mode() & 0o777 != 0o700 {
        return Err("root must be uid 0 mode 0700".into());
    }
    if fs::canonicalize(root)? != root {
        return Err("root canonical path mismatch".into());
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_data()?;
    Ok(())
}

fn read_exact_map(path: &Path, expected_keys: &[&str]) -> Result<BTreeMap<String, String>> {
    let mut text = String::new();
    File::open(path)?.read_to_string(&mut text)?;
    let mut map = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or("malformed key/value line")?;
        if key.is_empty() || value.is_empty() || map.insert(key.into(), value.into()).is_some() {
            return Err("empty or duplicate key/value field".into());
        }
    }
    let actual: Vec<&str> = map.keys().map(String::as_str).collect();
    let mut expected = expected_keys.to_vec();
    expected.sort_unstable();
    if actual != expected {
        return Err(format!("key set mismatch: actual={actual:?} expected={expected:?}").into());
    }
    Ok(map)
}

fn parse_positive_i32(value: &str, label: &str) -> Result<i32> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{label} is not canonical unsigned decimal").into());
    }
    let parsed: i32 = value.parse()?;
    if parsed <= 0 || parsed.to_string() != value {
        return Err(format!("{label} is not canonical positive decimal").into());
    }
    Ok(parsed)
}

fn parse_positive_u64(value: &str, label: &str) -> Result<u64> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("{label} is not canonical unsigned decimal").into());
    }
    let parsed: u64 = value.parse()?;
    if parsed == 0 || parsed.to_string() != value {
        return Err(format!("{label} is not canonical positive decimal").into());
    }
    Ok(parsed)
}

fn load_fixture(root: &Path, nonce: &str) -> Result<Fixture> {
    let map = read_exact_map(
        &root.join("fixture.meta"),
        &[
            "child_pid",
            "child_start",
            "fixture_dev",
            "fixture_exe",
            "fixture_ino",
            "nonce",
            "schema",
            "supervisor_pid",
            "supervisor_start",
        ],
    )?;
    if map.get("schema").map(String::as_str) != Some(FIXTURE_SCHEMA)
        || map.get("nonce").map(String::as_str) != Some(nonce)
    {
        return Err("fixture schema or nonce mismatch".into());
    }
    let executable = PathBuf::from(map.get("fixture_exe").ok_or("missing fixture_exe")?);
    if executable.parent() != Some(root) || fs::canonicalize(&executable)? != executable {
        return Err(
            "fixture executable must be a canonical direct child of the private case root".into(),
        );
    }
    let metadata = fs::metadata(&executable)?;
    let executable_dev = parse_positive_u64(
        map.get("fixture_dev").ok_or("missing fixture_dev")?,
        "fixture_dev",
    )?;
    let executable_ino = parse_positive_u64(
        map.get("fixture_ino").ok_or("missing fixture_ino")?,
        "fixture_ino",
    )?;
    if metadata.dev() != executable_dev || metadata.ino() != executable_ino {
        return Err("fixture executable inode identity mismatch".into());
    }
    Ok(Fixture {
        nonce: nonce.into(),
        executable,
        executable_dev,
        executable_ino,
        supervisor_pid: parse_positive_i32(
            map.get("supervisor_pid").ok_or("missing supervisor_pid")?,
            "supervisor_pid",
        )?,
        supervisor_start: parse_positive_u64(
            map.get("supervisor_start")
                .ok_or("missing supervisor_start")?,
            "supervisor_start",
        )?,
        child_pid: parse_positive_i32(
            map.get("child_pid").ok_or("missing child_pid")?,
            "child_pid",
        )?,
        child_start: parse_positive_u64(
            map.get("child_start").ok_or("missing child_start")?,
            "child_start",
        )?,
    })
}

fn parse_status(path: &Path) -> Result<(i32, i32)> {
    let text = fs::read_to_string(path)?;
    let mut tgid = None;
    let mut tracer_pid = None;
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Tgid:") {
            if tgid
                .replace(parse_positive_i32(value.trim(), "Tgid")?)
                .is_some()
            {
                return Err("duplicate Tgid".into());
            }
        }
        if let Some(value) = line.strip_prefix("TracerPid:") {
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err("TracerPid is not canonical decimal".into());
            }
            let parsed: i32 = value.parse()?;
            if parsed < 0 || parsed.to_string() != value {
                return Err("TracerPid is not canonical nonnegative decimal".into());
            }
            if tracer_pid.replace(parsed).is_some() {
                return Err("duplicate TracerPid".into());
            }
        }
    }
    Ok((
        tgid.ok_or("missing Tgid")?,
        tracer_pid.ok_or("missing TracerPid")?,
    ))
}

fn parse_stat_start(path: &Path) -> Result<u64> {
    let stat = fs::read_to_string(path)?;
    let split = stat
        .rfind(") ")
        .ok_or("stat missing final right-parenthesis delimiter")?;
    let fields: Vec<&str> = stat[split + 2..].split_ascii_whitespace().collect();
    parse_positive_u64(fields.get(19).ok_or("stat missing starttime")?, "starttime")
}

fn read_cmdline(path: &Path) -> Result<Vec<Vec<u8>>> {
    let bytes = fs::read(path)?;
    if bytes.is_empty() || bytes.last() != Some(&0) {
        return Err("cmdline must be nonempty and NUL-terminated".into());
    }
    let mut fields: Vec<Vec<u8>> = bytes[..bytes.len() - 1]
        .split(|byte| *byte == 0)
        .map(<[u8]>::to_vec)
        .collect();
    if fields.iter().any(Vec::is_empty) {
        return Err("cmdline contains an empty field".into());
    }
    if fields.is_empty() {
        return Err("cmdline has no fields".into());
    }
    Ok(std::mem::take(&mut fields))
}

fn read_proc_identity(tid: i32) -> Result<ProcIdentity> {
    let base = PathBuf::from(format!("/proc/{tid}"));
    let (tgid, tracer_pid) = parse_status(&base.join("status"))?;
    let start = parse_stat_start(&base.join("stat"))?;
    let executable = fs::read_link(base.join("exe"))?;
    let metadata = fs::metadata(base.join("exe"))?;
    let cmdline = read_cmdline(&base.join("cmdline"))?;
    Ok(ProcIdentity {
        tid,
        tgid,
        start,
        tracer_pid,
        executable,
        executable_dev: metadata.dev(),
        executable_ino: metadata.ino(),
        cmdline,
    })
}

fn verify_fixture_identity(fixture: &Fixture, root: &Path, identity: &ProcIdentity) -> Result<()> {
    if identity.executable != fixture.executable
        || identity.executable_dev != fixture.executable_dev
        || identity.executable_ino != fixture.executable_ino
    {
        return Err(format!("TID {} executable identity mismatch", identity.tid).into());
    }
    let root_bytes = root.as_os_str().as_encoded_bytes();
    let nonce_bytes = fixture.nonce.as_bytes();
    if !identity.cmdline.iter().any(|field| field == root_bytes)
        || !identity.cmdline.iter().any(|field| field == nonce_bytes)
    {
        return Err(format!("TID {} cmdline root/nonce mismatch", identity.tid).into());
    }
    Ok(())
}

fn list_tids(tgid: i32) -> Result<BTreeSet<i32>> {
    let mut tids = BTreeSet::new();
    for entry in fs::read_dir(format!("/proc/{tgid}/task"))? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_str().ok_or("non-UTF8 task entry")?;
        let tid = parse_positive_i32(name, "TID")?;
        tids.insert(tid);
    }
    if tids.is_empty() {
        return Err(format!("TGID {tgid} has no TIDs").into());
    }
    Ok(tids)
}

fn ptrace_call(
    request: libc::c_int,
    pid: i32,
    addr: *mut libc::c_void,
    data: *mut libc::c_void,
) -> io::Result<libc::c_long> {
    // SAFETY: this wrapper is lifecycle-only. It never issues register, memory peek, or poke requests.
    let result = unsafe { libc::ptrace(request, pid, addr, data) };
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(result)
    }
}

fn ptrace_seize(tid: i32) -> io::Result<()> {
    ptrace_call(
        libc::PTRACE_SEIZE,
        tid,
        std::ptr::null_mut(),
        OPTIONS as usize as *mut libc::c_void,
    )
    .map(|_| ())
}

fn ptrace_interrupt(tid: i32) -> io::Result<()> {
    ptrace_call(
        libc::PTRACE_INTERRUPT,
        tid,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
    )
    .map(|_| ())
}

fn ptrace_continue(tid: i32, signal: i32) -> io::Result<()> {
    ptrace_call(
        libc::PTRACE_CONT,
        tid,
        std::ptr::null_mut(),
        signal as usize as *mut libc::c_void,
    )
    .map(|_| ())
}

fn ptrace_detach(tid: i32, signal: i32) -> io::Result<()> {
    ptrace_call(
        libc::PTRACE_DETACH,
        tid,
        std::ptr::null_mut(),
        signal as usize as *mut libc::c_void,
    )
    .map(|_| ())
}

fn ptrace_geteventmsg(tid: i32) -> io::Result<u64> {
    #[repr(C)]
    struct GuardedMessage {
        before: libc::c_ulong,
        message: libc::c_ulong,
        after: libc::c_ulong,
    }

    const BEFORE: libc::c_ulong = 0x1357_9bdf;
    const AFTER: libc::c_ulong = 0x2468_ace0;
    let mut guarded = GuardedMessage {
        before: BEFORE,
        message: !0,
        after: AFTER,
    };
    ptrace_call(
        libc::PTRACE_GETEVENTMSG,
        tid,
        std::ptr::null_mut(),
        &mut guarded.message as *mut libc::c_ulong as *mut libc::c_void,
    )?;
    if guarded.before != BEFORE || guarded.after != AFTER {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PTRACE_GETEVENTMSG wrote outside tracer c_ulong",
        ));
    }
    Ok(guarded.message as u64)
}

fn wait_nonblocking() -> io::Result<Option<(i32, i32)>> {
    let mut status = 0;
    loop {
        // SAFETY: status is writable and __WALL|WNOHANG is the explicit Linux ptrace wait contract.
        let result = unsafe { libc::waitpid(-1, &mut status, libc::__WALL | libc::WNOHANG) };
        if result > 0 {
            return Ok(Some((result, status)));
        }
        if result == 0 {
            return Ok(None);
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.raw_os_error() == Some(libc::ECHILD) {
            return Ok(None);
        }
        return Err(error);
    }
}

fn progress(root: &Path, role: &str) -> Result<u64> {
    let value = fs::read_to_string(root.join(format!("{role}.progress")))?;
    let value = value.trim();
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("progress is not canonical unsigned decimal".into());
    }
    let parsed: u64 = value.parse()?;
    if parsed.to_string() != value {
        return Err("progress is not canonical unsigned decimal".into());
    }
    Ok(parsed)
}

fn read_u16_le(bytes: &[u8], offset: usize) -> Result<u16> {
    let value = bytes.get(offset..offset + 2).ok_or("truncated ELF u16")?;
    Ok(u16::from_le_bytes([value[0], value[1]]))
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = bytes.get(offset..offset + 4).ok_or("truncated ELF u32")?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64> {
    let value = bytes.get(offset..offset + 8).ok_or("truncated ELF u64")?;
    Ok(u64::from_le_bytes([
        value[0], value[1], value[2], value[3], value[4], value[5], value[6], value[7],
    ]))
}

fn elf_contract(path: &Path) -> Result<(u8, u16)> {
    let bytes = fs::read(path)?;
    if bytes.len() < 20 || &bytes[..4] != b"\x7fELF" || bytes[5] != 1 {
        return Err(format!("{} is not little-endian ELF", path.display()).into());
    }
    let class = bytes[4];
    let machine = read_u16_le(&bytes, 18)?;
    let (phoff, phentsize, phnum) = match class {
        1 => (
            read_u32_le(&bytes, 28)? as u64,
            read_u16_le(&bytes, 42)? as u64,
            read_u16_le(&bytes, 44)? as u64,
        ),
        2 => (
            read_u64_le(&bytes, 32)?,
            read_u16_le(&bytes, 54)? as u64,
            read_u16_le(&bytes, 56)? as u64,
        ),
        _ => return Err(format!("unsupported ELF class {class}").into()),
    };
    if phentsize == 0 || phnum == 0 {
        return Err("ELF has no program-header table".into());
    }
    for index in 0..phnum {
        let offset_u64 = phoff
            .checked_add(index.checked_mul(phentsize).ok_or("ELF phdr overflow")?)
            .ok_or("ELF phdr overflow")?;
        let offset = usize::try_from(offset_u64)?;
        let kind = read_u32_le(&bytes, offset)?;
        if kind == 2 || kind == 3 {
            return Err("ELF contains PT_DYNAMIC or PT_INTERP".into());
        }
    }
    Ok((class, machine))
}

impl Lease {
    fn new(root: PathBuf, fixture: Fixture) -> Self {
        Self {
            fixture,
            root,
            tasks: BTreeMap::new(),
            events: EventCounts::default(),
        }
    }

    fn acquire_tid(
        &mut self,
        tid: i32,
        expected_tgid: i32,
        owner_tgid: i32,
        auto_ok: bool,
    ) -> Result<()> {
        if let Some(existing) = self.tasks.get(&tid) {
            if existing.terminal {
                self.tasks.remove(&tid);
            } else {
                let current = read_proc_identity(tid)?;
                verify_fixture_identity(&self.fixture, &self.root, &current)?;
                if current.tgid != existing.tgid
                    || current.start != existing.start
                    || current.tracer_pid != std::process::id() as i32
                    || existing.owner_tgid != owner_tgid
                {
                    return Err(format!("active TID {tid} generation changed").into());
                }
                return Ok(());
            }
        }
        let before = read_proc_identity(tid)?;
        verify_fixture_identity(&self.fixture, &self.root, &before)?;
        if before.tgid != expected_tgid {
            return Err(format!("TID {tid} TGID mismatch").into());
        }
        let self_pid = std::process::id() as i32;
        if before.tracer_pid == 0 {
            ptrace_seize(tid)?;
        } else if !(auto_ok && before.tracer_pid == self_pid) {
            return Err(format!("TID {tid} already traced by {}", before.tracer_pid).into());
        }
        let after = read_proc_identity(tid)?;
        verify_fixture_identity(&self.fixture, &self.root, &after)?;
        if after.tgid != before.tgid || after.start != before.start || after.tracer_pid != self_pid
        {
            return Err(format!("TID {tid} changed during seize").into());
        }
        self.tasks.insert(
            tid,
            Task {
                tgid: expected_tgid,
                owner_tgid,
                start: after.start,
                stopped: auto_ok,
                interrupt_sent: false,
                terminal: false,
                pending_signal: None,
                auto_initial_stop_pending: auto_ok,
            },
        );
        Ok(())
    }

    fn acquire_group_fixpoint(&mut self, tgid: i32) -> Result<()> {
        let deadline = Instant::now() + OP_TIMEOUT;
        let mut previous = None;
        loop {
            let tids = list_tids(tgid)?;
            for tid in &tids {
                self.acquire_tid(*tid, tgid, tgid, false)?;
            }
            self.drain(WaitPhase::Running)?;
            let second = list_tids(tgid)?;
            if tids == second && previous.as_ref() == Some(&second) {
                return Ok(());
            }
            previous = Some(second);
            if Instant::now() >= deadline {
                return Err(format!("TGID {tgid} acquisition fixpoint timeout").into());
            }
            thread::sleep(POLL);
        }
    }

    fn acquire_initial(&mut self) -> Result<()> {
        self.acquire_group_fixpoint(self.fixture.supervisor_pid)?;
        self.acquire_group_fixpoint(self.fixture.child_pid)?;
        self.verify_anchor(self.fixture.supervisor_pid, self.fixture.supervisor_start)?;
        self.verify_anchor(self.fixture.child_pid, self.fixture.child_start)?;
        Ok(())
    }

    fn verify_anchor(&self, tid: i32, start: u64) -> Result<()> {
        let identity = read_proc_identity(tid)?;
        verify_fixture_identity(&self.fixture, &self.root, &identity)?;
        if identity.tgid != tid
            || identity.start != start
            || identity.tracer_pid != std::process::id() as i32
        {
            return Err(format!("anchor {tid} identity mismatch").into());
        }
        Ok(())
    }

    fn adopt_event_child(&mut self, parent_tid: i32, raw: u64) -> Result<i32> {
        if raw == 0 || raw > i32::MAX as u64 {
            return Err(format!("GETEVENTMSG value is not a positive PID: {raw}").into());
        }
        let tid = raw as i32;
        let owner_tgid = self
            .tasks
            .get(&parent_tid)
            .ok_or("event parent is not leased")?
            .owner_tgid;
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match read_proc_identity(tid) {
                Ok(identity) => {
                    verify_fixture_identity(&self.fixture, &self.root, &identity)?;
                    self.acquire_tid(tid, identity.tgid, owner_tgid, true)?;
                    return Ok(tid);
                }
                Err(error) if Instant::now() < deadline => {
                    let _ = error;
                    thread::sleep(POLL);
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn resume(&mut self, tid: i32, signal: i32) -> Result<()> {
        ptrace_continue(tid, signal)?;
        if let Some(task) = self.tasks.get_mut(&tid) {
            task.stopped = false;
            task.interrupt_sent = false;
            task.pending_signal = None;
        }
        Ok(())
    }

    fn owner_events_mut(&mut self, owner_tgid: i32) -> Result<&mut LifecycleCounts> {
        if owner_tgid == self.fixture.supervisor_pid {
            Ok(&mut self.events.supervisor)
        } else if owner_tgid == self.fixture.child_pid {
            Ok(&mut self.events.child)
        } else {
            Err(format!("event has unknown root owner TGID {owner_tgid}").into())
        }
    }

    fn handle_wait(&mut self, tid: i32, status: i32, phase: WaitPhase) -> Result<()> {
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            if let Some(task) = self.tasks.get_mut(&tid) {
                task.terminal = true;
                task.stopped = false;
            }
            self.events.terminal += 1;
            return Ok(());
        }
        if !libc::WIFSTOPPED(status) {
            return Err(format!("unexpected wait status {status:#x} for TID {tid}").into());
        }
        let signal = libc::WSTOPSIG(status);
        let event = (status >> 16) & 0xffff;
        let task = self
            .tasks
            .get_mut(&tid)
            .ok_or_else(|| format!("wait for unknown TID {tid}"))?;
        task.stopped = true;
        let was_interrupt_sent = task.interrupt_sent;
        task.interrupt_sent = false;
        let auto_initial_stop = task.auto_initial_stop_pending;
        task.auto_initial_stop_pending = false;
        let owner_tgid = task.owner_tgid;

        match event {
            libc::PTRACE_EVENT_FORK => {
                self.events.fork += 1;
                self.owner_events_mut(owner_tgid)?.fork += 1;
                let child = ptrace_geteventmsg(tid)?;
                self.events.geteventmsg += 1;
                self.adopt_event_child(tid, child)?;
            }
            libc::PTRACE_EVENT_VFORK => {
                self.events.vfork += 1;
                self.owner_events_mut(owner_tgid)?.vfork += 1;
                let child = ptrace_geteventmsg(tid)?;
                self.events.geteventmsg += 1;
                self.adopt_event_child(tid, child)?;
            }
            libc::PTRACE_EVENT_CLONE => {
                self.events.clone += 1;
                self.owner_events_mut(owner_tgid)?.clone += 1;
                let child = ptrace_geteventmsg(tid)?;
                self.events.geteventmsg += 1;
                self.adopt_event_child(tid, child)?;
            }
            libc::PTRACE_EVENT_EXEC => {
                self.events.exec += 1;
                self.owner_events_mut(owner_tgid)?.exec += 1;
                let old_tid = ptrace_geteventmsg(tid)?;
                self.events.geteventmsg += 1;
                if old_tid > i32::MAX as u64 {
                    return Err("exec GETEVENTMSG width overflow".into());
                }
                let identity = read_proc_identity(tid)?;
                verify_fixture_identity(&self.fixture, &self.root, &identity)?;
                let old_tid = old_tid as i32;
                if old_tid != 0 && old_tid != tid {
                    self.tasks.remove(&old_tid);
                }
            }
            libc::PTRACE_EVENT_EXIT => {
                self.events.exit += 1;
                self.owner_events_mut(owner_tgid)?.exit += 1;
                let _exit_status = ptrace_geteventmsg(tid)?;
                self.events.geteventmsg += 1;
            }
            libc::PTRACE_EVENT_STOP => {
                if was_interrupt_sent {
                    self.events.interrupt_stop += 1;
                }
            }
            0 => {
                if auto_initial_stop && signal == libc::SIGSTOP {
                    return self.resume(tid, 0);
                }
                if phase == WaitPhase::Freeze {
                    self.tasks
                        .get_mut(&tid)
                        .ok_or("missing stopped task")?
                        .pending_signal = Some(signal);
                    return Ok(());
                }
                return self.resume(tid, signal);
            }
            other => return Err(format!("unexpected ptrace event {other} for TID {tid}").into()),
        }

        if event == libc::PTRACE_EVENT_EXIT {
            return self.resume(tid, 0);
        }
        match phase {
            WaitPhase::Running => self.resume(tid, 0),
            WaitPhase::Freeze | WaitPhase::Commit => Ok(()),
        }
    }

    fn drain(&mut self, phase: WaitPhase) -> Result<usize> {
        // Linux may make an auto-attached fork/vfork/clone child's initial
        // wait stop visible before the parent's PTRACE_EVENT_* stop.  The
        // parent stop is the authority that binds GETEVENTMSG to the child;
        // never infer that relationship from PPID or a transient /proc walk.
        // Instead, hold unknown wait records until a known parent event
        // admits their exact TID.  Refuse if the ordering does not resolve
        // inside the same bounded operation deadline.
        let deadline = Instant::now() + OP_TIMEOUT;
        let mut pending = VecDeque::new();
        let mut handled = 0;
        loop {
            while let Some(wait) = wait_nonblocking()? {
                pending.push_back(wait);
            }
            if pending.is_empty() {
                return Ok(handled);
            }

            let mut made_progress = false;
            let pass_len = pending.len();
            for _ in 0..pass_len {
                let (tid, status) = pending
                    .pop_front()
                    .expect("pending wait length was captured before this pass");
                if self.tasks.contains_key(&tid) {
                    self.handle_wait(tid, status, phase)?;
                    handled += 1;
                    made_progress = true;
                } else {
                    pending.push_back((tid, status));
                }
            }
            if made_progress {
                continue;
            }
            if Instant::now() >= deadline {
                let tids = pending
                    .iter()
                    .map(|(tid, _)| tid.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                return Err(format!(
                    "wait ordering did not resolve through a bound parent event; unknown TIDs: {tids}"
                )
                .into());
            }
            thread::sleep(POLL);
        }
    }

    fn exercise_churn(&mut self) -> Result<()> {
        write_new(
            &self.root.join("churn.go"),
            format!(
                "schema={RECEIPT_SCHEMA}\nnonce={}\nexitkill=absent\n",
                self.fixture.nonce
            )
            .as_bytes(),
        )?;
        let deadline = Instant::now() + OP_TIMEOUT;
        loop {
            self.drain(WaitPhase::Running)?;
            let done = self.root.join("supervisor.churn.done").is_file()
                && self.root.join("child.churn.done").is_file();
            if done && self.events.required_churn_seen() && self.drain(WaitPhase::Running)? == 0 {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(format!("churn timeout with events {:?}", self.events).into());
            }
            thread::sleep(POLL);
        }
    }

    fn prove_seize_nonstop_progress(
        &mut self,
        supervisor_before: u64,
        child_before: u64,
    ) -> Result<(u64, u64)> {
        let deadline = Instant::now() + OP_TIMEOUT;
        loop {
            self.drain(WaitPhase::Running)?;
            let supervisor_after = progress(&self.root, "supervisor")?;
            let child_after = progress(&self.root, "child")?;
            if supervisor_after > supervisor_before && child_after > child_before {
                return Ok((supervisor_after, child_after));
            }
            if Instant::now() >= deadline {
                return Err("SEIZE non-stop progress timeout".into());
            }
            thread::sleep(POLL);
        }
    }

    fn active_tids(&self) -> Vec<i32> {
        self.tasks
            .iter()
            .filter_map(|(tid, task)| (!task.terminal).then_some(*tid))
            .collect()
    }

    fn interrupt_running(&mut self) -> Result<()> {
        for tid in self.active_tids() {
            let task = self.tasks.get_mut(&tid).ok_or("missing active task")?;
            if !task.stopped && !task.interrupt_sent {
                match ptrace_interrupt(tid) {
                    Ok(()) => task.interrupt_sent = true,
                    Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                        return Err(format!("TID {tid} vanished during interrupt").into())
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        }
        Ok(())
    }

    fn freeze_fixpoint(&mut self) -> Result<usize> {
        let deadline = Instant::now() + OP_TIMEOUT;
        let mut previous: Option<(BTreeSet<i32>, BTreeSet<i32>)> = None;
        loop {
            self.interrupt_running()?;
            self.drain(WaitPhase::Freeze)?;

            let supervisor = list_tids(self.fixture.supervisor_pid)?;
            let child = list_tids(self.fixture.child_pid)?;
            for (tgid, tids) in [
                (self.fixture.supervisor_pid, &supervisor),
                (self.fixture.child_pid, &child),
            ] {
                for tid in tids {
                    let identity = read_proc_identity(*tid)?;
                    if identity.tracer_pid != std::process::id() as i32 {
                        return Err(format!("unleased TID {tid} appeared during freeze").into());
                    }
                    self.acquire_tid(*tid, tgid, tgid, true)?;
                }
            }

            let all_stopped = self
                .tasks
                .values()
                .filter(|task| !task.terminal)
                .all(|task| task.stopped);
            let snapshot = (supervisor, child);
            if all_stopped
                && previous.as_ref() == Some(&snapshot)
                && self.drain(WaitPhase::Freeze)? == 0
            {
                self.verify_anchor(self.fixture.supervisor_pid, self.fixture.supervisor_start)?;
                self.verify_anchor(self.fixture.child_pid, self.fixture.child_start)?;
                return Ok(self.active_tids().len());
            }
            previous = Some(snapshot);
            if Instant::now() >= deadline {
                return Err("interrupt all-TID fixpoint timeout".into());
            }
            thread::sleep(POLL);
        }
    }

    fn detach_all(&mut self) -> Result<()> {
        let mut tids = self.active_tids();
        tids.sort_by_key(|tid| {
            (
                *tid == self.fixture.supervisor_pid || *tid == self.fixture.child_pid,
                *tid,
            )
        });
        for tid in tids {
            let task = self.tasks.get(&tid).ok_or("missing detach task")?;
            if !task.stopped {
                return Err(format!("refusing to detach running TID {tid}").into());
            }
            let signal = task.pending_signal.unwrap_or(0);
            match ptrace_detach(tid, signal) {
                Ok(()) => {}
                Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                    return Err(format!("TID {tid} vanished during detach").into())
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }

    fn prove_detached_progress(
        &self,
        before_supervisor: u64,
        before_child: u64,
    ) -> Result<(u64, u64)> {
        let deadline = Instant::now() + OP_TIMEOUT;
        loop {
            let supervisor = read_proc_identity(self.fixture.supervisor_pid)?;
            let child = read_proc_identity(self.fixture.child_pid)?;
            if supervisor.start != self.fixture.supervisor_start
                || child.start != self.fixture.child_start
                || supervisor.tracer_pid != 0
                || child.tracer_pid != 0
            {
                return Err("post-detach anchor identity mismatch".into());
            }
            let after_supervisor = progress(&self.root, "supervisor")?;
            let after_child = progress(&self.root, "child")?;
            if after_supervisor > before_supervisor && after_child > before_child {
                return Ok((after_supervisor, after_child));
            }
            if Instant::now() >= deadline {
                return Err("post-detach progress timeout".into());
            }
            thread::sleep(POLL);
        }
    }

    fn wait_group_terminal(&mut self, tgid: i32, original_start: u64) -> Result<()> {
        let deadline = Instant::now() + OP_TIMEOUT;
        let stat_path = PathBuf::from(format!("/proc/{tgid}/stat"));
        loop {
            self.drain(WaitPhase::Commit)?;
            let active_in_group = self
                .tasks
                .values()
                .any(|task| task.tgid == tgid && !task.terminal);
            match parse_stat_start(&stat_path) {
                Ok(start) if start != original_start => {
                    return Err(format!("TGID {tgid} was reused before absence proof").into())
                }
                Ok(_) => {}
                Err(error) => {
                    let not_found = error
                        .downcast_ref::<io::Error>()
                        .is_some_and(|value| value.kind() == io::ErrorKind::NotFound);
                    if !active_in_group && not_found {
                        return Ok(());
                    }
                    return Err(error);
                }
            }
            if Instant::now() >= deadline {
                return Err(format!("TGID {tgid} terminal timeout").into());
            }
            thread::sleep(POLL);
        }
    }

    fn kill_group(&mut self, leader: i32, start: u64) -> Result<()> {
        let task = self.tasks.get(&leader).ok_or("missing group leader")?;
        if task.terminal || !task.stopped {
            return Err(format!("group leader {leader} is not a live ptrace stop").into());
        }
        let mut group_tids = self
            .tasks
            .iter()
            .filter_map(|(tid, task)| (task.tgid == leader && !task.terminal).then_some(*tid))
            .collect::<Vec<_>>();
        group_tids.sort_by_key(|tid| (*tid != leader, *tid));
        for tid in &group_tids {
            let task = self.tasks.get(tid).ok_or("missing group task")?;
            if !task.stopped {
                return Err(format!("group task {tid} is not a live ptrace stop").into());
            }
        }

        // Commit the fatal action against the exact frozen TGID with kill(2).
        // Injecting SIGKILL as PTRACE_CONT data from PTRACE_EVENT_STOP is not
        // a reliable signal-delivery operation on the held 4.9 kernel. Once
        // the real group-directed signal is pending, release every frozen TID
        // with signal zero so each PTRACE_EVENT_EXIT stop can be drained.
        // SAFETY: leader is the still-bound frozen TGID checked immediately
        // above; kill writes no userspace memory.
        if unsafe { libc::kill(leader, libc::SIGKILL) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        for tid in group_tids {
            match ptrace_continue(tid, 0) {
                Ok(()) => {
                    let task = self
                        .tasks
                        .get_mut(&tid)
                        .ok_or("missing resumed group task")?;
                    task.stopped = false;
                    task.interrupt_sent = false;
                    task.pending_signal = None;
                }
                Err(error) if error.raw_os_error() == Some(libc::ESRCH) => {
                    // A fatal group exit may win this race. Do not infer
                    // terminal state from ESRCH; wait_group_terminal still
                    // requires the ptrace waits and original PID:start
                    // absence before it returns success.
                }
                Err(error) => return Err(error.into()),
            }
        }
        self.wait_group_terminal(leader, start)
    }
}

fn run_exercise(args: &Args, mut lease: Lease) -> Result<()> {
    lease.acquire_initial()?;
    lease.exercise_churn()?;
    let before_supervisor = progress(&args.root, "supervisor")?;
    let before_child = progress(&args.root, "child")?;
    let frozen_tids = lease.freeze_fixpoint()?;
    lease.detach_all()?;
    let (after_supervisor, after_child) =
        lease.prove_detached_progress(before_supervisor, before_child)?;
    write_new(
        &args.root.join("case.events-rollback.receipt"),
        format!(
            "schema={RECEIPT_SCHEMA}\nmode={}\nnonce={}\noptions={OPTIONS:#x}\nexitkill=absent\nseize_nonstop=churn-completed-while-seized\ngeteventmsg_bits={}\ngeteventmsg_canary=intact\ngeteventmsg_calls={}\nfork={}\nvfork={}\nclone={}\nexec={}\nexit={}\nsupervisor_fork={}\nsupervisor_vfork={}\nsupervisor_clone={}\nsupervisor_exec={}\nsupervisor_exit={}\nchild_fork={}\nchild_vfork={}\nchild_clone={}\nchild_exec={}\nchild_exit={}\ninterrupt_stop={}\nfrozen_tids={frozen_tids}\ndetach=complete\ndetach_supervisor_before={before_supervisor}\ndetach_supervisor_after={after_supervisor}\ndetach_child_before={before_child}\ndetach_child_after={after_child}\nprogress=resumed\n",
            args.mode.as_str(),
            args.nonce,
            std::mem::size_of::<libc::c_ulong>() * 8,
            lease.events.geteventmsg,
            lease.events.fork,
            lease.events.vfork,
            lease.events.clone,
            lease.events.exec,
            lease.events.exit,
            lease.events.supervisor.fork,
            lease.events.supervisor.vfork,
            lease.events.supervisor.clone,
            lease.events.supervisor.exec,
            lease.events.supervisor.exit,
            lease.events.child.fork,
            lease.events.child.vfork,
            lease.events.child.clone,
            lease.events.child.exec,
            lease.events.child.exit,
            lease.events.interrupt_stop,
        )
        .as_bytes(),
    )
}

fn run_precommit_hold(args: &Args, mut lease: Lease) -> Result<()> {
    lease.acquire_initial()?;
    let supervisor_before = progress(&args.root, "supervisor")?;
    let child_before = progress(&args.root, "child")?;
    let (supervisor_ready, child_ready) =
        lease.prove_seize_nonstop_progress(supervisor_before, child_before)?;
    write_new(
        &args.root.join("precommit.lease.ready"),
        format!(
            "schema={RECEIPT_SCHEMA}\nmode={}\nnonce={}\noptions={OPTIONS:#x}\nexitkill=absent\nseize_nonstop=progressed\ngeteventmsg_bits={}\ngeteventmsg_canary=not-exercised\nleased_tids={}\nsupervisor_progress={supervisor_ready}\nchild_progress={child_ready}\n",
            args.mode.as_str(),
            args.nonce,
            std::mem::size_of::<libc::c_ulong>() * 8,
            lease.active_tids().len(),
        )
        .as_bytes(),
    )?;
    loop {
        lease.drain(WaitPhase::Running)?;
        thread::sleep(POLL);
    }
}

fn run_commit_kill(args: &Args, mut lease: Lease) -> Result<()> {
    lease.acquire_initial()?;
    lease.exercise_churn()?;
    let frozen_tids = lease.freeze_fixpoint()?;
    write_new(
        &args.root.join("commit.authority.receipt"),
        format!(
            "schema={RECEIPT_SCHEMA}\nmode={}\nnonce={}\noptions={OPTIONS:#x}\nexitkill=absent\nseize_nonstop=churn-completed-while-seized\ngeteventmsg_bits={}\ngeteventmsg_canary=intact\ngeteventmsg_calls={}\nsupervisor_fork={}\nsupervisor_vfork={}\nsupervisor_clone={}\nsupervisor_exec={}\nsupervisor_exit={}\nchild_fork={}\nchild_vfork={}\nchild_clone={}\nchild_exec={}\nchild_exit={}\nstate=committed\nfrozen_tids={frozen_tids}\ninterrupt_stop={}\norder=supervisor-first\n",
            args.mode.as_str(),
            args.nonce,
            std::mem::size_of::<libc::c_ulong>() * 8,
            lease.events.geteventmsg,
            lease.events.supervisor.fork,
            lease.events.supervisor.vfork,
            lease.events.supervisor.clone,
            lease.events.supervisor.exec,
            lease.events.supervisor.exit,
            lease.events.child.fork,
            lease.events.child.vfork,
            lease.events.child.clone,
            lease.events.child.exec,
            lease.events.child.exit,
            lease.events.interrupt_stop,
        )
        .as_bytes(),
    )?;
    lease.kill_group(lease.fixture.supervisor_pid, lease.fixture.supervisor_start)?;
    lease.verify_anchor(lease.fixture.child_pid, lease.fixture.child_start)?;
    lease.kill_group(lease.fixture.child_pid, lease.fixture.child_start)?;
    write_new(
        &args.root.join("case.commit-kill.receipt"),
        format!(
            "schema={RECEIPT_SCHEMA}\nmode={}\nnonce={}\ncommit=published-before-terminal-action\norder=supervisor-first\nsupervisor=terminal-absent\nchild=terminal-absent\nexit_events={}\nterminal_waits={}\nreap=complete\n",
            args.mode.as_str(),
            args.nonce,
            lease.events.exit,
            lease.events.terminal,
        )
        .as_bytes(),
    )
}

fn run() -> Result<()> {
    let args = parse_args()?;
    validate_root(&args.root)?;
    let self_exe = fs::read_link("/proc/self/exe")?;
    if self_exe.parent() != Some(args.root.as_path()) || fs::canonicalize(&self_exe)? != self_exe {
        return Err(
            "tracer executable must be a canonical direct child of the private case root".into(),
        );
    }
    let (self_class, self_machine) = elf_contract(&self_exe)?;
    if self_class != 1 || self_machine != 40 {
        return Err(format!(
            "tracer must be ELF32 ARM, got class={self_class} machine={self_machine}"
        )
        .into());
    }
    let fixture = load_fixture(&args.root, &args.nonce)?;
    let (fixture_class, fixture_machine) = elf_contract(&fixture.executable)?;
    if fixture_class != 2 || fixture_machine != 183 {
        return Err(format!(
            "fixture must be ELF64 AArch64, got class={fixture_class} machine={fixture_machine}"
        )
        .into());
    }
    let lease = Lease::new(args.root.clone(), fixture);
    match args.mode {
        Mode::ExerciseRollback => run_exercise(&args, lease),
        Mode::PrecommitHold => run_precommit_hold(&args, lease),
        Mode::CommitKill => run_commit_kill(&args, lease),
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr(), "tracer error: {error}");
            ExitCode::FAILURE
        }
    }
}
