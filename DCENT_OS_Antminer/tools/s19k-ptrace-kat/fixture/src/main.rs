use std::collections::BTreeMap;
use std::env;
use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitCode};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const ROOT_PREFIX: &str = "/tmp/dcent-s19k-ptrace-kat.";
const SCHEMA: &str = "s19k-ptrace-fixture-v1";
const POLL: Duration = Duration::from_millis(20);
const READY_TIMEOUT: Duration = Duration::from_secs(15);

type AnyError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, AnyError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Role {
    Supervisor,
    Child,
    ExecLeaf,
}

impl Role {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "supervisor" => Ok(Self::Supervisor),
            "child" => Ok(Self::Child),
            "exec-leaf" => Ok(Self::ExecLeaf),
            _ => Err(format!("unknown role: {value}").into()),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Supervisor => "supervisor",
            Self::Child => "child",
            Self::ExecLeaf => "exec-leaf",
        }
    }
}

#[derive(Debug)]
struct Args {
    role: Role,
    root: PathBuf,
    nonce: String,
    exec_origin: Option<String>,
}

fn parse_args() -> Result<Args> {
    let mut iter = env::args().skip(1);
    let role = Role::parse(&iter.next().ok_or("missing role")?)?;
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
    let root = PathBuf::from(values.remove("--root").ok_or("missing --root")?);
    let nonce = values.remove("--nonce").ok_or("missing --nonce")?;
    let exec_origin = values.remove("--exec-origin");
    if !values.is_empty() {
        return Err(format!("unknown arguments: {values:?}").into());
    }
    if nonce.is_empty()
        || nonce.len() > 64
        || !nonce.bytes().all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err("nonce must be 1..64 ASCII alphanumeric bytes".into());
    }
    Ok(Args {
        role,
        root,
        nonce,
        exec_origin,
    })
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

fn write_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or("progress path has no UTF-8 file name")?;
    let temporary = path.with_file_name(format!(".{file_name}.{}.tmp", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_data()?;
    fs::rename(temporary, path)?;
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

fn proc_start_time(pid: u32) -> Result<u64> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
    let split = stat
        .rfind(") ")
        .ok_or("stat missing final right-parenthesis delimiter")?;
    let remainder = &stat[split + 2..];
    let fields: Vec<&str> = remainder.split_ascii_whitespace().collect();
    let value = fields.get(19).ok_or("stat missing starttime field")?;
    Ok(value.parse()?)
}

struct Runtime {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Runtime {
    fn start(root: &Path, role: Role) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let counter = Arc::new(AtomicU64::new(0));
        let mut threads = Vec::new();
        for _ in 0..3 {
            let stop = Arc::clone(&stop);
            let counter = Arc::clone(&counter);
            threads.push(thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    counter.fetch_add(1, Ordering::Relaxed);
                    thread::sleep(Duration::from_millis(5));
                }
            }));
        }
        let progress_path = root.join(format!("{}.progress", role.as_str()));
        let reporter_stop = Arc::clone(&stop);
        threads.push(thread::spawn(move || {
            while !reporter_stop.load(Ordering::Acquire) {
                let value = counter.load(Ordering::Relaxed);
                let _ = write_replace(&progress_path, format!("{value}\n").as_bytes());
                thread::sleep(POLL);
            }
        }));
        Self { stop, threads }
    }

    fn finish(self) {
        self.stop.store(true, Ordering::Release);
        for handle in self.threads {
            let _ = handle.join();
        }
    }
}

fn wait_for(path: &Path, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        if path.is_file() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("timeout waiting for {}", path.display()).into());
        }
        thread::sleep(POLL);
    }
}

fn wait_child_pid(pid: libc::pid_t) -> Result<i32> {
    let mut status = 0;
    loop {
        // SAFETY: pid is returned by fork/vfork in this process and status is a valid writable int.
        let result = unsafe { libc::waitpid(pid, &mut status, 0) };
        if result == pid {
            return Ok(status);
        }
        if result == -1 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(io::Error::last_os_error().into());
    }
}

fn transient_clone() -> Result<()> {
    thread::spawn(|| {
        thread::sleep(Duration::from_millis(10));
    })
    .join()
    .map_err(|_| "transient clone thread panicked".into())
}

fn transient_fork() -> Result<()> {
    // SAFETY: the fork child calls only async-signal-safe _exit; the parent waits for its exact PID.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(io::Error::last_os_error().into()),
        0 => {
            // SAFETY: immediate _exit is valid in the post-fork child of a multithreaded process.
            unsafe { libc::_exit(31) }
        }
        child => {
            let _ = wait_child_pid(child)?;
            Ok(())
        }
    }
}

fn transient_vfork() -> Result<()> {
    // AArch64 musl's libc::vfork wrapper on the held target reached the
    // kernel as an ordinary fork-class event, so it could not exercise
    // PTRACE_EVENT_VFORK. Issue the exact fork-like clone operation instead.
    // CLONE_VFORK blocks the parent and CLONE_VM shares its address space;
    // the child therefore performs no Rust/library operation and immediately
    // calls the async-signal-safe _exit syscall.
    let flags = libc::CLONE_VFORK | libc::CLONE_VM | libc::SIGCHLD;
    // SAFETY: raw clone uses a null child stack only for this fork-like
    // CLONE_VM|CLONE_VFORK form. The parent is suspended until the child exits,
    // and the child touches no shared Rust state before _exit.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone,
            flags as libc::c_ulong,
            0usize,
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
            std::ptr::null_mut::<libc::c_void>(),
        ) as libc::pid_t
    };
    match pid {
        -1 => Err(io::Error::last_os_error().into()),
        0 => {
            // SAFETY: _exit is the only operation in the vfork child.
            unsafe { libc::_exit(32) }
        }
        child => {
            let _ = wait_child_pid(child)?;
            Ok(())
        }
    }
}

fn transient_exec(root: &Path, nonce: &str, origin: Role) -> Result<()> {
    let executable = env::current_exe()?;
    let executable_c = CString::new(executable.as_os_str().as_bytes())?;
    let argv_values = [
        executable_c.clone(),
        CString::new("exec-leaf")?,
        CString::new("--root")?,
        CString::new(root.as_os_str().as_bytes())?,
        CString::new("--nonce")?,
        CString::new(nonce)?,
        CString::new("--exec-origin")?,
        CString::new(origin.as_str())?,
    ];
    let mut argv: Vec<*const libc::c_char> =
        argv_values.iter().map(|value| value.as_ptr()).collect();
    argv.push(std::ptr::null());

    // SAFETY: the child calls only execv and _exit, using C strings prepared before fork.
    let pid = unsafe { libc::fork() };
    match pid {
        -1 => Err(io::Error::last_os_error().into()),
        0 => {
            // SAFETY: pointers remain valid in the fork child and argv is null-terminated.
            unsafe {
                libc::execv(executable_c.as_ptr(), argv.as_ptr());
                libc::_exit(127);
            }
        }
        child => {
            let _ = wait_child_pid(child)?;
            Ok(())
        }
    }
}

fn run_churn(root: &Path, nonce: &str, role: Role) -> Result<()> {
    transient_clone()?;
    transient_fork()?;
    transient_vfork()?;
    transient_exec(root, nonce, role)?;
    write_new(
        &root.join(format!("{}.churn.done", role.as_str())),
        format!("schema={SCHEMA}\nnonce={nonce}\nrole={}\n", role.as_str()).as_bytes(),
    )
}

fn run_child(args: &Args) -> Result<()> {
    let runtime = Runtime::start(&args.root, Role::Child);
    let pid = std::process::id();
    let start = proc_start_time(pid)?;
    write_new(
        &args.root.join("child.ready"),
        format!(
            "schema={SCHEMA}\nnonce={}\npid={pid}\nstart={start}\n",
            args.nonce
        )
        .as_bytes(),
    )?;
    let mut churned = false;
    while !args.root.join("shutdown").is_file() {
        if !churned && args.root.join("churn.go").is_file() {
            run_churn(&args.root, &args.nonce, Role::Child)?;
            churned = true;
        }
        thread::sleep(POLL);
    }
    runtime.finish();
    Ok(())
}

fn spawn_child(args: &Args) -> Result<Child> {
    let executable = env::current_exe()?;
    Ok(Command::new(executable)
        .arg("child")
        .arg("--root")
        .arg(&args.root)
        .arg("--nonce")
        .arg(&args.nonce)
        .spawn()?)
}

fn run_supervisor(args: &Args) -> Result<()> {
    let runtime = Runtime::start(&args.root, Role::Supervisor);
    let mut child = spawn_child(args)?;
    wait_for(&args.root.join("child.ready"), READY_TIMEOUT)?;
    let child_ready = read_exact_map(
        &args.root.join("child.ready"),
        &["nonce", "pid", "schema", "start"],
    )?;
    if child_ready.get("schema").map(String::as_str) != Some(SCHEMA)
        || child_ready.get("nonce") != Some(&args.nonce)
        || child_ready
            .get("pid")
            .ok_or("missing child pid")?
            .parse::<u32>()?
            != child.id()
    {
        return Err("child ready identity mismatch".into());
    }
    let child_start: u64 = child_ready
        .get("start")
        .ok_or("missing child start")?
        .parse()?;
    let supervisor_pid = std::process::id();
    let supervisor_start = proc_start_time(supervisor_pid)?;
    let executable = fs::canonicalize(env::current_exe()?)?;
    let metadata = fs::metadata(&executable)?;
    write_new(
        &args.root.join("fixture.meta"),
        format!(
            "schema={SCHEMA}\nnonce={}\nfixture_exe={}\nfixture_dev={}\nfixture_ino={}\nsupervisor_pid={supervisor_pid}\nsupervisor_start={supervisor_start}\nchild_pid={}\nchild_start={child_start}\n",
            args.nonce,
            executable.display(),
            metadata.dev(),
            metadata.ino(),
            child.id()
        )
        .as_bytes(),
    )?;
    write_new(
        &args.root.join("fixture.ready"),
        format!("schema={SCHEMA}\nnonce={}\n", args.nonce).as_bytes(),
    )?;

    let mut churned = false;
    while !args.root.join("shutdown").is_file() {
        if !churned && args.root.join("churn.go").is_file() {
            run_churn(&args.root, &args.nonce, Role::Supervisor)?;
            churned = true;
        }
        thread::sleep(POLL);
    }
    runtime.finish();
    let status = child.wait()?;
    write_new(
        &args.root.join("fixture.stopped"),
        format!(
            "schema={SCHEMA}\nnonce={}\nchild_status={status}\n",
            args.nonce
        )
        .as_bytes(),
    )?;
    Ok(())
}

fn run_exec_leaf(args: &Args) -> Result<()> {
    let origin = args.exec_origin.as_deref().ok_or("missing --exec-origin")?;
    let pid = std::process::id();
    write_new(
        &args.root.join(format!("exec.{origin}.{pid}.done")),
        format!(
            "schema={SCHEMA}\nnonce={}\norigin={origin}\npid={pid}\n",
            args.nonce
        )
        .as_bytes(),
    )
}

fn main() -> ExitCode {
    let result = (|| -> Result<()> {
        let args = parse_args()?;
        validate_root(&args.root)?;
        let executable = fs::canonicalize(env::current_exe()?)?;
        if executable.parent() != Some(args.root.as_path()) {
            return Err(
                "fixture executable must be a canonical direct child of the private case root"
                    .into(),
            );
        }
        match args.role {
            Role::Supervisor => run_supervisor(&args),
            Role::Child => run_child(&args),
            Role::ExecLeaf => run_exec_leaf(&args),
        }
    })();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _ = writeln!(io::stderr(), "fixture error: {error}");
            ExitCode::FAILURE
        }
    }
}
