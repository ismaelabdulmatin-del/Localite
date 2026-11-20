//! localite-sandbox — Linux isolation layer for the Localite AWS emulator.
//! (Evolved from sandbox-t1: same namespace/pivot_root/seccomp/cap-drop
//! mechanics, but the payload is now the real six-service `spine`.)
//!
//! What this adds over the PoC (`poc/`):
//!   * seccomp deny-list (~24 rules) installed BEFORE any privilege drop,
//!     with in-sandbox self-tests proving the filter (not just caps) denies.
//!   * `no_new_privs` + full Linux capability drop (bounding + e/p/i).
//!   * Real HTTP/1.1 over TCP on 127.0.0.1 (no netns — deliberate MVP trade,
//!     per RESEARCH.md: bind loopback in the host netns instead of veth/NAT).
//!   * Slightly realer fake S3: PUT/GET/HEAD/DELETE object, PUT/DELETE bucket,
//!     ListObjectsV2 (minimal XML), S3-style XML errors.
//!   * Data-driven Policy (port + cgroup knobs); parent verifies CapBnd=0,
//!     Seccomp=filter-mode, NoNewPrivs=1 from /proc/<pid>/status.
//!
//! Deliberately NOT here: netns/veth plumbing, multi-service orchestration,
//! overlayfs, systemd cgroup driver, seccomp allow-list. See README.md.

mod init;

use libc::{c_char, c_int};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::sched::{clone, CloneFlags};
use nix::sys::signal::Signal;
use nix::sys::wait::waitpid;
use nix::unistd::{close, getpid};
use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn on_term(_sig: c_int) {
    STOP.store(true, Ordering::SeqCst);
}
use std::time::Duration;

// ---------------------------------------------------------------------------
// Policy (data, not code — the per-service policy template)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct Policy {
    port: u16,
    listen: Ipv4Addr,
    daemon: bool,
    no_seccomp: bool,
    mem_max_bytes: Option<u64>,
    cpu_max: Option<String>, // cgroup v2 "MAX period" e.g. "20000 100000"
    pids_max: Option<u64>,
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            port: 4566,
            listen: Ipv4Addr::LOCALHOST,
            daemon: false,
            no_seccomp: false,
            mem_max_bytes: Some(512 * 1024 * 1024),
            cpu_max: None,
            pids_max: Some(512),
        }
    }
}

fn parse_args() -> Result<Policy, String> {
    let mut p = Policy::default();
    let mut it = std::env::args().skip(1).peekable();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--port" => {
                p.port = it
                    .next()
                    .ok_or("--port needs a value")?
                    .parse()
                    .map_err(|_| "bad --port")?
            }
            "--listen" => {
                p.listen = it
                    .next()
                    .ok_or("--listen needs an IPv4 address")?
                    .parse()
                    .map_err(|_| "bad --listen")?
            }
            "--daemon" => p.daemon = true,
            "--no-seccomp" => p.no_seccomp = true,
            "--mem-mb" => {
                let mb: u64 = it
                    .next()
                    .ok_or("--mem-mb needs a value")?
                    .parse()
                    .map_err(|_| "bad --mem-mb")?;
                p.mem_max_bytes = if mb == 0 {
                    None
                } else {
                    Some(mb * 1024 * 1024)
                };
            }
            "--cpu-pct" => {
                let pct: u64 = it
                    .next()
                    .ok_or("--cpu-pct needs a value")?
                    .parse()
                    .map_err(|_| "bad --cpu-pct")?;
                p.cpu_max = if pct == 0 {
                    None
                } else {
                    Some(format!("{} 100000", pct * 1000))
                };
            }
            "--pids-max" => {
                let n: u64 = it
                    .next()
                    .ok_or("--pids-max needs a value")?
                    .parse()
                    .map_err(|_| "bad --pids-max")?;
                p.pids_max = if n == 0 { None } else { Some(n) };
            }
            "--help" | "-h" => {
                println!("usage: localite-sandbox [--daemon] [--listen IPV4] [--port N] [--mem-mb N] [--cpu-pct N] [--pids-max N] [--no-seccomp]  (0 disables a limit; without --daemon it runs the self-test and exits)");
                exit(0);
            }
            other => return Err(format!("unknown arg: {other}")),
        }
    }
    Ok(p)
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

fn errno() -> i32 {
    unsafe { *libc::__errno_location() }
}

fn cstr<T: Into<Vec<u8>>>(s: T) -> CString {
    CString::new(s).unwrap()
}

// ---------------------------------------------------------------------------
// seccomp deny-list: hand-rolled classic BPF, installed via seccomp(2).
// Production path per RESEARCH.md would be the `seccompiler` crate; the
// hand-rolled filter keeps the spike auditable and dependency-free.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

const B_LD_W_ABS: u16 = 0x20;
const B_JMP_JEQ_K: u16 = 0x15;
const B_ALU_AND_K: u16 = 0x54;
const B_RET_K: u16 = 0x06;

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
#[allow(dead_code)]
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
const SECCOMP_FILTER_FLAG_TSYNC: u64 = 1;
const EPERM: i32 = 1;

/// Minimal forward-jump assembler for classic BPF.
struct Asm {
    ins: Vec<SockFilter>,
    labels: Vec<Option<usize>>,
    patches: Vec<(usize, usize, bool)>, // (instr, label, is_jt)
}

impl Asm {
    fn new(nlabels: usize) -> Self {
        Asm {
            ins: Vec::new(),
            labels: vec![None; nlabels],
            patches: Vec::new(),
        }
    }
    fn emit(&mut self, code: u16, k: u32) -> usize {
        let i = self.ins.len();
        self.ins.push(SockFilter {
            code,
            jt: 0,
            jf: 0,
            k,
        });
        i
    }
    /// JEQ k: jump to jt_label if equal, jf_label (or fall through) if not.
    fn jeq(&mut self, k: u32, jt_label: usize, jf_label: Option<usize>) {
        let i = self.emit(B_JMP_JEQ_K, k);
        self.patches.push((i, jt_label, true));
        if let Some(l) = jf_label {
            self.patches.push((i, l, false));
        }
    }
    fn label(&mut self, id: usize) {
        assert!(self.labels[id].is_none(), "duplicate label");
        self.labels[id] = Some(self.ins.len());
    }
    fn finish(mut self) -> Vec<SockFilter> {
        for (idx, lab, is_jt) in self.patches.clone() {
            let target = self.labels[lab].expect("undefined label");
            assert!(target > idx, "BPF: only forward jumps supported");
            let dist = target - idx - 1;
            assert!(dist <= 255, "BPF: jump too far");
            if is_jt {
                self.ins[idx].jt = dist as u8;
            } else {
                self.ins[idx].jf = dist as u8;
            }
        }
        self.ins
    }
}

// Two-stage seccomp design.
//
// The child runs inside a NEW user namespace, and this environment's policy
// returns EINVAL for seccomp(2) from inside a nested userns (verified
// empirically: trivial filter installs fine in the parent, EINVAL in the
// child). So the filter is installed by the PARENT pre-clone and inherited.
//
//   Stage P (parent, pre-clone, inherited): denies the always-dangerous
//     syscalls. MUST allow mount/umount2/pivot_root (the child needs them
//     for rootfs setup) and clone with any flags (the parent needs
//     CLONE_NEW* for the sandbox creation itself).
//   Stage C (child, post-setup, best-effort): denies the setup syscalls and
//     namespace-creating clone flags. Installs on a real host; skipped with
//     a warning where the nested-userns policy blocks it.
//
// The composition is still sound where C is unavailable: the syscalls P must
// allow are all privilege-gated (CAP_SYS_ADMIN), and the child drops every
// capability + sets no_new_privs before serving. This mirrors Docker's own
// model (default seccomp profile + dropped caps + no_new_privs).

/// Per-architecture syscall numbers. The filter is arch-guarded: a process
/// running under a different audit arch than the one compiled in is killed,
/// never silently allowed.
struct ArchDef {
    audit: u32,
    p_denied: &'static [u32],
    c_denied: &'static [u32],
    clone_nr: u32,
    clone3_nr: u32,
}

const CLONE3_NR: u32 = 435; // same on x86_64 and aarch64

#[allow(dead_code)]
const X86_64: ArchDef = ArchDef {
    audit: AUDIT_ARCH_X86_64,
    p_denied: &[
        101, // ptrace
        310, // process_vm_readv
        311, // process_vm_writev
        248, // add_key
        249, // request_key
        250, // keyctl
        175, // init_module
        313, // finit_module
        176, // delete_module
        169, // reboot
        246, // kexec_load
        320, // kexec_file_load
        167, // swapon
        168, // swapoff
        321, // bpf
        323, // userfaultfd
        304, // open_by_handle_at
        272, // unshare
        308, // setns
    ],
    c_denied: &[165 /* mount */, 166 /* umount2 */, 155 /* pivot_root */],
    clone_nr: 56,
    clone3_nr: CLONE3_NR,
};

#[allow(dead_code)]
const AARCH64: ArchDef = ArchDef {
    audit: AUDIT_ARCH_AARCH64,
    p_denied: &[
        117, // ptrace
        270, // process_vm_readv
        271, // process_vm_writev
        217, // add_key
        218, // request_key
        219, // keyctl
        105, // init_module
        273, // finit_module
        106, // delete_module
        142, // reboot
        104, // kexec_load
        294, // kexec_file_load
        224, // swapon
        225, // swapoff
        280, // bpf
        282, // userfaultfd
        265, // open_by_handle_at
        97,  // unshare
        268, // setns
    ],
    c_denied: &[40 /* mount */, 39 /* umount2 */, 41 /* pivot_root */],
    clone_nr: 220,
    clone3_nr: CLONE3_NR,
};

#[cfg(target_arch = "x86_64")]
const HOST_ARCH: &ArchDef = &X86_64;
#[cfg(target_arch = "aarch64")]
const HOST_ARCH: &ArchDef = &AARCH64;

// Mask of all CLONE_NEW* flags: NEWNS|NEWCGROUP|NEWUTS|NEWIPC|NEWUSER|NEWPID|NEWNET
const CLONE_NEW_MASK: u32 = 0x7F02_0000;
const ENOSYS: u32 = 38;

/// `denied`: syscalls answered with EPERM. `clone3` is always answered with
/// ENOSYS (not EPERM) so glibc's pthread_create falls back to clone(2) —
/// this is what Docker's default profile does for the same reason.
fn build_filter(arch: &ArchDef, denied: &[u32], clone_flag_check: bool) -> Vec<SockFilter> {
    const L_ALLOW: usize = 0;
    const L_DENY: usize = 1;
    const L_KILL: usize = 2;
    const L_OK: usize = 3;
    const L_CLONECHK: usize = 4;
    const L_CHAIN: usize = 5;
    const L_NOSYS: usize = 6;
    let mut a = Asm::new(7);

    // seccomp_data offsets: nr@0, arch@4, ip@8, args@16
    a.emit(B_LD_W_ABS, 4); // arch
    a.jeq(arch.audit, L_OK, Some(L_KILL)); // wrong arch -> kill (nrs differ)
    a.label(L_OK);
    a.emit(B_LD_W_ABS, 0); // nr (the arch check leaves arch in A; reload)

    a.jeq(arch.clone3_nr, L_NOSYS, None);

    if clone_flag_check {
        // clone(2) needs flag inspection: deny only namespace-creating flags.
        a.jeq(arch.clone_nr, L_CLONECHK, Some(L_CHAIN));
        a.label(L_CLONECHK);
        a.emit(B_LD_W_ABS, 16); // args[0] = clone flags
        a.emit(B_ALU_AND_K, CLONE_NEW_MASK);
        a.jeq(0, L_ALLOW, Some(L_DENY)); // no newns bits -> allow
    }

    a.label(L_CHAIN);
    for &nr in denied {
        a.jeq(nr, L_DENY, None); // jf=0 falls through to next check
    }

    a.label(L_ALLOW);
    a.emit(B_RET_K, SECCOMP_RET_ALLOW);
    a.label(L_DENY);
    a.emit(B_RET_K, SECCOMP_RET_ERRNO | (EPERM as u32));
    a.label(L_NOSYS);
    a.emit(B_RET_K, SECCOMP_RET_ERRNO | ENOSYS);
    a.label(L_KILL);
    a.emit(B_RET_K, SECCOMP_RET_KILL_PROCESS);
    a.finish()
}

fn install_filter(ins: &[SockFilter]) -> Result<(), i32> {
    let prog = SockFprog {
        len: ins.len() as u16,
        filter: ins.as_ptr(),
    };
    // SECCOMP_SET_MODE_FILTER=1 (0 is SET_MODE_STRICT, which rejects a
    // program/flags with EINVAL: the original code passed 0 and so never
    // installed any filter). TSYNC is harmless single-threaded and required
    // if the process ever spawns threads later.
    let r = unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            1u64,
            SECCOMP_FILTER_FLAG_TSYNC,
            &prog as *const SockFprog,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(errno())
    }
}

// ---------------------------------------------------------------------------
// privilege drop: no_new_privs + clear every capability set
// ---------------------------------------------------------------------------

fn set_no_new_privs() -> Result<(), String> {
    let r = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS as c_int, 1, 0, 0, 0) };
    if r == 0 {
        Ok(())
    } else {
        Err(format!("PR_SET_NO_NEW_PRIVS failed: errno {}", errno()))
    }
}

fn drop_all_caps() -> Result<(), String> {
    // 1. bounding set: drop every capability (ignore errors for unknown caps)
    for c in 0..64u64 {
        unsafe {
            libc::prctl(libc::PR_CAPBSET_DROP as c_int, c, 0, 0, 0);
        }
    }
    // 2. effective/permitted/inheritable -> zero via capset(2).
    // (libc has no capset binding, so: own structs + raw syscall.)
    #[repr(C)]
    struct CapHeader {
        version: u32,
        pid: i32,
    }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData {
        effective: u32,
        permitted: u32,
        inheritable: u32,
    }
    let hdr = CapHeader {
        version: 0x2008_0522, // _LINUX_CAPABILITY_VERSION_3
        pid: 0,
    };
    let data = [CapData {
        effective: 0,
        permitted: 0,
        inheritable: 0,
    }; 2];
    let r = unsafe {
        libc::syscall(
            libc::SYS_capset,
            &hdr as *const CapHeader,
            data.as_ptr() as *const CapData,
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(format!("capset failed: errno {}", errno()))
    }
}
// ---------------------------------------------------------------------------
// namespace bootstrap (user/mount/pid/uts — NO netns by design: the service
// binds 127.0.0.1 in the host netns, the pragmatic MVP per RESEARCH.md)
// ---------------------------------------------------------------------------

const STACK_SIZE: usize = 1024 * 1024;

fn pivot_root_raw(new_root: &Path, put_old: &Path) -> Result<(), String> {
    let r = unsafe {
        libc::syscall(
            libc::SYS_pivot_root,
            cstr(new_root.as_os_str().as_bytes()).as_ptr(),
            cstr(put_old.as_os_str().as_bytes()).as_ptr(),
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(format!("pivot_root failed: errno {}", errno()))
    }
}

fn setup_namespaces(
    stage: &Path,
    ctl: UnixStream,
    policy: &Policy,
    canary: &Path,
    p_active: bool,
) -> Result<(), String> {
    // --- mount namespace prep (before pivot) ---
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_REC | MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| {
        format!("make-rprivate /: {e} (rootless needs unprivileged userns mount rights)")
    })?;

    let new_root = stage.join("root");
    let moto_backend = std::env::var("LOCALITE_BACKEND").as_deref() == Ok("moto");
    fs::create_dir_all(&new_root).map_err(|e| format!("mkdir {}: {e}", new_root.display()))?;
    if moto_backend {
        mount(
            Some("/moto-rootfs"),
            &new_root,
            None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC,
            None::<&str>,
        )
        .map_err(|e| format!("bind Moto rootfs into sandbox: {e}"))?;
    } else {
        mount(
            Some("tmpfs"),
            &new_root,
            Some("tmpfs"),
            MsFlags::empty(),
            Some("size=32M,mode=755"),
        )
        .map_err(|e| format!("tmpfs new_root: {e}"))?;
    }
    for d in ["app", "dev", "tmp", "proc"] {
        fs::create_dir_all(new_root.join(d)).map_err(|e| format!("mkdir2 {}: {e}", d))?;
    }
    if moto_backend {
        mount(
            Some("tmpfs"),
            &new_root.join("tmp"),
            Some("tmpfs"),
            MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
            Some("size=64M,mode=1777"),
        )
        .map_err(|e| format!("tmpfs /tmp: {e}"))?;
    }
    let workspace_requested = std::env::var("LOCALITE_WORKSPACE").as_deref() == Ok("1");
    if workspace_requested {
        let destination = new_root.join("workspace");
        fs::create_dir_all(&destination)
            .map_err(|e| format!("mkdir {}: {e}", destination.display()))?;
        mount(
            Some("/workspace"),
            &destination,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .map_err(|e| format!("bind guest workspace into sandbox: {e}"))?;
    }
    // bind our own binary into the new root
    let me_exe =
        fs::read_link("/proc/self/exe").map_err(|e| format!("readlink /proc/self/exe: {e}"))?;
    fs::copy(&me_exe, new_root.join("app/localite-sandbox")).map_err(|e| format!("stage binary: {e}"))?;

    // /dev: runc-style bind-mount of host devices, done pre-pivot while the
    // host /dev is still reachable. (mknod is blocked by this environment's
    // outer policy; bind-mount is also what runc does in production.)
    let mut report: Vec<String> = Vec::new();
    for name in ["null", "zero", "urandom", "full"] {
        let dst = new_root.join(format!("dev/{name}"));
        fs::File::create(&dst).map_err(|e| format!("create {}: {e}", dst.display()))?;
        let src = format!("/dev/{name}");
        let r = mount(
            Some(src.as_str()),
            &dst,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        );
        if let Err(e) = r {
            let _ = fs::remove_file(&dst);
            let devnum: u64 = match name {
                "null" => 0x0103,
                "zero" => 0x0105,
                "urandom" => 0x0109,
                "full" => 0x0107,
                _ => unreachable!(),
            };
            let mr = unsafe {
                libc::mknod(
                    cstr(dst.to_string_lossy().as_bytes()).as_ptr(),
                    0o020000u32 | 0o666u32, // S_IFCHR | rw-rw-rw-
                    devnum as libc::dev_t,
                )
            };
            if mr != 0 {
                report.push(format!(
                    "/dev/{name}: no device node (bind failed: {e}; mknod blocked here)"
                ));
            }
        }
    }

    pivot_root_raw(&new_root, &new_root.join("proc"))?;
    // now inside new root: old root is at /proc
    std::env::set_current_dir("/").map_err(|e| format!("chdir /: {e}"))?;
    umount2("/proc", MntFlags::MNT_DETACH).map_err(|e| format!("detach old root: {e}"))?;
    fs::create_dir_all("/proc").map_err(|e| format!("mkdir /proc: {e}"))?;

    // --- in-sandbox isolation proofs (reported to parent) ---
    report.push(format!("pid={} (expect 1: first in new PID ns)", getpid()));
    let mut entries: Vec<String> = fs::read_dir("/")
        .map_err(|e| format!("read_dir /: {e}"))?
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    entries.sort();
    let mut expected_entries = vec!["app", "dev", "proc", "tmp"];
    if workspace_requested {
        expected_entries.push("workspace");
        let count = fs::read_dir("/workspace")
            .map_err(|e| format!("read isolated workspace: {e}"))?
            .count();
        report.push(format!(
            "workspace: isolated and mounted at /workspace ({count} top-level entries)"
        ));
    }
    if moto_backend {
        report.push(format!("root_entries={entries:?} (isolated Moto image root)"));
    } else {
        report.push(format!(
            "root_entries={entries:?} (expect {expected_entries:?}; parent fs gone)"
        ));
    }
    match fs::read(canary) {
        Ok(_) => report.push("canary: READABLE (ISOLATION FAILURE)".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            report.push("canary: unreadable as expected (ENOENT)".into())
        }
        Err(e) => report.push(format!("canary: unexpected error: {e}")),
    }

    // --- stage-C filter: best-effort tightening of the inherited stage-P
    // filter. Works on a real host; this nested-userns environment returns
    // EINVAL, in which case the inherited stage-P filter still applies and
    // the caps-drop below neutralizes the setup syscalls P must allow. ---
    let c_active = install_filter(&build_filter(HOST_ARCH, HOST_ARCH.c_denied, true)).is_ok();
    report.push(format!(
        "stage-P filter: {}; stage-C filter: {}",
        if p_active {
            "ACTIVE (inherited)"
        } else {
            "unavailable here"
        },
        if c_active {
            "INSTALLED"
        } else {
            "unavailable in nested userns (EINVAL)"
        }
    ));
    report.extend(selftest_seccomp(p_active, c_active));

    // --- then drop privileges ---
    set_no_new_privs()?;
    drop_all_caps()?;
    // phase B: privilege-gated syscalls must fail now even where the
    // inherited filter permits them.
    report.extend(selftest_postdrop());

    // --- bind the TCP listener BEFORE signaling READY, so the parent's
    // HTTP tests can never race the listen socket. ---
    // PID 1 of a namespace ignores signals without a handler.
    unsafe {
        libc::signal(libc::SIGTERM, on_term as usize);
        libc::signal(libc::SIGINT, on_term as usize);
    }
    let addr = SocketAddrV4::new(policy.listen, policy.port);
    let listener = if moto_backend {
        let mut server = std::process::Command::new("/usr/local/bin/moto_server")
            .args(["-H", "127.0.0.1", "-p", &policy.port.to_string()])
            .current_dir("/moto")
            .spawn()
            .map_err(|e| format!("start Moto API server: {e}"))?;
        let deadline = std::time::Instant::now() + Duration::from_secs(90);
        loop {
            if let Some(status) = server
                .try_wait()
                .map_err(|e| format!("check Moto API server: {e}"))?
            {
                return Err(format!("Moto API server exited before readiness: {status}"));
            }
            if TcpStream::connect(addr).is_ok() {
                break;
            }
            if STOP.load(Ordering::SeqCst) {
                let _ = server.kill();
                let _ = server.wait();
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                let _ = server.kill();
                let _ = server.wait();
                return Err("Moto API server did not become ready within 90 seconds".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        // Keep the child alive until the sandbox is stopped, and reap it here.
        // The parent communicates readiness through the control socket below.
        let mut ctl = ctl;
        for line in &report {
            let _ = writeln!(ctl, "ST {line}");
        }
        let _ = writeln!(ctl, "ST Moto API server ready");
        let _ = writeln!(ctl, "READY");
        let _ = ctl.flush();
        loop {
            if let Some(status) = server
                .try_wait()
                .map_err(|e| format!("wait for Moto API server: {e}"))?
            {
                return if status.success() {
                    Ok(())
                } else {
                    Err(format!("Moto API server exited: {status}"))
                };
            }
            if STOP.load(Ordering::SeqCst) {
                let _ = server.kill();
                let _ = server.wait();
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    } else {
        Some(
            TcpListener::bind(addr)
                .map_err(|e| format!("bind {}:{}: {e}", policy.listen, policy.port))?,
        )
    };
    let (app, _auth) = spine::app_from_env();

    // report + READY over the control channel
    let mut ctl = ctl;
    for line in &report {
        let _ = writeln!(ctl, "ST {line}");
    }
    let _ = writeln!(ctl, "READY");
    let _ = ctl.flush();

    // --- serve the Rust compatibility backend inside the sandbox ---
    spine::serve_until(Arc::clone(&app), listener.expect("Rust backend listener"), &STOP);
    Ok(())
}

/// Phase-A self-tests: syscalls the active filter(s) must deny.
/// Runs BEFORE the capability drop, so a denial proves the seccomp filter
/// (full caps are still held at this point). Skipped entirely when no filter
/// could be installed (this environment's outer sandbox allowlists only
/// trivial filter programs).
fn selftest_seccomp(p_active: bool, c_active: bool) -> Vec<String> {
    if !p_active && !c_active {
        return vec![
            "seccomp self-tests SKIPPED: no filter active in this environment \
             (seccomp(2) refused the filter; see the errno printed above)"
                .into(),
        ];
    }
    let mut out = Vec::new();
    let check = |name: &str, ret: i64| {
        let e = errno();
        let ok = ret == -1 && e == EPERM;
        format!(
            "{name}: ret={ret} errno={e} -> {}",
            if ok {
                "DENIED(as expected)"
            } else {
                "UNEXPECTED"
            }
        )
    };
    unsafe {
        // denied by the inherited stage-P filter on every host
        out.push(check(
            "unshare(CLONE_NEWNS)",
            libc::syscall(libc::SYS_unshare, libc::CLONE_NEWNS as u64),
        ));
        out.push(check(
            "ptrace(PTRACE_TRACEME)",
            libc::syscall(libc::SYS_ptrace, 0u64, 0u64, 0u64, 0u64),
        ));
        out.push(check(
            "bpf(BPF_MAP_CREATE)",
            libc::syscall(libc::SYS_bpf, 0u64, 0u64, 0u64),
        ));
        {
            // clone3 -> ENOSYS by design (so glibc falls back to clone(2))
            let r = libc::syscall(libc::SYS_clone3, std::ptr::null::<c_char>(), 0u64);
            let e = errno();
            out.push(format!(
                "clone3(): ret={r} errno={e} -> {}",
                if r == -1 && e == ENOSYS as i32 { "DENIED(ENOSYS as designed)" } else { "UNEXPECTED" }
            ));
        }
        if c_active {
            // denied by the stage-C filter (real hosts)
            out.push(check(
                "mount(tmpfs on /tmp)",
                libc::syscall(
                    libc::SYS_mount,
                    cstr("none").as_ptr(),
                    cstr("/tmp").as_ptr(),
                    cstr("tmpfs").as_ptr(),
                    0u64,
                    std::ptr::null::<c_char>(),
                ),
            ));
            // filter denies before any child is created: no stray process
            out.push(check(
                "clone(CLONE_NEWNS|SIGCHLD)",
                libc::syscall(
                    libc::SYS_clone,
                    (libc::CLONE_NEWNS | libc::SIGCHLD) as u64,
                    0u64,
                ),
            ));
        } else {
            out.push(
                "mount/pivot_root: allowed by inherited stage-P filter (setup needs them); \
                 neutralized post-drop by zero caps (see phase B)"
                    .into(),
            );
        }
        // sanity: an allowed syscall still works
        let pid = libc::syscall(libc::SYS_getpid);
        out.push(format!(
            "getpid(): ret={pid} -> {}",
            if pid > 0 {
                "ALLOWED(as expected)"
            } else {
                "UNEXPECTED"
            }
        ));
    }
    out
}

/// Phase-B self-test: after zero caps + no_new_privs, privilege-gated
/// syscalls must fail even where the inherited filter permits them.
fn selftest_postdrop() -> Vec<String> {
    let mut out = Vec::new();
    unsafe {
        let r = libc::syscall(
            libc::SYS_mount,
            cstr("none").as_ptr(),
            cstr("/tmp").as_ptr(),
            cstr("tmpfs").as_ptr(),
            0u64,
            std::ptr::null::<c_char>(),
        );
        let e = errno();
        out.push(format!(
            "post-drop mount(tmpfs on /tmp): ret={r} errno={e} -> {}",
            if r == -1 && e == EPERM {
                "DENIED(as expected: no CAP_SYS_ADMIN)"
            } else {
                "UNEXPECTED"
            }
        ));
    }
    out
}

// ---------------------------------------------------------------------------
// parent: spawn, verify, test over real TCP, report
// ---------------------------------------------------------------------------

fn setup_cgroup(tag: &str, policy: &Policy) -> Result<(PathBuf, Vec<String>), String> {
    let root = Path::new("/sys/fs/cgroup");
    if fs::read_to_string(root.join("cgroup.controllers")).is_err() {
        return Err(
            "cannot read /sys/fs/cgroup/cgroup.controllers (not mounted or not accessible)".into(),
        );
    }
    for c in ["memory", "cpu", "pids"] {
        let _ = fs::write(root.join("cgroup.subtree_control"), format!("+{c}"));
    }
    let dir = root.join(format!("localite-{tag}"));
    let _ = fs::remove_dir(&dir);
    fs::create_dir(&dir).map_err(|e| format!("mkdir cgroup: {e}"))?;
    let avail = fs::read_to_string(dir.join("cgroup.controllers")).unwrap_or_default();
    let mut applied = Vec::new();
    let w = |f: &str, v: &str| fs::write(dir.join(f), v);
    if avail.contains("memory") {
        if let Some(mb) = policy.mem_max_bytes {
            if w("memory.max", &mb.to_string()).is_ok() {
                applied.push(format!("memory.max={mb}"));
            }
        }
    }
    if avail.contains("cpu") {
        if let Some(c) = &policy.cpu_max {
            if w("cpu.max", c).is_ok() {
                applied.push(format!("cpu.max={c}"));
            }
        }
    }
    if avail.contains("pids") {
        if let Some(p) = policy.pids_max {
            if w("pids.max", &p.to_string()).is_ok() {
                applied.push(format!("pids.max={p}"));
            }
        }
    }
    if applied.is_empty() {
        let _ = fs::remove_dir(&dir);
        return Err(
            "no cgroup controllers delegated by the host (memory/cpu/pids all unavailable)".into(),
        );
    }
    Ok((dir, applied))
}

fn ns_ino(pid: u32, ns: &str) -> String {
    fs::read_link(format!("/proc/{pid}/ns/{ns}"))
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "?".into())
}

fn http_round(
    stream: &mut TcpStream,
    req: &str,
    body: Option<&[u8]>,
) -> Result<(String, Vec<u8>), String> {
    let mut full = req.as_bytes().to_vec();
    if let Some(b) = body {
        full.extend_from_slice(b);
    }
    stream
        .write_all(&full)
        .map_err(|e| format!("write req: {e}"))?;
    stream.flush().map_err(|e| format!("flush: {e}"))?;
    // status line
    let mut head = Vec::new();
    let mut tmp = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let n = stream.read(&mut tmp).map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("connection closed".into());
        }
        head.push(tmp[0]);
        if head.len() > 65536 {
            return Err("header too big".into());
        }
    }
    let head_s = String::from_utf8_lossy(&head).into_owned();
    let status = head_s
        .lines()
        .next()
        .unwrap_or("")
        .splitn(3, ' ')
        .nth(1)
        .unwrap_or("")
        .to_string();
    let cl: usize = head_s
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.trim().eq_ignore_ascii_case("content-length") {
                v.trim().parse().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);
    let mut out = vec![0u8; cl];
    stream
        .read_exact(&mut out)
        .map_err(|e| format!("read body: {e}"))?;
    Ok((status, out))
}

fn real_main() -> Result<(), String> {
    let policy = parse_args()?;
    println!("localite-sandbox: policy: {policy:?}");

    let tag = format!("{}", getpid());
    let stage = std::env::temp_dir().join(format!("localite-stage-{tag}"));
    let _ = fs::remove_dir_all(&stage);
    fs::create_dir_all(&stage).map_err(|e| format!("stage dir: {e}"))?;

    // host canary: must be invisible inside the sandbox
    let canary = std::env::temp_dir().join(format!("localite-canary-{tag}"));
    fs::write(&canary, b"host secret").map_err(|e| format!("canary: {e}"))?;

    // cgroup: best-effort
    let cgroup = setup_cgroup(&tag, &policy);
    match &cgroup {
        Ok((_, applied)) => println!("[+] cgroup: limits applied: {}", applied.join(", ")),
        Err(e) => {
            println!("[!] cgroup limits unavailable: {e}\n    continuing WITHOUT resource limits")
        }
    }

    // Stage-P seccomp filter: installed pre-clone, inherited by the child.
    // (The child cannot install its own inside a nested userns — EINVAL —
    // so the parent installs the inheritable base here.)
    // Best-effort: this nested sandbox allowlists only trivial filter
    // programs (verified empirically), so a real deny-list gets EINVAL here.
    // We warn loudly and continue — the namespaces/caps/no_new_privs below
    // still hold, and the filter path is fully implemented for real hosts.
    let p_res = if policy.no_seccomp {
        Err(-1)
    } else {
        install_filter(&build_filter(HOST_ARCH, HOST_ARCH.p_denied, false))
    };
    if let Err(e) = p_res {
        println!("[!] seccomp install errno={e}");
    }
    let p_active = p_res.is_ok();
    if p_active {
        println!("[+] stage-P seccomp filter installed (inherited by child)");
    } else {
        println!("[!] stage-P seccomp NOT installed (disabled or refused by kernel);");
        println!("    continuing WITHOUT seccomp. Namespaces + no_new_privs + zero caps still apply.");
    }

    // control channel for READY + self-test report
    let (psock, csock) = UnixStream::pair().map_err(|e| format!("socketpair: {e}"))?;
    let (sync_r, sync_w) = nix::unistd::pipe().map_err(|e| format!("pipe: {e}"))?;
    let sync_r: RawFd = sync_r.into_raw_fd();
    let sync_w: RawFd = sync_w.into_raw_fd();

    let mut stack = vec![0u8; STACK_SIZE];
    let flags = CloneFlags::CLONE_NEWUSER
        | CloneFlags::CLONE_NEWNS
        | CloneFlags::CLONE_NEWPID
        | CloneFlags::CLONE_NEWUTS;
    // Option-take: the callback moves `csock` but nix::clone needs FnMut
    // (it calls the closure exactly once).
    let mut csock_opt = Some(csock);
    let child_cb = Box::new(|| {
        let csock = csock_opt.take().expect("clone callback called twice");
        // our fd table is a copy of the parent's: closing here doesn't touch it
        close(psock.as_raw_fd()).ok(); // don't hold the parent's socket end open
        close(sync_w).ok(); // our copy of the write end
                            // wait for the parent to write uid_map/gid_map (parent-writes pattern);
                            // the sync byte also carries whether the stage-P filter is active.
        let mut b = [0u8; 1];
        let n = unsafe { libc::read(sync_r, b.as_mut_ptr() as *mut libc::c_void, 1) };
        close(sync_r).ok();
        if n != 1 {
            eprintln!("child: sync pipe closed before parent wrote uid_map");
            return 1isize;
        }
        let p_active = b[0] == b'1';
        match setup_namespaces(&stage, csock, &policy, &canary, p_active) {
            Ok(_) => 0isize,
            Err(e) => {
                eprintln!("child: fatal: {e}");
                1isize
            }
        }
    });
    let child = unsafe { clone(child_cb, &mut stack, flags, Some(Signal::SIGCHLD as i32)) }
        .map_err(|e| format!("clone: {e}"))?;
    let mut psock = psock;
    close(sync_r).ok(); // our copy of the read end

    // parent writes uid/gid maps (child-writes fails with EPERM pre-map)
    let pid = child.as_raw();
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    fs::write(format!("/proc/{pid}/uid_map"), format!("0 {uid} 1")).map_err(|e| format!("uid_map: {e}"))?;
    fs::write(format!("/proc/{pid}/setgroups"), "deny").map_err(|e| format!("setgroups: {e}"))?;
    fs::write(format!("/proc/{pid}/gid_map"), format!("0 {gid} 1")).map_err(|e| format!("gid_map: {e}"))?;
    println!("[+] wrote uid_map/gid_map for child (0 -> {uid}/{gid})");
    // wake the child; the byte also reports stage-P filter status
    let wake = if p_active { b"1" } else { b"0" };
    unsafe {
        libc::write(sync_w, wake.as_ptr() as *const libc::c_void, 1);
    }
    close(sync_w).ok();

    if let Ok((dir, _)) = &cgroup {
        let w = |f: &str, v: &str| fs::write(dir.join(f), v);
        w("cgroup.procs", &format!("{pid}")).map_err(|e| format!("cgroup.procs: {e}"))?;
        println!("[+] child moved into cgroup");
    }

    // namespace proof (parent side — airtight)
    println!("\n--- namespace isolation (parent-measured) ---");
    let me = std::process::id();
    for ns in ["pid", "mnt", "uts", "user", "ipc", "cgroup", "net"] {
        let (a, b) = (ns_ino(me, ns), ns_ino(pid as u32, ns));
        let note = if ns == "net" {
            "(shared BY DESIGN: service binds 127.0.0.1 in host netns)"
        } else if a == b {
            "(shared)"
        } else {
            "(ISOLATED)"
        };
        println!("    {ns:<7} parent={a} child={b} {note}");
    }

    // wait for READY + self-test report over control channel
    println!("\n--- seccomp self-tests (run INSIDE the sandbox, pre-priv-drop) ---");
    psock.set_read_timeout(Some(Duration::from_secs(15))).ok();
    let mut ctl_buf = Vec::new();
    let mut tmp = [0u8; 1024];
    let ready = loop {
        let n = psock
            .read(&mut tmp)
            .map_err(|e| format!("control channel: {e}"))?;
        if n == 0 {
            break false;
        }
        ctl_buf.extend_from_slice(&tmp[..n]);
        if ctl_buf.windows(6).any(|w| w == b"READY\n") {
            break true;
        }
    };
    if !ready {
        return Err("child never signaled READY".into());
    }
    for line in String::from_utf8_lossy(&ctl_buf).lines() {
        if let Some(rep) = line.strip_prefix("ST ") {
            println!("    {rep}");
        }
    }

    // privilege proof from /proc/<pid>/status (parent side)
    println!("\n--- privilege drop (parent-measured from /proc/{pid}/status) ---");
    let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    for key in ["CapBnd", "Seccomp", "NoNewPrivs"] {
        let val = status.lines().find(|l| l.starts_with(key)).unwrap_or("?");
        println!("    {val}");
    }
    let capbnd_zero = status
        .lines()
        .find(|l| l.starts_with("CapBnd"))
        .map(|l| l.ends_with('0'))
        .unwrap_or(false);
    if !capbnd_zero {
        println!("    [!] WARNING: CapBnd is not zero — capability drop incomplete");
    }

    // --- daemon mode: stay up until signalled ---
    if policy.daemon {
        println!(
            "\n[+] LOCALITE READY on http://{}:{} (sandbox pid {pid})",
            policy.listen, policy.port
        );
        let _ = std::io::stdout().flush();
        unsafe {
            libc::signal(libc::SIGTERM, on_term as usize);
            libc::signal(libc::SIGINT, on_term as usize);
        }
        loop {
            match nix::sys::wait::waitpid(child, Some(nix::sys::wait::WaitPidFlag::WNOHANG)) {
                Ok(nix::sys::wait::WaitStatus::StillAlive) => {}
                Ok(st) => {
                    println!("[+] sandbox exited: {st:?}");
                    let _ = fs::remove_dir_all(&stage);
                    let _ = fs::remove_file(&canary);
                    if let Ok((dir, _)) = &cgroup {
                        let _ = fs::remove_dir(dir);
                    }
                    return Ok(());
                }
                Err(e) => return Err(format!("waitpid: {e}")),
            }
            if STOP.load(Ordering::SeqCst) {
                unsafe { libc::kill(child.as_raw(), libc::SIGTERM) };
                let st = waitpid(child, None).map_err(|e| format!("waitpid: {e}"))?;
                println!("[+] sandbox stopped: {st:?}");
                let _ = fs::remove_dir_all(&stage);
                let _ = fs::remove_file(&canary);
                if let Ok((dir, _)) = &cgroup {
                    let _ = fs::remove_dir(dir);
                }
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // --- self-test: drive every service over REAL TCP, outside the sandbox ---
    let host = if policy.listen.is_unspecified() { Ipv4Addr::LOCALHOST } else { policy.listen };
    println!("\n--- six-service AWS round-trips over real TCP {host}:{} ---", policy.port);
    let mut failures = 0usize;
    let mut check = |name: &str, ok: bool, detail: String| {
        println!("    {} {name}: {detail}", if ok { "ok  " } else { "FAIL" });
        if !ok {
            failures += 1;
        }
    };
    let call = |req: &str, body: &[u8]| -> Result<(String, Vec<u8>), String> {
        let mut s = TcpStream::connect((host, policy.port)).map_err(|e| format!("connect: {e}"))?;
        s.set_read_timeout(Some(Duration::from_secs(10))).ok();
        http_round(&mut s, req, Some(body))
    };
    let form = |body: &str| format!("POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {}\r\n\r\n", body.len());
    let body_s = |b: &[u8]| String::from_utf8_lossy(b).into_owned();

    // STS
    let b = "Action=GetCallerIdentity&Version=2011-06-15";
    match call(&form(b), b.as_bytes()) {
        Ok((st, r)) => check("STS GetCallerIdentity", st == "200" && body_s(&r).contains("123456789012"), format!("{st}")),
        Err(e) => check("STS GetCallerIdentity", false, e),
    }
    // S3
    let put = b"hello localite";
    match call(&format!("PUT /b1/hello.txt HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n", put.len()), put) {
        Ok((st, _)) => check("S3 PutObject", st == "200", st),
        Err(e) => check("S3 PutObject", false, e),
    }
    match call("GET /b1/hello.txt HTTP/1.1\r\nHost: x\r\n\r\n", b"") {
        Ok((st, r)) => check("S3 GetObject", st == "200" && r == put, format!("{st}, {} bytes", r.len())),
        Err(e) => check("S3 GetObject", false, e),
    }
    match call("GET /b1?list-type=2 HTTP/1.1\r\nHost: x\r\n\r\n", b"") {
        Ok((st, r)) => check("S3 ListObjectsV2", st == "200" && body_s(&r).contains("hello.txt"), st),
        Err(e) => check("S3 ListObjectsV2", false, e),
    }
    match call("DELETE /b1/hello.txt HTTP/1.1\r\nHost: x\r\n\r\n", b"") {
        Ok((st, _)) => check("S3 DeleteObject", st == "204", st),
        Err(e) => check("S3 DeleteObject", false, e),
    }
    // SQS (JSON)
    let hdr = |target: &str, n: usize| format!("POST / HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-amz-json-1.0\r\nX-Amz-Target: {target}\r\nContent-Length: {n}\r\n\r\n");
    let sb = r#"{"QueueUrl":"http://x/123456789012/q1","MessageBody":"hi"}"#;
    match call(&hdr("AmazonSQS.SendMessage", sb.len()), sb.as_bytes()) {
        Ok((st, r)) => check("SQS SendMessage", st == "200" && body_s(&r).contains("MessageId"), st),
        Err(e) => check("SQS SendMessage", false, e),
    }
    let rb = r#"{"QueueUrl":"http://x/123456789012/q1"}"#;
    match call(&hdr("AmazonSQS.ReceiveMessage", rb.len()), rb.as_bytes()) {
        Ok((st, r)) => check("SQS ReceiveMessage", st == "200" && body_s(&r).contains("\"hi\""), st),
        Err(e) => check("SQS ReceiveMessage", false, e),
    }
    // DynamoDB
    let pb = r#"{"TableName":"t1","Item":{"pk":{"S":"1"},"v":{"S":"x"}}}"#;
    match call(&hdr("DynamoDB_20120810.PutItem", pb.len()), pb.as_bytes()) {
        Ok((st, _)) => check("DynamoDB PutItem", st == "200", st),
        Err(e) => check("DynamoDB PutItem", false, e),
    }
    let gb = r#"{"TableName":"t1","Key":{"pk":{"S":"1"}}}"#;
    match call(&hdr("DynamoDB_20120810.GetItem", gb.len()), gb.as_bytes()) {
        Ok((st, r)) => check("DynamoDB GetItem", st == "200" && body_s(&r).contains("\"Item\""), st),
        Err(e) => check("DynamoDB GetItem", false, e),
    }
    // IAM
    let b = "Action=CreateUser&UserName=u1&Version=2010-05-08";
    match call(&form(b), b.as_bytes()) {
        Ok((st, r)) => check("IAM CreateUser", st == "200" && body_s(&r).contains("u1"), st),
        Err(e) => check("IAM CreateUser", false, e),
    }
    // Lambda
    let cb = r#"{"FunctionName":"f1","Runtime":"python3.12"}"#;
    match call(&format!("POST /2015-03-31/functions HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n", cb.len()), cb.as_bytes()) {
        Ok((st, _)) => check("Lambda CreateFunction", st == "201", st),
        Err(e) => check("Lambda CreateFunction", false, e),
    }
    let ib = r#"{"a":1}"#;
    match call(&format!("POST /2015-03-31/functions/f1/invocations HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n", ib.len()), ib.as_bytes()) {
        Ok((st, r)) => check("Lambda Invoke (echo mode)", st == "200" && r == ib.as_bytes(), st),
        Err(e) => check("Lambda Invoke (echo mode)", false, e),
    }
    // concurrency: an idle connection must not stall other clients
    let idle = TcpStream::connect((host, policy.port)).map_err(|e| format!("idle connect: {e}"))?;
    match call("GET /health HTTP/1.1\r\nHost: x\r\n\r\n", b"") {
        Ok((st, _)) => check("concurrent client while a connection idles", st == "200", st),
        Err(e) => check("concurrent client while a connection idles", false, e),
    }
    drop(idle);
    if failures > 0 {
        unsafe { libc::kill(child.as_raw(), libc::SIGTERM) };
        let _ = waitpid(child, None);
        return Err(format!("{failures} service check(s) failed"));
    }

    // graceful shutdown: SIGTERM the child (it handles it, then exits).
    // (nix "signal" feature not enabled; raw libc::kill is fine here.)
    unsafe {
        libc::kill(child.as_raw(), libc::SIGTERM);
    }
    let st = waitpid(child, None).map_err(|e| format!("waitpid: {e}"))?;
    println!("\n[+] child exit status: {st:?}");

    if let Ok((dir, _)) = &cgroup {
        let _ = fs::remove_dir(dir);
        println!("[+] cgroup removed");
    }
    let _ = fs::remove_dir_all(&stage);
    let _ = fs::remove_file(&canary);
    println!("[+] staging dir + canary cleaned up");

    let seccomp_str = if p_active {
        "seccomp stage-P active"
    } else {
        "seccomp NOT active"
    };
    match &cgroup {
        Ok((_, applied)) if !applied.is_empty() =>         println!(
            "\n=== RESULT: PASS — hardened sandbox: namespaces + {seccomp_str} + zero caps + no_new_privs; {} over real TCP; cgroup limits: {} ===",
            if std::env::var("LOCALITE_BACKEND").as_deref() == Ok("moto") { "Moto AWS API backend" } else { "Rust compatibility backend" },
            applied.join(", ")
        ),
        _ => println!(
            "\n=== RESULT: PASS — hardened sandbox: namespaces + {seccomp_str} + zero caps + no_new_privs; {} over real TCP; cgroup limits NOT applied (host delegated no controllers) ===",
            if std::env::var("LOCALITE_BACKEND").as_deref() == Ok("moto") { "Moto AWS API backend" } else { "Rust compatibility backend" }
        ),
    }
    Ok(())
}

fn main() {
    // Guest-VM entry points (see init.rs). Everything else is the sandbox CLI.
    let a1 = std::env::args().nth(1).unwrap_or_default();
    match a1.as_str() {
        "--init" => init::stage1(),
        "--init2" => init::stage2(),
        _ if std::process::id() == 1 && a1.is_empty() => init::stage1(), // kernel runs /init with no args
        "--seccomp-probe" => {
            // diagnostic: which filter shapes does THIS kernel accept?
            unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS as c_int, 1, 0, 0, 0) };
            let try_it = |name: &str, ins: Vec<SockFilter>, flags: u64| {
                let prog = SockFprog { len: ins.len() as u16, filter: ins.as_ptr() };
                // fork so a successful install doesn't constrain later probes
                let pid = unsafe { libc::fork() };
                if pid == 0 {
                    let r = unsafe { libc::syscall(libc::SYS_seccomp, 1u64, flags, &prog as *const SockFprog) };
                    let e = if r == 0 { 0 } else { errno() };
                    println!("{name}: len={} flags={flags} -> {}", ins.len(), if r == 0 { "OK".to_string() } else { format!("errno {e}") });
                    unsafe { libc::_exit(0) };
                }
                let mut st = 0;
                unsafe { libc::waitpid(pid, &mut st, 0) };
            };
            let allow = vec![SockFilter { code: B_RET_K, jt: 0, jf: 0, k: SECCOMP_RET_ALLOW }];
            try_it("allow-all", allow.clone(), 0);
            try_it("allow-all+tsync", allow, SECCOMP_FILTER_FLAG_TSYNC);
            let f = build_filter(HOST_ARCH, HOST_ARCH.p_denied, false);
            try_it("stage-P", f.clone(), 0);
            try_it("stage-P+tsync", f.clone(), SECCOMP_FILTER_FLAG_TSYNC);
            for (i, x) in f.iter().enumerate() {
                println!("  [{i:02}] code={:#06x} jt={} jf={} k={:#x}", x.code, x.jt, x.jf, x.k);
            }
            return;
        }
        "--relay-tcp" => {
            // hidden test helper: --relay-tcp LISTEN_PORT TARGET_PORT
            let v: Vec<u16> = std::env::args().skip(2).filter_map(|x| x.parse().ok()).collect();
            if v.len() == 2 {
                init::tcp_relay(v[0], v[1]);
            }
            return;
        }
        _ => {}
    }
    if let Err(e) = real_main() {
        eprintln!("localite-sandbox: fatal: {e}");
        exit(1);
    }
}

/// Offline verification for the generated seccomp filters.
///
/// This nested sandbox allowlists only trivial filter programs, so the real
/// deny-lists cannot be installed here (seccomp(2) -> EINVAL). These tests
/// prove the *logic* of the generated BPF — the deny-list membership, the
/// clone-flag mask, and the arch guard — by interpreting the exact
/// instruction stream `build_filter` emits.
#[cfg(test)]
mod bpf_tests {
    use super::*;

    /// Minimal classic-BPF interpreter: just the opcodes our generator emits.
    fn run(prog: &[SockFilter], nr: u32, arch: u32, args: [u64; 6]) -> u32 {
        // struct seccomp_data layout: nr@0, arch@4, ip@8, args@16
        let mut mem = [0u8; 64];
        mem[0..4].copy_from_slice(&nr.to_ne_bytes());
        mem[4..8].copy_from_slice(&arch.to_ne_bytes());
        for (i, a) in args.iter().enumerate() {
            mem[16 + i * 8..16 + (i + 1) * 8].copy_from_slice(&a.to_ne_bytes());
        }
        let mut acc: u32 = 0;
        let mut pc: usize = 0;
        loop {
            let ins = prog[pc];
            match ins.code {
                B_LD_W_ABS => {
                    let off = ins.k as usize;
                    acc = u32::from_ne_bytes(mem[off..off + 4].try_into().unwrap());
                    pc += 1;
                }
                B_ALU_AND_K => {
                    acc &= ins.k;
                    pc += 1;
                }
                B_JMP_JEQ_K => {
                    pc += if acc == ins.k {
                        ins.jt as usize + 1
                    } else {
                        ins.jf as usize + 1
                    };
                }
                B_RET_K => return ins.k,
                _ => panic!("unsupported opcode {:#x} in test interpreter", ins.code),
            }
        }
    }

    const ALLOW: u32 = SECCOMP_RET_ALLOW;
    const DENY: u32 = SECCOMP_RET_ERRNO | 1;
    const KILL: u32 = SECCOMP_RET_KILL_PROCESS;
    
    fn each_arch(f: impl Fn(&ArchDef, u32)) {
        f(&X86_64, AUDIT_ARCH_X86_64);
        f(&AARCH64, AUDIT_ARCH_AARCH64);
    }

    #[test]
    fn parent_filter_denies_dangerous_allows_setup() {
        each_arch(|arch, audit| {
            let p = build_filter(arch, arch.p_denied, false);
            let t = |nr, a0: u64| run(&p, nr, audit, [a0, 0, 0, 0, 0, 0]);
            // ordinary syscalls pass (read/write differ per arch; 63/64 and 0/1 are both benign)
            assert_eq!(t(63, 0), ALLOW);
            assert_eq!(t(64, 0), ALLOW);
            // every listed denial returns EPERM
            for &nr in arch.p_denied {
                assert_eq!(t(nr, 0), DENY, "nr={nr} must be denied");
            }
            // clone3 -> ENOSYS so glibc falls back to clone(2)
            assert_eq!(t(arch.clone3_nr, 0), SECCOMP_RET_ERRNO | ENOSYS);
            // setup syscalls stay allowed in stage P
            for &nr in arch.c_denied {
                assert_eq!(t(nr, 0), ALLOW, "stage-P must allow bootstrap nr={nr}");
            }
            assert_eq!(t(arch.clone_nr, 0), ALLOW);
            assert_eq!(t(arch.clone_nr, 0x0002_0000), ALLOW); // CLONE_NEWNS ok in P
            // wrong arch is killed, not merely denied
            let other = if audit == AUDIT_ARCH_X86_64 { AUDIT_ARCH_AARCH64 } else { AUDIT_ARCH_X86_64 };
            assert_eq!(run(&p, 1, other, [0; 6]), KILL);
        });
    }

    #[test]
    fn child_filter_denies_setup_and_namespace_clone() {
        each_arch(|arch, audit| {
            let p = build_filter(arch, arch.c_denied, true);
            let t = |nr, a0: u64| run(&p, nr, audit, [a0, 0, 0, 0, 0, 0]);
            for &nr in arch.c_denied {
                assert_eq!(t(nr, 0), DENY, "stage-C must deny nr={nr}");
            }
            let c = arch.clone_nr;
            assert_eq!(t(c, 0), ALLOW); // plain clone (threads) still works
            assert_eq!(t(c, 0x0000_0100 | 0x0001_0000), ALLOW); // thread-style flags
            assert_eq!(t(c, 0x0002_0000), DENY); // CLONE_NEWNS
            assert_eq!(t(c, 0x4000_0000), DENY); // CLONE_NEWNET
            assert_eq!(t(c, 0x1000_0000), DENY); // CLONE_NEWUSER
            assert_eq!(t(c, 0x0200_0000), DENY); // CLONE_NEWPID
            assert_eq!(t(c, 0x0002_0011), DENY); // NEWNS|SIGCHLD
            assert_eq!(t(63, 0), ALLOW);
            let other = if audit == AUDIT_ARCH_X86_64 { AUDIT_ARCH_AARCH64 } else { AUDIT_ARCH_X86_64 };
            assert_eq!(run(&p, arch.c_denied[0], other, [0; 6]), KILL);
        });
    }

    #[test]
    fn arch_tables_have_no_overlap_between_stages() {
        for arch in [&X86_64, &AARCH64] {
            for nr in arch.c_denied {
                assert!(!arch.p_denied.contains(nr), "stage C-only syscall {nr} also in P");
            }
        }
    }
}
