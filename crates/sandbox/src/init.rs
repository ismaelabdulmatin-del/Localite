//! Guest-side PID 1 for the Localite VM (macOS app) plus a vsock<->TCP bridge.
//!
//! Boot flow (kernel -> initramfs containing only this binary as /init):
//!   stage 1  `/init`              — we are on the initramfs `rootfs`, which
//!            cannot be pivot_root()ed away; so (like busybox switch_root) we
//!            mount a tmpfs, copy ourselves in, MS_MOVE it over `/`, chroot,
//!            and re-exec as stage 2. This makes `/` a real mount so the
//!            sandbox's own pivot_root works.
//!   stage 2  `/init --init2`      — mount proc/sys/dev/cgroup2/tmp, bring up
//!            loopback, spawn `localite-sandbox --daemon` (the namespaced,
//!            seccomp'd, cap-dropped emulator on guest 127.0.0.1:4566), bridge
//!            vsock port 4566 <-> that TCP port, reap children, power off when
//!            the sandbox exits.
//!
//! All of this is Linux-only and meant to run as real root inside the VM.

use libc::{c_int, c_void};
use nix::mount::{mount, MsFlags};
use std::ffi::CString;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::FromRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;

pub const SERVICE_PORT: u16 = 4566;

fn log(msg: &str) {
    // never panic if the console is missing: a dead PID 1 is a kernel panic
    let mut o = std::io::stdout();
    let _ = writeln!(o, "[init] {msg}");
    let _ = o.flush();
}

fn m(src: &str, dst: &str, fstype: &str, flags: MsFlags, data: Option<&str>) {
    let _ = fs::create_dir_all(dst);
    match mount(Some(src), dst, Some(fstype), flags, data) {
        Ok(()) => log(&format!("mounted {fstype} on {dst}")),
        Err(e) => log(&format!("mount {fstype} on {dst}: {e} (continuing)")),
    }
}

/// Stage 1: escape the initramfs `rootfs` so pivot_root works later.
pub fn stage1() -> ! {
    log("localite guest init (stage 1)");
    let _ = fs::create_dir_all("/newroot");
    if let Err(e) = mount(
        Some("tmpfs"),
        "/newroot",
        Some("tmpfs"),
        MsFlags::empty(),
        Some("size=128M,mode=755"),
    ) {
        log(&format!("FATAL: tmpfs /newroot: {e}"));
        poweroff();
    }
    if let Err(e) = fs::copy("/init", "/newroot/init") {
        log(&format!("FATAL: copy /init: {e}"));
        poweroff();
    }
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions("/newroot/init", fs::Permissions::from_mode(0o755));
    }
    for d in ["proc", "sys", "dev", "tmp", "run"] {
        let _ = fs::create_dir_all(format!("/newroot/{d}"));
    }
    if let Err(e) = fs::create_dir_all("/newroot/moto-rootfs") {
        log(&format!("FATAL: mkdir Moto rootfs mountpoint: {e}"));
        poweroff();
    }
    if let Err(e) = mount(
        Some("/moto-rootfs"),
        "/newroot/moto-rootfs",
        None::<&str>,
        MsFlags::MS_BIND | MsFlags::MS_REC,
        None::<&str>,
    ) {
        log(&format!("FATAL: preserve Moto rootfs across switch_root: {e}"));
        poweroff();
    }
    unsafe {
        let nr = CString::new("/newroot").unwrap();
        let dot = CString::new(".").unwrap();
        let root = CString::new("/").unwrap();
        if libc::chdir(nr.as_ptr()) != 0
            || libc::mount(dot.as_ptr(), root.as_ptr(), std::ptr::null(), libc::MS_MOVE, std::ptr::null()) != 0
            || libc::chroot(dot.as_ptr()) != 0
            || libc::chdir(root.as_ptr()) != 0
        {
            log(&format!("FATAL: switch_root: errno {}", *libc::__errno_location()));
            poweroff();
        }
    }
    let err = Command::new("/init").arg("--init2").exec();
    log(&format!("FATAL: re-exec: {err}"));
    poweroff()
}

fn lo_up() {
    unsafe {
        let s = libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0);
        if s < 0 {
            return;
        }
        let mut ifr: libc::ifreq = std::mem::zeroed();
        for (i, b) in b"lo\0".iter().enumerate() {
            ifr.ifr_name[i] = *b as libc::c_char;
        }
        if libc::ioctl(s, libc::SIOCGIFFLAGS as _, &mut ifr) == 0 {
            ifr.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            if libc::ioctl(s, libc::SIOCSIFFLAGS as _, &ifr) == 0 {
                log("loopback up");
            }
        }
        libc::close(s);
    }
}

pub fn poweroff() -> ! {
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_POWER_OFF);
    }
    loop {
        std::thread::sleep(std::time::Duration::from_secs(3600));
    }
}

/// Copy bytes both ways between two connected sockets until either closes.
fn pump<A, B>(mut a: A, mut b: B)
where
    A: Read + Write + Send + 'static,
    B: Read + Write + Send + 'static,
    A: TryCloneRw<Out = A>,
    B: TryCloneRw<Out = B>,
{
    let (mut a2, mut b2) = match (a.try_clone_rw(), b.try_clone_rw()) {
        (Some(x), Some(y)) => (x, y),
        _ => return,
    };
    let t = std::thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match a.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if b.write_all(&buf[..n]).is_err() {
                        break;
                    }
                }
            }
        }
        let _ = b.flush();
        b.half_close();
    });
    let mut buf = [0u8; 16 * 1024];
    loop {
        match b2.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                if a2.write_all(&buf[..n]).is_err() {
                    break;
                }
            }
        }
    }
    a2.half_close();
    let _ = t.join();
}

pub trait TryCloneRw: Sized {
    type Out;
    fn try_clone_rw(&self) -> Option<Self::Out>;
    /// Send FIN on the write side so the peer sees EOF.
    fn half_close(&self);
}
impl TryCloneRw for TcpStream {
    type Out = TcpStream;
    fn try_clone_rw(&self) -> Option<TcpStream> {
        self.try_clone().ok()
    }
    fn half_close(&self) {
        let _ = self.shutdown(std::net::Shutdown::Write);
    }
}
/// A connected stream socket fd (vsock or unix) usable as Read+Write.
pub struct FdStream(pub std::fs::File);
impl Read for FdStream {
    fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(b)
    }
}
impl Write for FdStream {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.write(b)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
impl TryCloneRw for FdStream {
    type Out = FdStream;
    fn try_clone_rw(&self) -> Option<FdStream> {
        self.0.try_clone().ok().map(FdStream)
    }
    fn half_close(&self) {
        use std::os::fd::AsRawFd;
        unsafe {
            libc::shutdown(self.0.as_raw_fd(), libc::SHUT_WR);
        }
    }
}

/// Listen on AF_VSOCK `port` (any CID) and relay each connection to
/// 127.0.0.1:`target`. Blocks forever.
pub fn vsock_bridge(port: u32, target: u16) {
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
        if fd < 0 {
            log(&format!("vsock socket failed: errno {} (no vsock in this kernel?)", *libc::__errno_location()));
            return;
        }
        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_port = port;
        addr.svm_cid = libc::VMADDR_CID_ANY;
        if libc::bind(fd, &addr as *const _ as *const libc::sockaddr, std::mem::size_of::<libc::sockaddr_vm>() as u32) != 0
            || libc::listen(fd, 128) != 0
        {
            log(&format!("vsock bind/listen failed: errno {}", *libc::__errno_location()));
            return;
        }
        log(&format!("vsock bridge: vsock:{port} -> 127.0.0.1:{target}"));
        loop {
            let c = libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut());
            if c < 0 {
                std::thread::sleep(std::time::Duration::from_millis(50));
                continue;
            }
            let conn = FdStream(std::fs::File::from_raw_fd(c));
            std::thread::spawn(move || match TcpStream::connect(("127.0.0.1", target)) {
                Ok(t) => {
                    t.set_nodelay(true).ok();
                    pump(conn, t)
                }
                Err(_) => {}
            });
        }
    }
}

/// Test helper: relay TCP `listen_port` -> 127.0.0.1:`target` (same pump code
/// path as the vsock bridge, so it can be exercised without a VM).
pub fn tcp_relay(listen_port: u16, target: u16) {
    let l = TcpListener::bind(("127.0.0.1", listen_port)).expect("relay bind");
    for c in l.incoming().flatten() {
        std::thread::spawn(move || {
            if let Ok(t) = TcpStream::connect(("127.0.0.1", target)) {
                pump(c, t);
            }
        });
    }
}

/// Stage 2: real PID 1.
pub fn stage2() -> ! {
    log("localite guest init (stage 2)");
    m("proc", "/proc", "proc", MsFlags::empty(), None);
    m("sysfs", "/sys", "sysfs", MsFlags::empty(), None);
    m("devtmpfs", "/dev", "devtmpfs", MsFlags::empty(), Some("mode=755"));
    m("tmpfs", "/tmp", "tmpfs", MsFlags::empty(), Some("size=64M,mode=1777"));
    m("cgroup2", "/sys/fs/cgroup", "cgroup2", MsFlags::empty(), None);
    let workspace = fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let mut workspace_mounted = false;
    let workspace_source = if workspace.contains("localite.workspace=private") {
        Some(("localite-private", "private project copy"))
    } else if workspace.contains("localite.workspace=shared") {
        Some(("localite-shared", "explicitly shared host folder"))
    } else {
        None
    };
    if let Some((tag, description)) = workspace_source {
        let _ = fs::create_dir_all("/workspace");
        match mount(
            Some(tag),
            "/workspace",
            Some("virtiofs"),
            MsFlags::MS_NODEV | MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
            None::<&str>,
        ) {
            Ok(()) => {
                workspace_mounted = true;
                log(&format!("{description} mounted at /workspace"));
            }
            Err(e) => {
                log(&format!("FATAL: {description} mount failed: {e}"));
                poweroff();
            }
        }
    }
    unsafe {
        let h = b"localite";
        libc::sethostname(h.as_ptr() as *const libc::c_char, h.len());
    }
    lo_up();

    // report the kernel features the sandbox relies on
    let ver = fs::read_to_string("/proc/version").unwrap_or_default();
    log(&format!("kernel: {}", ver.trim()));
    log(&format!(
        "cgroup controllers: {}",
        fs::read_to_string("/sys/fs/cgroup/cgroup.controllers").unwrap_or_else(|_| "unavailable".into()).trim()
    ));

    // `localite.selftest` on the kernel cmdline: run the sandbox self-test
    // (no --daemon) and power off; used to verify the guest end-to-end.
    let selftest = fs::read_to_string("/proc/cmdline").unwrap_or_default().contains("localite.selftest");
    let port = SERVICE_PORT.to_string();
    let probe = fs::read_to_string("/proc/cmdline").unwrap_or_default().contains("localite.probe");
    let args: Vec<&str> = if probe {
        vec!["--seccomp-probe"]
    } else if selftest {
        vec!["--port", &port]
    } else {
        vec!["--daemon", "--listen", "127.0.0.1", "--port", &port]
    };
    let mut command = Command::new("/init");
    command.args(&args);
    if workspace_mounted {
        command.env("LOCALITE_WORKSPACE", "1");
    }
    if !selftest && !probe {
        command.env("LOCALITE_BACKEND", "moto");
    }
    let mut child = match command.spawn() {
        Ok(c) => c,
        Err(e) => {
            log(&format!("FATAL: spawn sandbox: {e}"));
            poweroff();
        }
    };
    log(&format!("sandbox daemon started (pid {})", child.id()));
    std::thread::spawn(|| vsock_bridge(SERVICE_PORT as u32, SERVICE_PORT));

    // PID 1 duties: reap orphans; power off when the sandbox exits.
    loop {
        let mut status: c_int = 0;
        let pid = unsafe { libc::waitpid(-1, &mut status as *mut c_int, 0) };
        if pid == child.id() as i32 {
            log(&format!("sandbox exited (status {status}); powering off"));
            poweroff();
        }
        if pid < 0 {
            let e = unsafe { *libc::__errno_location() };
            if e != libc::EINTR {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
        let _ = (&mut child, 0 as *const c_void);
    }
}
