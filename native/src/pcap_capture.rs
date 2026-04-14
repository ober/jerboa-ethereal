//! pcap_capture.rs — Live packet capture FFI
//!
//! On Linux: uses rscap (AF_PACKET sockets).
//! On macOS: bypasses rscap entirely and drives /dev/bpf directly.
//!
//! Reason for macOS bypass:
//!  - rscap's Sniffer::new() calls BIOCSETIF (bind) before we can call BIOCSBLEN.
//!    macOS rejects BIOCSBLEN after bind, leaving bd_bufsize at the kernel default.
//!    read() on a BPF fd requires a buffer >= bd_bufsize; if we don't know that size
//!    we can't satisfy the requirement reliably.
//!  - rscap's recv() uses readv() with a tiny first iovec; macOS BPF requires a
//!    single contiguous read buffer.
//!  - rscap parses bpf_xhdr (FreeBSD); macOS returns bpf_hdr (timeval32, 20 bytes).
//!
//! By opening /dev/bpf ourselves we can call BIOCSBLEN before BIOCSETIF, then
//! use plain read() into a correctly-sized buffer.

use crate::panic::set_last_error;
use std::time::{SystemTime, UNIX_EPOCH};

// ── macOS: full BPF implementation ───────────────────────────────────────────

#[cfg(target_os = "macos")]
mod bpf {
    use std::cell::RefCell;
    use std::io;

    // ioctl numbers from <net/bpf.h>
    const BIOCGBLEN: libc::c_ulong    = 0x40044266; // get buffer length
    const BIOCSBLEN: libc::c_ulong    = 0xc0044266; // set buffer length (BEFORE bind)
    const BIOCSETF: libc::c_ulong     = 0x80104267; // set filter (resets buffer)
    const BIOCSETIF: libc::c_ulong    = 0x8020426c; // bind to interface
    const BIOCIMMEDIATE: libc::c_ulong = 0x80044270; // immediate delivery mode

    // Requested BPF buffer size (kernel may round up/down).
    const WANT_BUFSIZE: libc::c_uint = 65536;

    // struct bpf_program on macOS arm64:
    //   bf_len (u32) + _pad (u32) + bf_insns* (8 bytes) = 16 bytes
    #[repr(C)]
    struct BpfProgram {
        bf_len: u32,
        _pad: u32,
        bf_insns: *mut BpfInsn,
    }

    // struct bpf_insn: code(2) + jt(1) + jf(1) + k(4) = 8 bytes
    #[repr(C)]
    struct BpfInsn {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    // macOS userspace bpf_hdr uses timeval32 (two i32s), not full timeval.
    // The C struct is 20 bytes (sizeof includes trailing pad), but the kernel
    // writes bh_hdrlen=18 — the actual data fields without trailing padding:
    //   tv_sec(4) + tv_usec(4) + caplen(4) + datalen(4) + hdrlen(2) = 18 bytes
    // We need at least 18 bytes to safely read all fields.
    const BPF_HDR_LEN: usize = 18;

    // Per-thread read buffer, sized to bd_bufsize after open.
    thread_local! {
        static READ_BUF: RefCell<Vec<u8>> = RefCell::new(Vec::new());
    }

    pub struct Capture {
        fd: libc::c_int,
        pub bufsize: usize,
    }

    impl Capture {
        /// Open a live capture on `iface`, bypassing rscap.
        pub fn open(iface: &str) -> io::Result<Self> {
            // 1. Open first available /dev/bpf device.
            let fd = Self::open_bpf()?;

            // 2. BIOCSBLEN — MUST come before BIOCSETIF on macOS.
            let mut want: libc::c_uint = WANT_BUFSIZE;
            unsafe { libc::ioctl(fd, BIOCSBLEN, &mut want) };

            // 3. Read back the actual buffer size the kernel granted.
            let mut bufsize: libc::c_uint = 0;
            unsafe { libc::ioctl(fd, BIOCGBLEN, &mut bufsize) };
            let bufsize = bufsize as usize;

            // 4. BIOCSETIF — bind to the network interface.
            let mut ifreq = Self::make_ifreq(iface);
            let rc = unsafe { libc::ioctl(fd, BIOCSETIF, &mut ifreq) };
            if rc < 0 {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }

            // 5. BIOCSETF — accept-all filter (single RET K=0xffffffff).
            let mut insn = BpfInsn { code: 0x0006, jt: 0, jf: 0, k: 0xffff_ffff };
            let mut prog = BpfProgram { bf_len: 1, _pad: 0, bf_insns: &mut insn };
            let rc = unsafe {
                libc::ioctl(fd, BIOCSETF, &mut prog as *mut BpfProgram as *mut libc::c_void)
            };
            if rc < 0 {
                unsafe { libc::close(fd) };
                return Err(io::Error::last_os_error());
            }

            // 6. BIOCIMMEDIATE — return each packet immediately, don't buffer.
            let mut imm: libc::c_uint = 1;
            unsafe { libc::ioctl(fd, BIOCIMMEDIATE, &mut imm) };

            // Pre-size the thread-local read buffer.
            READ_BUF.with(|cell| {
                let mut buf = cell.borrow_mut();
                if buf.len() < bufsize {
                    buf.resize(bufsize, 0);
                }
            });

            Ok(Capture { fd, bufsize })
        }

        /// Block until one packet arrives; copy it into `out`. Returns bytes written.
        pub fn recv(&self, out: &mut [u8]) -> io::Result<usize> {
            READ_BUF.with(|cell| {
                let mut buf = cell.borrow_mut();

                // Ensure buffer is large enough (it was sized at open time, but be safe).
                if buf.len() < self.bufsize {
                    buf.resize(self.bufsize, 0);
                }

                // Single contiguous read — macOS BPF requires buffer >= bd_bufsize.
                let n = unsafe {
                    libc::read(
                        self.fd,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        self.bufsize,
                    )
                };
                if n < 0 {
                    return Err(io::Error::last_os_error());
                }
                let n = n as usize;

                if n < BPF_HDR_LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "BPF read returned fewer bytes than bpf_hdr",
                    ));
                }

                // bpf_hdr layout (userspace / timeval32):
                //   [0..4]  tv_sec  (i32)
                //   [4..8]  tv_usec (i32)
                //   [8..12] bh_caplen (u32)   ← packet bytes captured
                //   [12..16] bh_datalen (u32) ← original packet length
                //   [16..18] bh_hdrlen (u16)  ← total header length (incl. alignment)
                let caplen = u32::from_ne_bytes(buf[8..12].try_into().unwrap()) as usize;
                let hdrlen = u16::from_ne_bytes(buf[16..18].try_into().unwrap()) as usize;

                if hdrlen < BPF_HDR_LEN || hdrlen + caplen > n {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("BPF header/caplen out of range: hdrlen={hdrlen} caplen={caplen} n={n}"),
                    ));
                }

                let copy_len = caplen.min(out.len());
                out[..copy_len].copy_from_slice(&buf[hdrlen..hdrlen + copy_len]);
                Ok(copy_len)
            })
        }

        // ── helpers ──────────────────────────────────────────────────────────

        fn open_bpf() -> io::Result<libc::c_int> {
            // Try /dev/bpf first, then /dev/bpf1 .. /dev/bpf99.
            // Skip /dev/bpf0 — some tools hardcode it.
            let paths: Vec<String> = std::iter::once("/dev/bpf".to_string())
                .chain((1..100).map(|i| format!("/dev/bpf{}", i)))
                .collect();

            for path in &paths {
                let cpath = std::ffi::CString::new(path.as_str()).unwrap();
                let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR) };
                if fd >= 0 {
                    return Ok(fd);
                }
                let e = io::Error::last_os_error();
                if e.raw_os_error() != Some(libc::EBUSY)
                    && e.raw_os_error() != Some(libc::ENOENT)
                {
                    return Err(e);
                }
            }
            Err(io::Error::new(io::ErrorKind::NotFound, "no /dev/bpf device available"))
        }

        fn make_ifreq(iface: &str) -> libc::ifreq {
            let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
            let name_bytes = iface.as_bytes();
            let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
            for (i, &b) in name_bytes[..copy_len].iter().enumerate() {
                req.ifr_name[i] = b as libc::c_char;
            }
            req
        }
    }

    impl Drop for Capture {
        fn drop(&mut self) {
            unsafe { libc::close(self.fd) };
        }
    }
}

// ── Handle type (platform-specific) ──────────────────────────────────────────

#[cfg(target_os = "macos")]
type CaptureHandle = bpf::Capture;

#[cfg(not(target_os = "macos"))]
type CaptureHandle = rscap::Sniffer;

// ── Open ──────────────────────────────────────────────────────────────────────

/// Open and activate a live capture on the named interface.
/// Returns a handle (i64 > 0) on success, or -1 on error.
#[no_mangle]
pub extern "C" fn jerboa_pcap_open(iface_ptr: *const u8, iface_len: usize) -> i64 {
    if iface_ptr.is_null() {
        set_last_error("null interface pointer".to_string());
        return -1;
    }
    let iface_str = unsafe {
        match std::str::from_utf8(std::slice::from_raw_parts(iface_ptr, iface_len)) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(format!("invalid UTF-8 in interface name: {e}"));
                return -1;
            }
        }
    };

    #[cfg(target_os = "macos")]
    let result = bpf::Capture::open(iface_str);

    #[cfg(not(target_os = "macos"))]
    let result = {
        use rscap::{Interface, Sniffer};
        Interface::new(iface_str)
            .map_err(|e| std::io::Error::other(format!("invalid interface '{iface_str}': {e}")))
            .and_then(|iface| Sniffer::new(iface))
            .and_then(|mut s| s.activate(None).map(|_| s))
    };

    match result {
        Ok(handle) => Box::into_raw(Box::new(handle)) as i64,
        Err(e) => {
            set_last_error(format!("pcap_open: {e}"));
            -1
        }
    }
}

// ── Next packet ───────────────────────────────────────────────────────────────

/// Receive the next packet into buf[0..buf_len].
/// Writes arrival timestamp into *ts_sec_out / *ts_usec_out (if non-null).
/// Returns bytes written on success, -1 on error.
#[no_mangle]
pub extern "C" fn jerboa_pcap_next(
    handle: i64,
    buf: *mut u8,
    buf_len: usize,
    ts_sec_out: *mut u64,
    ts_usec_out: *mut u64,
) -> i32 {
    if handle <= 0 {
        set_last_error("invalid handle".to_string());
        return -1;
    }
    if buf.is_null() || buf_len == 0 {
        set_last_error("null/empty output buffer".to_string());
        return -1;
    }
    let cap = unsafe { &mut *(handle as *mut CaptureHandle) };
    let out = unsafe { std::slice::from_raw_parts_mut(buf, buf_len) };

    match cap.recv(out) {
        Ok(n) => {
            let dur = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default();
            if !ts_sec_out.is_null() {
                unsafe { *ts_sec_out = dur.as_secs() };
            }
            if !ts_usec_out.is_null() {
                unsafe { *ts_usec_out = dur.subsec_micros() as u64 };
            }
            n as i32
        }
        Err(e) => {
            set_last_error(format!("pcap_next: {e}"));
            -1
        }
    }
}

// ── Close ─────────────────────────────────────────────────────────────────────

/// Close and free a capture handle.
#[no_mangle]
pub extern "C" fn jerboa_pcap_close(handle: i64) -> i32 {
    if handle <= 0 {
        return -1;
    }
    let _ = unsafe { Box::from_raw(handle as *mut CaptureHandle) };
    0
}

// ── List interfaces ───────────────────────────────────────────────────────────

/// Write a newline-separated list of interface names into buf (NUL-terminated).
/// Returns bytes written (excluding NUL), or -1 on error.
#[no_mangle]
pub extern "C" fn jerboa_pcap_list_interfaces(buf: *mut u8, buf_len: usize) -> i32 {
    if buf.is_null() || buf_len == 0 {
        set_last_error("null/empty buffer for interface list".to_string());
        return -1;
    }
    match collect_interfaces() {
        Ok(names) => {
            let joined = names.join("\n");
            let bytes = joined.as_bytes();
            let copy_len = bytes.len().min(buf_len.saturating_sub(1));
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, copy_len);
                *buf.add(copy_len) = 0;
            }
            copy_len as i32
        }
        Err(e) => {
            set_last_error(format!("list_interfaces: {e}"));
            -1
        }
    }
}

// ── Interface enumeration ─────────────────────────────────────────────────────

#[cfg(unix)]
fn collect_interfaces() -> Result<Vec<String>, String> {
    use libc::{freeifaddrs, getifaddrs, ifaddrs};
    use std::ffi::CStr;

    let mut names: Vec<String> = Vec::new();
    let mut ifap: *mut ifaddrs = std::ptr::null_mut();

    if unsafe { getifaddrs(&mut ifap) } != 0 {
        return Err("getifaddrs failed".to_string());
    }

    let mut cursor = ifap;
    while !cursor.is_null() {
        let ifa = unsafe { &*cursor };
        if !ifa.ifa_name.is_null() {
            let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
                .to_string_lossy()
                .into_owned();
            if !names.contains(&name) {
                names.push(name);
            }
        }
        cursor = ifa.ifa_next;
    }

    unsafe { freeifaddrs(ifap) };
    Ok(names)
}

#[cfg(not(unix))]
fn collect_interfaces() -> Result<Vec<String>, String> {
    Err("interface enumeration not supported on this platform".to_string())
}
