//! pcap_capture.rs — Live packet capture FFI via rscap
//!
//! Provides:
//!   jerboa_pcap_open(iface, iface_len) -> i64    // returns handle or -1
//!   jerboa_pcap_next(handle, buf, buf_len, ts_sec_out, ts_usec_out) -> i32  // bytes read or -1
//!   jerboa_pcap_close(handle) -> i32
//!   jerboa_pcap_list_interfaces(buf, buf_len) -> i32  // bytes written or -1
//!
//! The handle is a Box<rscap::Sniffer> cast to i64 (raw pointer).
//! Scheme is responsible for calling jerboa_pcap_close exactly once per handle.

use crate::panic::set_last_error;
use rscap::{Interface, Sniffer};
use std::time::{SystemTime, UNIX_EPOCH};

// ── macOS BPF capture ────────────────────────────────────────────────────────
//
// rscap has two macOS bugs we work around here:
//
//  1. activate() calls BIOCSETFNR which returns EINVAL on this macOS version.
//     Fix: use BIOCSETF (the buffer-resetting variant) instead.
//
//  2. recv() uses readv() with a small first iovec (sizeof bpf_xhdr = 32 bytes).
//     macOS BPF requires a single contiguous read buffer >= the BPF buffer size;
//     a multi-iovec readv whose first element is tiny returns EINVAL.
//     Additionally, macOS userspace uses bpf_hdr (with timeval32, 20 bytes) not
//     bpf_xhdr (FreeBSD-only, 32 bytes), so rscap misparses the header anyway.
//     Fix: use plain read() into a single 65536-byte buffer, then parse bpf_hdr.

#[cfg(target_os = "macos")]
mod macos_bpf {
    use std::cell::RefCell;
    use std::io;
    use std::os::fd::AsRawFd;

    // ioctl numbers from <net/bpf.h>
    const BIOCSETF: libc::c_ulong = 0x80104267;     // set filter (resets buffer)
    const BIOCSBLEN: libc::c_ulong = 0xc0044266;    // set buffer length
    const BIOCIMMEDIATE: libc::c_ulong = 0x80044270; // immediate mode

    // BPF buffer size we request — must be >= what the kernel will return.
    const BPF_BUF_SIZE: usize = 65536;

    // struct bpf_program layout on macOS arm64:
    //   bf_len (u32, 4 bytes) + _pad (u32, 4 bytes) + bf_insns* (8 bytes)
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

    // macOS userspace bpf_hdr uses timeval32 (two i32s), not the full timeval.
    // Layout (20 bytes total):
    //   offset  0: tv_sec  (i32)
    //   offset  4: tv_usec (i32)
    //   offset  8: bh_caplen  (u32)
    //   offset 12: bh_datalen (u32)
    //   offset 16: bh_hdrlen  (u16)
    //   offset 18: _pad       (u16)
    const BPF_HDR_LEN: usize = 20;

    // Per-thread read buffer — avoids a heap alloc on every recv call.
    thread_local! {
        static BPF_READ_BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; BPF_BUF_SIZE]);
    }

    /// Set accept-all filter, configure buffer size, and enable immediate mode.
    pub fn activate(sniffer: &rscap::Sniffer) -> io::Result<()> {
        let fd = sniffer.as_raw_fd();

        // Set BPF buffer to BPF_BUF_SIZE so our read buffer is always sufficient.
        let mut buflen: libc::c_uint = BPF_BUF_SIZE as libc::c_uint;
        unsafe { libc::ioctl(fd, BIOCSBLEN, &mut buflen as *mut libc::c_uint) };

        // BPF accept-all program: single RET K=0xffffffff instruction.
        let mut insn = BpfInsn { code: 0x0006, jt: 0, jf: 0, k: 0xffff_ffff };
        let mut prog = BpfProgram { bf_len: 1, _pad: 0, bf_insns: &mut insn };

        let rc = unsafe {
            libc::ioctl(fd, BIOCSETF, &mut prog as *mut BpfProgram as *mut libc::c_void)
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }

        // Immediate mode: deliver each packet to userspace right away.
        let mut imm: libc::c_uint = 1;
        unsafe { libc::ioctl(fd, BIOCIMMEDIATE, &mut imm as *mut libc::c_uint) };

        Ok(())
    }

    /// Receive one packet from the BPF fd using plain read() + bpf_hdr parsing.
    ///
    /// Bypasses rscap's recv() which uses readv() — incompatible with macOS BPF.
    pub fn recv(sniffer: &rscap::Sniffer, out: &mut [u8]) -> io::Result<usize> {
        let fd = sniffer.as_raw_fd();

        BPF_READ_BUF.with(|cell| {
            let mut buf = cell.borrow_mut();

            // Single contiguous read — macOS BPF requires this.
            let n = unsafe {
                libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len())
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

            // Parse bpf_hdr fields directly from the buffer bytes.
            let caplen  = u32::from_ne_bytes(buf[8..12].try_into().unwrap()) as usize;
            let hdrlen  = u16::from_ne_bytes(buf[16..18].try_into().unwrap()) as usize;

            // Sanity check: hdrlen must be at least BPF_HDR_LEN and within buffer.
            if hdrlen < BPF_HDR_LEN || hdrlen + caplen > n {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "BPF header/caplen out of range",
                ));
            }

            let copy_len = caplen.min(out.len());
            out[..copy_len].copy_from_slice(&buf[hdrlen..hdrlen + copy_len]);
            Ok(copy_len)
        })
    }
}

// ── Open ──────────────────────────────────────────────────────────────────────

/// Open and activate a live capture on the named interface.
/// Returns a handle (i64 > 0) on success, or -1 on error (check jerboa_last_error).
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
    let iface = match Interface::new(iface_str) {
        Ok(i) => i,
        Err(e) => {
            set_last_error(format!("pcap_open: invalid interface '{iface_str}': {e}"));
            return -1;
        }
    };
    let sniffer = match Sniffer::new(iface) {
        Ok(s) => s,
        Err(e) => {
            set_last_error(format!("pcap_open: Sniffer::new failed: {e}"));
            return -1;
        }
    };

    // Activate: set accept-all filter and begin capturing
    #[cfg(target_os = "macos")]
    let activate_result = macos_bpf::activate(&sniffer);
    #[cfg(not(target_os = "macos"))]
    let activate_result = sniffer.activate(None);

    if let Err(e) = activate_result {
        set_last_error(format!("pcap_open: activate failed: {e}"));
        return -1;
    }

    Box::into_raw(Box::new(sniffer)) as i64
}

// ── Next packet ───────────────────────────────────────────────────────────────

/// Receive the next packet into buf[0..buf_len].
/// Writes arrival timestamp seconds  into *ts_sec_out  (if non-null).
/// Writes arrival timestamp microseconds into *ts_usec_out (if non-null).
/// Returns the number of bytes written on success, -1 on error.
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
    // Safety: handle was produced by Box::into_raw in jerboa_pcap_open
    let sniffer = unsafe { &mut *(handle as *mut Sniffer) };
    let out = unsafe { std::slice::from_raw_parts_mut(buf, buf_len) };

    #[cfg(target_os = "macos")]
    let recv_result = macos_bpf::recv(sniffer, out);
    #[cfg(not(target_os = "macos"))]
    let recv_result = sniffer.recv(out);

    match recv_result {
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
    // Safety: handle was produced by Box::into_raw in jerboa_pcap_open
    let _ = unsafe { Box::from_raw(handle as *mut Sniffer) };
    0
}

// ── List interfaces ───────────────────────────────────────────────────────────

/// Write a newline-separated list of network interface names into buf (NUL-terminated).
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
