;; packet-netlink-sock_diag.c
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/netlink-sock-diag.ss
;; Auto-generated from wireshark/epan/dissectors/packet-netlink_sock_diag.c

(import (jerboa prelude))

;; ── Protocol Helpers ─────────────────────────────────────────────────
(def (read-u8 buf offset)
  (if (>= offset (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u8-ref buf offset))))

(def (read-u16be buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u16-ref buf offset (endianness big)))))

(def (read-u24be buf offset)
  (if (> (+ offset 3) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (+ (* (bytevector-u8-ref buf offset) 65536)
             (* (bytevector-u8-ref buf (+ offset 1)) 256)
             (bytevector-u8-ref buf (+ offset 2))))))

(def (read-u32be buf offset)
  (if (> (+ offset 4) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u32-ref buf offset (endianness big)))))

(def (read-u16le buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u16-ref buf offset (endianness little)))))

(def (read-u32le buf offset)
  (if (> (+ offset 4) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u32-ref buf offset (endianness little)))))

(def (read-u64be buf offset)
  (if (> (+ offset 8) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u64-ref buf offset (endianness big)))))

(def (read-u64le buf offset)
  (if (> (+ offset 8) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u64-ref buf offset (endianness little)))))

(def (slice buf offset len)
  (if (> (+ offset len) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (let ((result (make-bytevector len)))
            (bytevector-copy! buf offset result 0 len)
            result))))

(def (extract-bits val mask shift)
  (bitwise-arithmetic-shift-right (bitwise-and val mask) shift))

(def (fmt-ipv4 addr)
  (let ((b0 (bitwise-arithmetic-shift-right addr 24))
        (b1 (bitwise-and (bitwise-arithmetic-shift-right addr 16) 255))
        (b2 (bitwise-and (bitwise-arithmetic-shift-right addr 8) 255))
        (b3 (bitwise-and addr 255)))
    (str b0 "." b1 "." b2 "." b3)))

(def (fmt-mac bytes)
  (string-join
    (map (lambda (b) (string-pad (number->string b 16) 2 #\0))
         (bytevector->list bytes))
    ":"))

(def (fmt-hex val)
  (str "0x" (number->string val 16)))

(def (fmt-oct val)
  (str "0" (number->string val 8)))

(def (fmt-port port)
  (number->string port))

(def (fmt-bytes bv)
  (string-join
    (map (lambda (b) (string-pad (number->string b 16) 2 #\0))
         (bytevector->list bv))
    " "))

(def (fmt-ipv6-address bytes)
  (let loop ((i 0) (parts '()))
    (if (>= i 16)
        (string-join (reverse parts) ":")
        (loop (+ i 2)
              (cons (let ((w (+ (* (bytevector-u8-ref bytes i) 256)
                                (bytevector-u8-ref bytes (+ i 1)))))
                      (number->string w 16))
                    parts)))))

;; ── Dissector ──────────────────────────────────────────────────────
(def (dissect-netlink-sock-diag buffer)
  "Linux netlink sock diag protocol"
  (try
    (let* (
           (sock-diag-unix-name (unwrap (slice buffer 4 1)))
           (sock-diag-unix-peer-inode (unwrap (read-u32be buffer 4)))
           (sock-diag-unix-show (unwrap (read-u32be buffer 20)))
           (sock-diag-unix-show-name (unwrap (read-u8 buffer 20)))
           (sock-diag-unix-show-vfs (unwrap (read-u8 buffer 20)))
           (sock-diag-unix-show-peer (unwrap (read-u8 buffer 20)))
           (sock-diag-unix-show-icons (unwrap (read-u8 buffer 20)))
           (sock-diag-unix-show-rqlen (unwrap (read-u8 buffer 20)))
           (sock-diag-unix-show-meminfo (unwrap (read-u8 buffer 20)))
           (sock-diag-rmem-alloc (unwrap (read-u32be buffer 44)))
           (sock-diag-wmem-queued (unwrap (read-u32be buffer 48)))
           (sock-diag-fwd-alloc (unwrap (read-u32be buffer 52)))
           (sock-diag-wmem-alloc (unwrap (read-u32be buffer 56)))
           (sock-diag-inet-sport (unwrap (read-u16be buffer 60)))
           (sock-diag-inet-dport (unwrap (read-u16be buffer 62)))
           (sock-diag-inet-src-ip4 (unwrap (read-u32be buffer 64)))
           (sock-diag-inet-dst-ip4 (unwrap (read-u32be buffer 80)))
           (sock-diag-inet-src-ip6 (unwrap (slice buffer 96 16)))
           (sock-diag-inet-dst-ip6 (unwrap (slice buffer 112 16)))
           (sock-diag-inet-interface (unwrap (read-u32be buffer 128)))
           (sock-diag-rqueue (unwrap (read-u32be buffer 148)))
           (sock-diag-wqueue (unwrap (read-u32be buffer 152)))
           (sock-diag-inet-extended (unwrap (read-u8 buffer 166)))
           (sock-diag-inet-padding (unwrap (read-u8 buffer 167)))
           (sock-diag-inet-states (unwrap (read-u32be buffer 168)))
           (sock-diag-netlink-port-id (unwrap (read-u32be buffer 176)))
           (sock-diag-netlink-dst-port-id (unwrap (read-u32be buffer 180)))
           (sock-diag-netlink-show (unwrap (read-u32be buffer 200)))
           (sock-diag-netlink-show-meminfo (unwrap (read-u8 buffer 200)))
           (sock-diag-netlink-show-groups (unwrap (read-u8 buffer 200)))
           (sock-diag-netlink-show-ring-cfg (unwrap (read-u8 buffer 200)))
           (sock-diag-packet-show (unwrap (read-u32be buffer 236)))
           (sock-diag-packet-show-info (unwrap (read-u8 buffer 236)))
           (sock-diag-packet-show-mclist (unwrap (read-u8 buffer 236)))
           (sock-diag-packet-show-ring-cfg (unwrap (read-u8 buffer 236)))
           (sock-diag-packet-show-fanout (unwrap (read-u8 buffer 236)))
           (sock-diag-packet-show-meminfo (unwrap (read-u8 buffer 236)))
           (sock-diag-packet-show-filter (unwrap (read-u8 buffer 236)))
           (sock-diag-inode (unwrap (read-u32be buffer 244)))
           (sock-diag-cookie (unwrap (read-u64be buffer 248)))
           )

      (ok (list
        (cons 'sock-diag-unix-name (list (cons 'raw sock-diag-unix-name) (cons 'formatted (utf8->string sock-diag-unix-name))))
        (cons 'sock-diag-unix-peer-inode (list (cons 'raw sock-diag-unix-peer-inode) (cons 'formatted (number->string sock-diag-unix-peer-inode))))
        (cons 'sock-diag-unix-show (list (cons 'raw sock-diag-unix-show) (cons 'formatted (fmt-hex sock-diag-unix-show))))
        (cons 'sock-diag-unix-show-name (list (cons 'raw sock-diag-unix-show-name) (cons 'formatted (if (= sock-diag-unix-show-name 0) "Don't show" "Show"))))
        (cons 'sock-diag-unix-show-vfs (list (cons 'raw sock-diag-unix-show-vfs) (cons 'formatted (if (= sock-diag-unix-show-vfs 0) "Don't show" "Show"))))
        (cons 'sock-diag-unix-show-peer (list (cons 'raw sock-diag-unix-show-peer) (cons 'formatted (if (= sock-diag-unix-show-peer 0) "Don't show" "Show"))))
        (cons 'sock-diag-unix-show-icons (list (cons 'raw sock-diag-unix-show-icons) (cons 'formatted (if (= sock-diag-unix-show-icons 0) "Don't show" "Show"))))
        (cons 'sock-diag-unix-show-rqlen (list (cons 'raw sock-diag-unix-show-rqlen) (cons 'formatted (if (= sock-diag-unix-show-rqlen 0) "Don't show" "Show"))))
        (cons 'sock-diag-unix-show-meminfo (list (cons 'raw sock-diag-unix-show-meminfo) (cons 'formatted (if (= sock-diag-unix-show-meminfo 0) "Don't show" "Show"))))
        (cons 'sock-diag-rmem-alloc (list (cons 'raw sock-diag-rmem-alloc) (cons 'formatted (number->string sock-diag-rmem-alloc))))
        (cons 'sock-diag-wmem-queued (list (cons 'raw sock-diag-wmem-queued) (cons 'formatted (number->string sock-diag-wmem-queued))))
        (cons 'sock-diag-fwd-alloc (list (cons 'raw sock-diag-fwd-alloc) (cons 'formatted (number->string sock-diag-fwd-alloc))))
        (cons 'sock-diag-wmem-alloc (list (cons 'raw sock-diag-wmem-alloc) (cons 'formatted (number->string sock-diag-wmem-alloc))))
        (cons 'sock-diag-inet-sport (list (cons 'raw sock-diag-inet-sport) (cons 'formatted (number->string sock-diag-inet-sport))))
        (cons 'sock-diag-inet-dport (list (cons 'raw sock-diag-inet-dport) (cons 'formatted (number->string sock-diag-inet-dport))))
        (cons 'sock-diag-inet-src-ip4 (list (cons 'raw sock-diag-inet-src-ip4) (cons 'formatted (fmt-ipv4 sock-diag-inet-src-ip4))))
        (cons 'sock-diag-inet-dst-ip4 (list (cons 'raw sock-diag-inet-dst-ip4) (cons 'formatted (fmt-ipv4 sock-diag-inet-dst-ip4))))
        (cons 'sock-diag-inet-src-ip6 (list (cons 'raw sock-diag-inet-src-ip6) (cons 'formatted (fmt-ipv6-address sock-diag-inet-src-ip6))))
        (cons 'sock-diag-inet-dst-ip6 (list (cons 'raw sock-diag-inet-dst-ip6) (cons 'formatted (fmt-ipv6-address sock-diag-inet-dst-ip6))))
        (cons 'sock-diag-inet-interface (list (cons 'raw sock-diag-inet-interface) (cons 'formatted (number->string sock-diag-inet-interface))))
        (cons 'sock-diag-rqueue (list (cons 'raw sock-diag-rqueue) (cons 'formatted (number->string sock-diag-rqueue))))
        (cons 'sock-diag-wqueue (list (cons 'raw sock-diag-wqueue) (cons 'formatted (number->string sock-diag-wqueue))))
        (cons 'sock-diag-inet-extended (list (cons 'raw sock-diag-inet-extended) (cons 'formatted (number->string sock-diag-inet-extended))))
        (cons 'sock-diag-inet-padding (list (cons 'raw sock-diag-inet-padding) (cons 'formatted (number->string sock-diag-inet-padding))))
        (cons 'sock-diag-inet-states (list (cons 'raw sock-diag-inet-states) (cons 'formatted (number->string sock-diag-inet-states))))
        (cons 'sock-diag-netlink-port-id (list (cons 'raw sock-diag-netlink-port-id) (cons 'formatted (number->string sock-diag-netlink-port-id))))
        (cons 'sock-diag-netlink-dst-port-id (list (cons 'raw sock-diag-netlink-dst-port-id) (cons 'formatted (number->string sock-diag-netlink-dst-port-id))))
        (cons 'sock-diag-netlink-show (list (cons 'raw sock-diag-netlink-show) (cons 'formatted (fmt-hex sock-diag-netlink-show))))
        (cons 'sock-diag-netlink-show-meminfo (list (cons 'raw sock-diag-netlink-show-meminfo) (cons 'formatted (if (= sock-diag-netlink-show-meminfo 0) "Don't show" "Show"))))
        (cons 'sock-diag-netlink-show-groups (list (cons 'raw sock-diag-netlink-show-groups) (cons 'formatted (if (= sock-diag-netlink-show-groups 0) "Don't show" "Show"))))
        (cons 'sock-diag-netlink-show-ring-cfg (list (cons 'raw sock-diag-netlink-show-ring-cfg) (cons 'formatted (if (= sock-diag-netlink-show-ring-cfg 0) "Don't show" "Show"))))
        (cons 'sock-diag-packet-show (list (cons 'raw sock-diag-packet-show) (cons 'formatted (fmt-hex sock-diag-packet-show))))
        (cons 'sock-diag-packet-show-info (list (cons 'raw sock-diag-packet-show-info) (cons 'formatted (if (= sock-diag-packet-show-info 0) "Don't show" "Show"))))
        (cons 'sock-diag-packet-show-mclist (list (cons 'raw sock-diag-packet-show-mclist) (cons 'formatted (if (= sock-diag-packet-show-mclist 0) "Don't show" "Show"))))
        (cons 'sock-diag-packet-show-ring-cfg (list (cons 'raw sock-diag-packet-show-ring-cfg) (cons 'formatted (if (= sock-diag-packet-show-ring-cfg 0) "Don't show" "Show"))))
        (cons 'sock-diag-packet-show-fanout (list (cons 'raw sock-diag-packet-show-fanout) (cons 'formatted (if (= sock-diag-packet-show-fanout 0) "Don't show" "Show"))))
        (cons 'sock-diag-packet-show-meminfo (list (cons 'raw sock-diag-packet-show-meminfo) (cons 'formatted (if (= sock-diag-packet-show-meminfo 0) "Don't show" "Show"))))
        (cons 'sock-diag-packet-show-filter (list (cons 'raw sock-diag-packet-show-filter) (cons 'formatted (if (= sock-diag-packet-show-filter 0) "Don't show" "Show"))))
        (cons 'sock-diag-inode (list (cons 'raw sock-diag-inode) (cons 'formatted (number->string sock-diag-inode))))
        (cons 'sock-diag-cookie (list (cons 'raw sock-diag-cookie) (cons 'formatted (fmt-hex sock-diag-cookie))))
        )))

    (catch (e)
      (err (str "NETLINK-SOCK-DIAG parse error: " e)))))

;; dissect-netlink-sock-diag: parse NETLINK-SOCK-DIAG from bytevector
;; Returns (ok fields-alist) or (err message)