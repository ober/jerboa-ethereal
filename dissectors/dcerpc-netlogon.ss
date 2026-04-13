;; packet-dcerpc-netlogon.c
;; Routines for SMB \PIPE\NETLOGON packet disassembly
;; Copyright 2001,2003 Tim Potter <tpot@samba.org>
;; 2002 structure and command dissectors by Ronnie Sahlberg
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dcerpc-netlogon.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dcerpc_netlogon.c

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
(def (dissect-dcerpc-netlogon buffer)
  "Microsoft Network Logon"
  (try
    (let* (
           (blob (unwrap (slice buffer 0 516)))
           (new-password (unwrap (slice buffer 0 1)))
           (level (unwrap (read-u32be buffer 8)))
           (lm-owf-password (unwrap (slice buffer 10 16)))
           (sockaddr-ipv4 (unwrap (read-u32be buffer 24)))
           (nt-owf-password (unwrap (slice buffer 26 16)))
           (sockaddr-ipv6 (unwrap (slice buffer 28 16)))
           (secchan-nl-nb-domain (unwrap (slice buffer 32 1)))
           (secchan-nl-nb-host (unwrap (slice buffer 32 1)))
           (secchan-verf-flag (unwrap (slice buffer 32 2)))
           (challenge (unwrap (slice buffer 42 8)))
           (credential (unwrap (slice buffer 50 8)))
           (user-session-key (unwrap (slice buffer 62 16)))
           (pac-data (unwrap (slice buffer 78 1)))
           (auth-data (unwrap (slice buffer 78 1)))
           (encrypted-lm-owf-password (unwrap (slice buffer 78 16)))
           (sensitive-data (unwrap (slice buffer 94 1)))
           (computer-name (unwrap (slice buffer 98 16)))
           (time-created (unwrap (read-u32be buffer 114)))
           (logon-duration (unwrap (read-u32be buffer 516)))
           )

      (ok (list
        (cons 'blob (list (cons 'raw blob) (cons 'formatted (fmt-bytes blob))))
        (cons 'new-password (list (cons 'raw new-password) (cons 'formatted (utf8->string new-password))))
        (cons 'level (list (cons 'raw level) (cons 'formatted (number->string level))))
        (cons 'lm-owf-password (list (cons 'raw lm-owf-password) (cons 'formatted (fmt-bytes lm-owf-password))))
        (cons 'sockaddr-ipv4 (list (cons 'raw sockaddr-ipv4) (cons 'formatted (fmt-ipv4 sockaddr-ipv4))))
        (cons 'nt-owf-password (list (cons 'raw nt-owf-password) (cons 'formatted (fmt-bytes nt-owf-password))))
        (cons 'sockaddr-ipv6 (list (cons 'raw sockaddr-ipv6) (cons 'formatted (fmt-ipv6-address sockaddr-ipv6))))
        (cons 'secchan-nl-nb-domain (list (cons 'raw secchan-nl-nb-domain) (cons 'formatted (utf8->string secchan-nl-nb-domain))))
        (cons 'secchan-nl-nb-host (list (cons 'raw secchan-nl-nb-host) (cons 'formatted (utf8->string secchan-nl-nb-host))))
        (cons 'secchan-verf-flag (list (cons 'raw secchan-verf-flag) (cons 'formatted (fmt-bytes secchan-verf-flag))))
        (cons 'challenge (list (cons 'raw challenge) (cons 'formatted (fmt-bytes challenge))))
        (cons 'credential (list (cons 'raw credential) (cons 'formatted (fmt-bytes credential))))
        (cons 'user-session-key (list (cons 'raw user-session-key) (cons 'formatted (fmt-bytes user-session-key))))
        (cons 'pac-data (list (cons 'raw pac-data) (cons 'formatted (fmt-bytes pac-data))))
        (cons 'auth-data (list (cons 'raw auth-data) (cons 'formatted (fmt-bytes auth-data))))
        (cons 'encrypted-lm-owf-password (list (cons 'raw encrypted-lm-owf-password) (cons 'formatted (fmt-bytes encrypted-lm-owf-password))))
        (cons 'sensitive-data (list (cons 'raw sensitive-data) (cons 'formatted (fmt-bytes sensitive-data))))
        (cons 'computer-name (list (cons 'raw computer-name) (cons 'formatted (utf8->string computer-name))))
        (cons 'time-created (list (cons 'raw time-created) (cons 'formatted (number->string time-created))))
        (cons 'logon-duration (list (cons 'raw logon-duration) (cons 'formatted (number->string logon-duration))))
        )))

    (catch (e)
      (err (str "DCERPC-NETLOGON parse error: " e)))))

;; dissect-dcerpc-netlogon: parse DCERPC-NETLOGON from bytevector
;; Returns (ok fields-alist) or (err message)