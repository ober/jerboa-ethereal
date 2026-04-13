;; packet-socks.c
;; Routines for socks versions 4 &5  packet dissection
;; Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
;; Copyright 2008, Jelmer Vernooij <jelmer@samba.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;;
;; The Version 4 decode is based on SOCKS4.protocol and SOCKS4A.protocol.
;; The Version 5 decoder is based upon rfc-1928
;; The Version 5 User/Password authentication is based on rfc-1929.
;;
;; See
;; http://www.openssh.org/txt/socks4.protocol
;; http://www.openssh.org/txt/socks4a.protocol
;;
;; for information on SOCKS version 4 and 4a.
;;
;; Revisions:
;;
;; 2003-09-18 JCFoster Fixed problem with socks tunnel in socks tunnel
;; causing heap overflow because of an infinite loop
;; where the socks dissect was call over and over.
;;
;; Also remove some old code marked with __JUNK__
;;
;; 2001-01-08 JCFoster Fixed problem with NULL pointer for hash data.
;; Now test and exit if hash_info is null.
;;

;; jerboa-ethereal/dissectors/socks.ss
;; Auto-generated from wireshark/epan/dissectors/packet-socks.c

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
(def (dissect-socks buffer)
  "Socks Protocol"
  (try
    (let* (
           (reserved2 (unwrap (read-u16be buffer 0)))
           (ver (unwrap (read-u8 buffer 0)))
           (ip-dst (unwrap (read-u32be buffer 0)))
           (ip6-dst (unwrap (slice buffer 0 16)))
           (dstport (unwrap (read-u16be buffer 0)))
           (fragment-number (unwrap (read-u8 buffer 2)))
           (remote-name (unwrap (slice buffer 5 1)))
           (dns-name (unwrap (slice buffer 16 1)))
           (auth-method-count (unwrap (read-u8 buffer 21)))
           (auth-method (unwrap (read-u8 buffer 22)))
           (username (unwrap (slice buffer 27 1)))
           (password (unwrap (slice buffer 27 1)))
           (accepted-auth-method (unwrap (read-u8 buffer 28)))
           (auth-status (unwrap (read-u8 buffer 29)))
           (subnegotiation-version (unwrap (read-u8 buffer 29)))
           (length (unwrap (read-u16be buffer 30)))
           (payload (unwrap (slice buffer 30 1)))
           (port (unwrap (read-u16be buffer 33)))
           (reserved (unwrap (read-u8 buffer 35)))
           (remote-host-port (unwrap (read-u16be buffer 36)))
           )

      (ok (list
        (cons 'reserved2 (list (cons 'raw reserved2) (cons 'formatted (number->string reserved2))))
        (cons 'ver (list (cons 'raw ver) (cons 'formatted (number->string ver))))
        (cons 'ip-dst (list (cons 'raw ip-dst) (cons 'formatted (fmt-ipv4 ip-dst))))
        (cons 'ip6-dst (list (cons 'raw ip6-dst) (cons 'formatted (fmt-ipv6-address ip6-dst))))
        (cons 'dstport (list (cons 'raw dstport) (cons 'formatted (number->string dstport))))
        (cons 'fragment-number (list (cons 'raw fragment-number) (cons 'formatted (number->string fragment-number))))
        (cons 'remote-name (list (cons 'raw remote-name) (cons 'formatted (utf8->string remote-name))))
        (cons 'dns-name (list (cons 'raw dns-name) (cons 'formatted (utf8->string dns-name))))
        (cons 'auth-method-count (list (cons 'raw auth-method-count) (cons 'formatted (number->string auth-method-count))))
        (cons 'auth-method (list (cons 'raw auth-method) (cons 'formatted (number->string auth-method))))
        (cons 'username (list (cons 'raw username) (cons 'formatted (utf8->string username))))
        (cons 'password (list (cons 'raw password) (cons 'formatted (utf8->string password))))
        (cons 'accepted-auth-method (list (cons 'raw accepted-auth-method) (cons 'formatted (number->string accepted-auth-method))))
        (cons 'auth-status (list (cons 'raw auth-status) (cons 'formatted (number->string auth-status))))
        (cons 'subnegotiation-version (list (cons 'raw subnegotiation-version) (cons 'formatted (number->string subnegotiation-version))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-bytes payload))))
        (cons 'port (list (cons 'raw port) (cons 'formatted (number->string port))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (number->string reserved))))
        (cons 'remote-host-port (list (cons 'raw remote-host-port) (cons 'formatted (number->string remote-host-port))))
        )))

    (catch (e)
      (err (str "SOCKS parse error: " e)))))

;; dissect-socks: parse SOCKS from bytevector
;; Returns (ok fields-alist) or (err message)