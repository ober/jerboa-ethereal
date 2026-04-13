;; packet-shicp.c
;; Routines for Secure Host IP Configuration Protocol dissection
;; Copyright 2021, Filip Kågesson <exfik@hms.se>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/shicp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-shicp.c

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
(def (dissect-shicp buffer)
  "Secure Host IP Configuration Protocol"
  (try
    (let* (
           (header (unwrap (read-u16be buffer 0)))
           (protocol-version (unwrap (read-u8 buffer 0)))
           (dst (unwrap (slice buffer 0 6)))
           (src (unwrap (slice buffer 0 6)))
           (error-string (unwrap (slice buffer 1 1)))
           (auth-req (unwrap (read-u8 buffer 3)))
           (module-version (unwrap (slice buffer 3 1)))
           (module-desc (unwrap (slice buffer 3 1)))
           (supported-msg (unwrap (slice buffer 3 1)))
           (hn-max-len (unwrap (read-u8 buffer 3)))
           (pswd-max-len (unwrap (read-u8 buffer 3)))
           (challenge (unwrap (read-u32be buffer 3)))
           (validity-period (unwrap (read-u8 buffer 3)))
           (error (unwrap (read-u8 buffer 3)))
           (ip (unwrap (read-u32be buffer 5)))
           (sn (unwrap (read-u32be buffer 5)))
           (gw (unwrap (read-u32be buffer 5)))
           (dns1 (unwrap (read-u32be buffer 5)))
           (dns2 (unwrap (read-u32be buffer 5)))
           (dhcp (unwrap (read-u8 buffer 5)))
           (hn (unwrap (slice buffer 5 1)))
           (pswd (unwrap (slice buffer 5 1)))
           (token (unwrap (slice buffer 5 1)))
           (wink-type (unwrap (read-u8 buffer 5)))
           )

      (ok (list
        (cons 'header (list (cons 'raw header) (cons 'formatted (fmt-hex header))))
        (cons 'protocol-version (list (cons 'raw protocol-version) (cons 'formatted (number->string protocol-version))))
        (cons 'dst (list (cons 'raw dst) (cons 'formatted (fmt-mac dst))))
        (cons 'src (list (cons 'raw src) (cons 'formatted (fmt-mac src))))
        (cons 'error-string (list (cons 'raw error-string) (cons 'formatted (utf8->string error-string))))
        (cons 'auth-req (list (cons 'raw auth-req) (cons 'formatted (number->string auth-req))))
        (cons 'module-version (list (cons 'raw module-version) (cons 'formatted (utf8->string module-version))))
        (cons 'module-desc (list (cons 'raw module-desc) (cons 'formatted (utf8->string module-desc))))
        (cons 'supported-msg (list (cons 'raw supported-msg) (cons 'formatted (utf8->string supported-msg))))
        (cons 'hn-max-len (list (cons 'raw hn-max-len) (cons 'formatted (number->string hn-max-len))))
        (cons 'pswd-max-len (list (cons 'raw pswd-max-len) (cons 'formatted (number->string pswd-max-len))))
        (cons 'challenge (list (cons 'raw challenge) (cons 'formatted (fmt-hex challenge))))
        (cons 'validity-period (list (cons 'raw validity-period) (cons 'formatted (number->string validity-period))))
        (cons 'error (list (cons 'raw error) (cons 'formatted (fmt-hex error))))
        (cons 'ip (list (cons 'raw ip) (cons 'formatted (fmt-ipv4 ip))))
        (cons 'sn (list (cons 'raw sn) (cons 'formatted (fmt-ipv4 sn))))
        (cons 'gw (list (cons 'raw gw) (cons 'formatted (fmt-ipv4 gw))))
        (cons 'dns1 (list (cons 'raw dns1) (cons 'formatted (fmt-ipv4 dns1))))
        (cons 'dns2 (list (cons 'raw dns2) (cons 'formatted (fmt-ipv4 dns2))))
        (cons 'dhcp (list (cons 'raw dhcp) (cons 'formatted (if (= dhcp 0) "False" "True"))))
        (cons 'hn (list (cons 'raw hn) (cons 'formatted (utf8->string hn))))
        (cons 'pswd (list (cons 'raw pswd) (cons 'formatted (utf8->string pswd))))
        (cons 'token (list (cons 'raw token) (cons 'formatted (fmt-bytes token))))
        (cons 'wink-type (list (cons 'raw wink-type) (cons 'formatted (fmt-hex wink-type))))
        )))

    (catch (e)
      (err (str "SHICP parse error: " e)))))

;; dissect-shicp: parse SHICP from bytevector
;; Returns (ok fields-alist) or (err message)