;; packet-dcerpc-spoolss.c
;; Routines for SMB \PIPE\spoolss packet disassembly
;; Copyright 2001-2003, Tim Potter <tpot@samba.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dcerpc-spoolss.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dcerpc_spoolss.c

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
(def (dissect-dcerpc-spoolss buffer)
  "Microsoft Spool Subsystem"
  (try
    (let* (
           (access-enum (unwrap (read-u8 buffer 0)))
           (access-admin (unwrap (read-u8 buffer 0)))
           (data (unwrap (slice buffer 0 1)))
           (parm-data (unwrap (slice buffer 0 1)))
           (data-sz (unwrap (slice buffer 0 1)))
           (data-dword (unwrap (read-u32be buffer 0)))
           (hf-devmode (unwrap (read-u32be buffer 0)))
           (field (unwrap (read-u16be buffer 128)))
           (hf-form (unwrap (read-u32be buffer 128)))
           (value (unwrap (slice buffer 128 1)))
           (hf-printerdata (unwrap (read-u32be buffer 648)))
           (name-offset (unwrap (read-u32be buffer 648)))
           (name-len (unwrap (read-u32be buffer 648)))
           (access-use (unwrap (read-u8 buffer 652)))
           )

      (ok (list
        (cons 'access-enum (list (cons 'raw access-enum) (cons 'formatted (if (= access-enum 0) "False" "True"))))
        (cons 'access-admin (list (cons 'raw access-admin) (cons 'formatted (if (= access-admin 0) "False" "True"))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'parm-data (list (cons 'raw parm-data) (cons 'formatted (utf8->string parm-data))))
        (cons 'data-sz (list (cons 'raw data-sz) (cons 'formatted (utf8->string data-sz))))
        (cons 'data-dword (list (cons 'raw data-dword) (cons 'formatted (fmt-hex data-dword))))
        (cons 'hf-devmode (list (cons 'raw hf-devmode) (cons 'formatted (fmt-hex hf-devmode))))
        (cons 'field (list (cons 'raw field) (cons 'formatted (number->string field))))
        (cons 'hf-form (list (cons 'raw hf-form) (cons 'formatted (fmt-hex hf-form))))
        (cons 'value (list (cons 'raw value) (cons 'formatted (utf8->string value))))
        (cons 'hf-printerdata (list (cons 'raw hf-printerdata) (cons 'formatted (fmt-hex hf-printerdata))))
        (cons 'name-offset (list (cons 'raw name-offset) (cons 'formatted (number->string name-offset))))
        (cons 'name-len (list (cons 'raw name-len) (cons 'formatted (number->string name-len))))
        (cons 'access-use (list (cons 'raw access-use) (cons 'formatted (if (= access-use 0) "False" "True"))))
        )))

    (catch (e)
      (err (str "DCERPC-SPOOLSS parse error: " e)))))

;; dissect-dcerpc-spoolss: parse DCERPC-SPOOLSS from bytevector
;; Returns (ok fields-alist) or (err message)