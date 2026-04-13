;; packet-vtp.c
;; Routines for the disassembly of Cisco's VLAN Trunking Protocol
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/vtp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-vtp.c

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
(def (dissect-vtp buffer)
  "VLAN Trunking Protocol"
  (try
    (let* (
           (followers (unwrap (read-u8 buffer 2)))
           (upd-id (unwrap (read-u32be buffer 40)))
           (upd-ts (unwrap (slice buffer 44 12)))
           (md5-digest (unwrap (slice buffer 56 16)))
           (seq-num (unwrap (read-u8 buffer 56)))
           (conf-rev-num (unwrap (read-u32be buffer 90)))
           (start-value (unwrap (read-u16be buffer 128)))
           (reserved (unwrap (slice buffer 128 1)))
           (md-len (unwrap (read-u8 buffer 129)))
           (md (unwrap (slice buffer 130 32)))
           (pruning-first-vid (unwrap (read-u16be buffer 162)))
           (pruning-last-vid (unwrap (read-u16be buffer 164)))
           (pruning-active-vid (unwrap (read-u16be buffer 166)))
           (version (unwrap (read-u8 buffer 168)))
           )

      (ok (list
        (cons 'followers (list (cons 'raw followers) (cons 'formatted (number->string followers))))
        (cons 'upd-id (list (cons 'raw upd-id) (cons 'formatted (fmt-ipv4 upd-id))))
        (cons 'upd-ts (list (cons 'raw upd-ts) (cons 'formatted (utf8->string upd-ts))))
        (cons 'md5-digest (list (cons 'raw md5-digest) (cons 'formatted (fmt-bytes md5-digest))))
        (cons 'seq-num (list (cons 'raw seq-num) (cons 'formatted (number->string seq-num))))
        (cons 'conf-rev-num (list (cons 'raw conf-rev-num) (cons 'formatted (number->string conf-rev-num))))
        (cons 'start-value (list (cons 'raw start-value) (cons 'formatted (fmt-hex start-value))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'md-len (list (cons 'raw md-len) (cons 'formatted (number->string md-len))))
        (cons 'md (list (cons 'raw md) (cons 'formatted (utf8->string md))))
        (cons 'pruning-first-vid (list (cons 'raw pruning-first-vid) (cons 'formatted (number->string pruning-first-vid))))
        (cons 'pruning-last-vid (list (cons 'raw pruning-last-vid) (cons 'formatted (number->string pruning-last-vid))))
        (cons 'pruning-active-vid (list (cons 'raw pruning-active-vid) (cons 'formatted (number->string pruning-active-vid))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (fmt-hex version))))
        )))

    (catch (e)
      (err (str "VTP parse error: " e)))))

;; dissect-vtp: parse VTP from bytevector
;; Returns (ok fields-alist) or (err message)