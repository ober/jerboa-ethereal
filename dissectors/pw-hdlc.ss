;; packet-pw-hdlc.c
;; Routines for HDLC PW dissection as per RFC4618.
;; Copyright 2009, Dmitry Trebich, Artem Tamazov <artem.tamazov@tellabs.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; History:
;; ---------------------------------
;; 02.03.2009 Initial implementation, supports:
;; - HDLC mode (rfc4618 5.1), no CW, payload is PPP (PPP in HDLC-like Framing (rfc1662)).
;; - FR port mode (rfc4618 5.2), no CW.
;;
;; [informative: Not supported yet:
;; - All kinds of HDLC PW with CW.
;; - PPP mode (rfc4618 5.3).
;; - For HDLC mode, decoding payloads other than PPP.]
;;

;; jerboa-ethereal/dissectors/pw-hdlc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-pw_hdlc.c
;; RFC 4618

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
(def (dissect-pw-hdlc buffer)
  "HDLC PW, FR port mode (no CW)"
  (try
    (let* (
           (hdlc-cr-bit (unwrap (read-u8 buffer 0)))
           (hdlc-address (unwrap (read-u8 buffer 0)))
           (hdlc-address-field (unwrap (read-u8 buffer 0)))
           (hdlc-pf-bit (unwrap (read-u8 buffer 1)))
           (hdlc-frame (unwrap (read-u8 buffer 1)))
           (hdlc-control-field (unwrap (read-u8 buffer 1)))
           )

      (ok (list
        (cons 'hdlc-cr-bit (list (cons 'raw hdlc-cr-bit) (cons 'formatted (number->string hdlc-cr-bit))))
        (cons 'hdlc-address (list (cons 'raw hdlc-address) (cons 'formatted (fmt-hex hdlc-address))))
        (cons 'hdlc-address-field (list (cons 'raw hdlc-address-field) (cons 'formatted (fmt-hex hdlc-address-field))))
        (cons 'hdlc-pf-bit (list (cons 'raw hdlc-pf-bit) (cons 'formatted (number->string hdlc-pf-bit))))
        (cons 'hdlc-frame (list (cons 'raw hdlc-frame) (cons 'formatted (number->string hdlc-frame))))
        (cons 'hdlc-control-field (list (cons 'raw hdlc-control-field) (cons 'formatted (fmt-hex hdlc-control-field))))
        )))

    (catch (e)
      (err (str "PW-HDLC parse error: " e)))))

;; dissect-pw-hdlc: parse PW-HDLC from bytevector
;; Returns (ok fields-alist) or (err message)