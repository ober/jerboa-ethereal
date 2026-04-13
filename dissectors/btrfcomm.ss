;; packet-btrfcomm.c
;; Routines for Bluetooth RFCOMM protocol dissection
;; and RFCOMM based profile dissection:
;; - Dial-Up Networking Profile (DUN)
;; - Serial Port Profile (SPP)
;; - Global Navigation Satellite System (GNSS)
;;
;; Copyright 2002, Wolfgang Hansmann <hansmann@cs.uni-bonn.de>
;;
;; Refactored for wireshark checkin
;; Ronnie Sahlberg 2006
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/btrfcomm.ss
;; Auto-generated from wireshark/epan/dissectors/packet-btrfcomm.c

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
(def (dissect-btrfcomm buffer)
  "Bluetooth RFCOMM Protocol"
  (try
    (let* (
           (data (unwrap (slice buffer 0 1)))
           (at-cmd (unwrap (slice buffer 0 1)))
           (uuid (unwrap (slice buffer 0 1)))
           (credits (unwrap (read-u8 buffer 0)))
           (pn-zeros-padding (unwrap (read-u8 buffer 1)))
           (pn-dlci (unwrap (read-u8 buffer 1)))
           (pn-channel (unwrap (read-u8 buffer 1)))
           (pn-direction (unwrap (read-u8 buffer 1)))
           (dlci (unwrap (read-u8 buffer 1)))
           (channel (unwrap (read-u8 buffer 1)))
           (direction (unwrap (read-u8 buffer 1)))
           (const-1 (unwrap (read-u8 buffer 1)))
           (hf-priority (unwrap (read-u8 buffer 3)))
           (timer-t1 (unwrap (read-u8 buffer 4)))
           (frame-size (unwrap (read-u16be buffer 5)))
           (retrans (unwrap (read-u8 buffer 7)))
           (recovery-mode (unwrap (read-u8 buffer 8)))
           (fc (unwrap (read-u8 buffer 10)))
           (rtc (unwrap (read-u8 buffer 10)))
           (rtr (unwrap (read-u8 buffer 10)))
           (ic (unwrap (read-u8 buffer 10)))
           (dv (unwrap (read-u8 buffer 10)))
           (break-bits (unwrap (read-u8 buffer 11)))
           (l (unwrap (read-u8 buffer 11)))
           (hf-dlci (unwrap (read-u8 buffer 12)))
           (hf-channel (unwrap (read-u8 buffer 12)))
           (hf-direction (unwrap (read-u8 buffer 12)))
           (hf-cr (unwrap (read-u8 buffer 12)))
           (hf-pf (unwrap (read-u8 buffer 13)))
           )

      (ok (list
        (cons 'data (list (cons 'raw data) (cons 'formatted (utf8->string data))))
        (cons 'at-cmd (list (cons 'raw at-cmd) (cons 'formatted (utf8->string at-cmd))))
        (cons 'uuid (list (cons 'raw uuid) (cons 'formatted (fmt-bytes uuid))))
        (cons 'credits (list (cons 'raw credits) (cons 'formatted (number->string credits))))
        (cons 'pn-zeros-padding (list (cons 'raw pn-zeros-padding) (cons 'formatted (fmt-hex pn-zeros-padding))))
        (cons 'pn-dlci (list (cons 'raw pn-dlci) (cons 'formatted (fmt-hex pn-dlci))))
        (cons 'pn-channel (list (cons 'raw pn-channel) (cons 'formatted (number->string pn-channel))))
        (cons 'pn-direction (list (cons 'raw pn-direction) (cons 'formatted (fmt-hex pn-direction))))
        (cons 'dlci (list (cons 'raw dlci) (cons 'formatted (fmt-hex dlci))))
        (cons 'channel (list (cons 'raw channel) (cons 'formatted (number->string channel))))
        (cons 'direction (list (cons 'raw direction) (cons 'formatted (fmt-hex direction))))
        (cons 'const-1 (list (cons 'raw const-1) (cons 'formatted (fmt-hex const-1))))
        (cons 'hf-priority (list (cons 'raw hf-priority) (cons 'formatted (number->string hf-priority))))
        (cons 'timer-t1 (list (cons 'raw timer-t1) (cons 'formatted (number->string timer-t1))))
        (cons 'frame-size (list (cons 'raw frame-size) (cons 'formatted (number->string frame-size))))
        (cons 'retrans (list (cons 'raw retrans) (cons 'formatted (number->string retrans))))
        (cons 'recovery-mode (list (cons 'raw recovery-mode) (cons 'formatted (number->string recovery-mode))))
        (cons 'fc (list (cons 'raw fc) (cons 'formatted (fmt-hex fc))))
        (cons 'rtc (list (cons 'raw rtc) (cons 'formatted (fmt-hex rtc))))
        (cons 'rtr (list (cons 'raw rtr) (cons 'formatted (fmt-hex rtr))))
        (cons 'ic (list (cons 'raw ic) (cons 'formatted (fmt-hex ic))))
        (cons 'dv (list (cons 'raw dv) (cons 'formatted (fmt-hex dv))))
        (cons 'break-bits (list (cons 'raw break-bits) (cons 'formatted (number->string break-bits))))
        (cons 'l (list (cons 'raw l) (cons 'formatted (number->string l))))
        (cons 'hf-dlci (list (cons 'raw hf-dlci) (cons 'formatted (fmt-hex hf-dlci))))
        (cons 'hf-channel (list (cons 'raw hf-channel) (cons 'formatted (number->string hf-channel))))
        (cons 'hf-direction (list (cons 'raw hf-direction) (cons 'formatted (fmt-hex hf-direction))))
        (cons 'hf-cr (list (cons 'raw hf-cr) (cons 'formatted (if (= hf-cr 0) "False" "True"))))
        (cons 'hf-pf (list (cons 'raw hf-pf) (cons 'formatted (fmt-hex hf-pf))))
        )))

    (catch (e)
      (err (str "BTRFCOMM parse error: " e)))))

;; dissect-btrfcomm: parse BTRFCOMM from bytevector
;; Returns (ok fields-alist) or (err message)