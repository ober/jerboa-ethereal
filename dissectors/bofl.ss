;; packet-bofl.c
;; Routines for Wellfleet BOFL dissection
;; Wellfleet -> Baynetworks -> Nortel -> Avaya -> Extremenetworks
;; Protocol is now called Simple Loop Protection Protocol (SLPP)
;; Author: Endoh Akira (endoh@netmarks.co.jp)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@unicom.net>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; The following information was copied from
;; http://web.archive.org/web/20150608035209/http://www.protocols.com/pbook/bridge.htm#WellfleetBOFL
;;
;; The Wellfleet Breath of Life (BOFL) protocol is used as a line sensing
;; protocol on:
;;
;; - Ethernet LANs to detect transmitter jams.
;; - Synchronous lines running WFLT STD protocols to determine if the line
;; is up.
;; - Dial backup PPP lines.
;;
;; The frame format of Wellfleet BOFL is shown following the Ethernet header
;; in the following illustration:
;;
;; Destination   Source    8102    PDU   Sequence   Padding
;; 6           6        2      4       4       n bytes
;;

;; jerboa-ethereal/dissectors/bofl.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bofl.c

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
(def (dissect-bofl buffer)
  "Wellfleet Breath of Life"
  (try
    (let* (
           (pdu (unwrap (read-u32be buffer 0)))
           (sequence (unwrap (read-u32be buffer 4)))
           (padding (unwrap (slice buffer 8 1)))
           )

      (ok (list
        (cons 'pdu (list (cons 'raw pdu) (cons 'formatted (fmt-hex pdu))))
        (cons 'sequence (list (cons 'raw sequence) (cons 'formatted (number->string sequence))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        )))

    (catch (e)
      (err (str "BOFL parse error: " e)))))

;; dissect-bofl: parse BOFL from bytevector
;; Returns (ok fields-alist) or (err message)