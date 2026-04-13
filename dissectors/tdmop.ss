;; packet-tdmop.c
;; Routines for TDM over Packet network disassembly
;; Copyright 2015, Andrew Chernyh <andew.chernyh@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/tdmop.ss
;; Auto-generated from wireshark/epan/dissectors/packet-tdmop.c

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
(def (dissect-tdmop buffer)
  "TDMoP protocol"
  (try
    (let* (
           (DstCh (unwrap (read-u8 buffer 2)))
           (SrcCh (unwrap (read-u8 buffer 3)))
           (Flags (unwrap (read-u8 buffer 4)))
           (Flags-no-data (unwrap (read-u8 buffer 4)))
           (Flags-lost-request (unwrap (read-u8 buffer 4)))
           (Flags-remote-no-data (unwrap (read-u8 buffer 4)))
           (Flags-compressed (unwrap (read-u8 buffer 4)))
           (SrcDst (unwrap (read-u8 buffer 5)))
           (SeqNum (unwrap (read-u16be buffer 6)))
           (LastRecv (unwrap (read-u16be buffer 8)))
           (Delay (unwrap (read-u16be buffer 10)))
           (Reserved (unwrap (read-u16be buffer 12)))
           (payload (unwrap (slice buffer 14 1)))
           (Compression-mask (unwrap (read-u32be buffer 14)))
           (TransferID (unwrap (read-u32be buffer 18)))
           )

      (ok (list
        (cons 'DstCh (list (cons 'raw DstCh) (cons 'formatted (number->string DstCh))))
        (cons 'SrcCh (list (cons 'raw SrcCh) (cons 'formatted (number->string SrcCh))))
        (cons 'Flags (list (cons 'raw Flags) (cons 'formatted (number->string Flags))))
        (cons 'Flags-no-data (list (cons 'raw Flags-no-data) (cons 'formatted (number->string Flags-no-data))))
        (cons 'Flags-lost-request (list (cons 'raw Flags-lost-request) (cons 'formatted (number->string Flags-lost-request))))
        (cons 'Flags-remote-no-data (list (cons 'raw Flags-remote-no-data) (cons 'formatted (number->string Flags-remote-no-data))))
        (cons 'Flags-compressed (list (cons 'raw Flags-compressed) (cons 'formatted (number->string Flags-compressed))))
        (cons 'SrcDst (list (cons 'raw SrcDst) (cons 'formatted (fmt-hex SrcDst))))
        (cons 'SeqNum (list (cons 'raw SeqNum) (cons 'formatted (number->string SeqNum))))
        (cons 'LastRecv (list (cons 'raw LastRecv) (cons 'formatted (number->string LastRecv))))
        (cons 'Delay (list (cons 'raw Delay) (cons 'formatted (number->string Delay))))
        (cons 'Reserved (list (cons 'raw Reserved) (cons 'formatted (number->string Reserved))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-bytes payload))))
        (cons 'Compression-mask (list (cons 'raw Compression-mask) (cons 'formatted (fmt-hex Compression-mask))))
        (cons 'TransferID (list (cons 'raw TransferID) (cons 'formatted (fmt-hex TransferID))))
        )))

    (catch (e)
      (err (str "TDMOP parse error: " e)))))

;; dissect-tdmop: parse TDMOP from bytevector
;; Returns (ok fields-alist) or (err message)