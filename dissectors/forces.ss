;; packet-forces.c
;; RFC 5810
;; Routines for dissecting IETF ForCES protocol layer messages.Now support the following TML types:TCP+UDP,SCTP.
;; Copyright 2009, NDSC & Zhejiang Gongshang University,Fenggen Jia <fgjia@mail.zjgsu.edu.cn or fenggen.jia@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/forces.ss
;; Auto-generated from wireshark/epan/dissectors/packet-forces.c
;; RFC 5810

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
(def (dissect-forces buffer)
  "Forwarding and Control Element Separation Protocol"
  (try
    (let* (
           (rsvd (unwrap (read-u8 buffer 0)))
           (version (unwrap (read-u8 buffer 0)))
           (messagetype (unwrap (read-u8 buffer 0)))
           (length (unwrap (read-u16be buffer 0)))
           (sid (unwrap (read-u32be buffer 0)))
           (did (unwrap (read-u32be buffer 0)))
           (correlator (unwrap (read-u64be buffer 0)))
           (flags (unwrap (read-u32be buffer 0)))
           (flags-pri (unwrap (read-u32be buffer 0)))
           (flags-reserved (unwrap (read-u32be buffer 0)))
           (flags-rsrvd (unwrap (read-u32be buffer 0)))
           (tlv-type (unwrap (read-u16be buffer 24)))
           (unknown-tlv (unwrap (slice buffer 24 1)))
           )

      (ok (list
        (cons 'rsvd (list (cons 'raw rsvd) (cons 'formatted (number->string rsvd))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'messagetype (list (cons 'raw messagetype) (cons 'formatted (number->string messagetype))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'sid (list (cons 'raw sid) (cons 'formatted (fmt-ipv4 sid))))
        (cons 'did (list (cons 'raw did) (cons 'formatted (fmt-ipv4 did))))
        (cons 'correlator (list (cons 'raw correlator) (cons 'formatted (fmt-hex correlator))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (number->string flags))))
        (cons 'flags-pri (list (cons 'raw flags-pri) (cons 'formatted (number->string flags-pri))))
        (cons 'flags-reserved (list (cons 'raw flags-reserved) (cons 'formatted (number->string flags-reserved))))
        (cons 'flags-rsrvd (list (cons 'raw flags-rsrvd) (cons 'formatted (number->string flags-rsrvd))))
        (cons 'tlv-type (list (cons 'raw tlv-type) (cons 'formatted (number->string tlv-type))))
        (cons 'unknown-tlv (list (cons 'raw unknown-tlv) (cons 'formatted (fmt-bytes unknown-tlv))))
        )))

    (catch (e)
      (err (str "FORCES parse error: " e)))))

;; dissect-forces: parse FORCES from bytevector
;; Returns (ok fields-alist) or (err message)