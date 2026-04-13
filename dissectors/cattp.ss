;; packet-cattp.c
;; Routines for packet dissection of
;; ETSI TS 102 127 v6.13.0  (Release 6 / 2009-0r45)
;; Card Application Toolkit - Transport Protocol over UDP
;;
;; Copyright 2014-2014 by Sebastian Kloeppel <sk [at] nakedape.net>
;; Cristina E. Vintila <cristina.vintila [at] gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/cattp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cattp.c

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
(def (dissect-cattp buffer)
  "ETSI Card Application Toolkit Transport Protocol"
  (try
    (let* (
           (flags (unwrap (read-u8 buffer 0)))
           (flag-syn (extract-bits flags 0x0 0))
           (flag-ack (extract-bits flags 0x0 0))
           (flag-eak (extract-bits flags 0x0 0))
           (flag-rst (extract-bits flags 0x0 0))
           (flag-nul (extract-bits flags 0x0 0))
           (flag-seg (extract-bits flags 0x0 0))
           (version (extract-bits flags 0x0 0))
           (hlen (unwrap (read-u8 buffer 3)))
           (srcport (unwrap (read-u16be buffer 4)))
           (dstport (unwrap (read-u16be buffer 6)))
           (datalen (unwrap (read-u16be buffer 8)))
           (seq (unwrap (read-u16be buffer 10)))
           (ack (unwrap (read-u16be buffer 12)))
           (windowsize (unwrap (read-u16be buffer 14)))
           )

      (ok (list
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flag-syn (list (cons 'raw flag-syn) (cons 'formatted (if (= flag-syn 0) "Not set" "Set"))))
        (cons 'flag-ack (list (cons 'raw flag-ack) (cons 'formatted (if (= flag-ack 0) "Not set" "Set"))))
        (cons 'flag-eak (list (cons 'raw flag-eak) (cons 'formatted (if (= flag-eak 0) "Not set" "Set"))))
        (cons 'flag-rst (list (cons 'raw flag-rst) (cons 'formatted (if (= flag-rst 0) "Not set" "Set"))))
        (cons 'flag-nul (list (cons 'raw flag-nul) (cons 'formatted (if (= flag-nul 0) "Not set" "Set"))))
        (cons 'flag-seg (list (cons 'raw flag-seg) (cons 'formatted (if (= flag-seg 0) "Not set" "Set"))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (if (= version 0) "Not set" "Set"))))
        (cons 'hlen (list (cons 'raw hlen) (cons 'formatted (number->string hlen))))
        (cons 'srcport (list (cons 'raw srcport) (cons 'formatted (number->string srcport))))
        (cons 'dstport (list (cons 'raw dstport) (cons 'formatted (number->string dstport))))
        (cons 'datalen (list (cons 'raw datalen) (cons 'formatted (number->string datalen))))
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (number->string seq))))
        (cons 'ack (list (cons 'raw ack) (cons 'formatted (number->string ack))))
        (cons 'windowsize (list (cons 'raw windowsize) (cons 'formatted (number->string windowsize))))
        )))

    (catch (e)
      (err (str "CATTP parse error: " e)))))

;; dissect-cattp: parse CATTP from bytevector
;; Returns (ok fields-alist) or (err message)