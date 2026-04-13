;; packet-fcsb3.c
;; Routines for Fibre Channel Single Byte Protocol (SBCCS); used in FICON.
;; This decoder is for FC-SB3 version 1.4
;; Copyright 2003, Dinesh G Dutt <ddutt@cisco.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/fcsb3.ss
;; Auto-generated from wireshark/epan/dissectors/packet-fcsb3.c

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
(def (dissect-fcsb3 buffer)
  "Fibre Channel Single Byte Command"
  (try
    (let* (
           (chid (unwrap (read-u8 buffer 0)))
           (cuid (unwrap (read-u8 buffer 0)))
           (devaddr (unwrap (read-u16be buffer 0)))
           (ccw (unwrap (read-u16be buffer 0)))
           (token (unwrap (read-u24be buffer 0)))
           (dib-iucnt (unwrap (read-u8 buffer 0)))
           (dib-datacnt (unwrap (read-u16be buffer 0)))
           (lrc (unwrap (read-u32be buffer 0)))
           (dib-ccw-cnt (unwrap (read-u16be buffer 0)))
           (dib-ioprio (unwrap (read-u8 buffer 0)))
           (dib-residualcnt (unwrap (read-u16be buffer 0)))
           (dib-iupacing (unwrap (read-u8 buffer 0)))
           (dib-qtuf (unwrap (read-u8 buffer 0)))
           (dib-qtu (unwrap (read-u16be buffer 0)))
           (dib-dtuf (unwrap (read-u8 buffer 0)))
           (dib-dtu (unwrap (read-u16be buffer 0)))
           (dib-ctlparam (unwrap (read-u24be buffer 0)))
           (dib-tin-imgid-cnt (unwrap (read-u8 buffer 0)))
           (dib-ctccntr (unwrap (read-u16be buffer 0)))
           )

      (ok (list
        (cons 'chid (list (cons 'raw chid) (cons 'formatted (number->string chid))))
        (cons 'cuid (list (cons 'raw cuid) (cons 'formatted (number->string cuid))))
        (cons 'devaddr (list (cons 'raw devaddr) (cons 'formatted (number->string devaddr))))
        (cons 'ccw (list (cons 'raw ccw) (cons 'formatted (fmt-hex ccw))))
        (cons 'token (list (cons 'raw token) (cons 'formatted (number->string token))))
        (cons 'dib-iucnt (list (cons 'raw dib-iucnt) (cons 'formatted (number->string dib-iucnt))))
        (cons 'dib-datacnt (list (cons 'raw dib-datacnt) (cons 'formatted (number->string dib-datacnt))))
        (cons 'lrc (list (cons 'raw lrc) (cons 'formatted (fmt-hex lrc))))
        (cons 'dib-ccw-cnt (list (cons 'raw dib-ccw-cnt) (cons 'formatted (number->string dib-ccw-cnt))))
        (cons 'dib-ioprio (list (cons 'raw dib-ioprio) (cons 'formatted (number->string dib-ioprio))))
        (cons 'dib-residualcnt (list (cons 'raw dib-residualcnt) (cons 'formatted (number->string dib-residualcnt))))
        (cons 'dib-iupacing (list (cons 'raw dib-iupacing) (cons 'formatted (number->string dib-iupacing))))
        (cons 'dib-qtuf (list (cons 'raw dib-qtuf) (cons 'formatted (number->string dib-qtuf))))
        (cons 'dib-qtu (list (cons 'raw dib-qtu) (cons 'formatted (number->string dib-qtu))))
        (cons 'dib-dtuf (list (cons 'raw dib-dtuf) (cons 'formatted (number->string dib-dtuf))))
        (cons 'dib-dtu (list (cons 'raw dib-dtu) (cons 'formatted (number->string dib-dtu))))
        (cons 'dib-ctlparam (list (cons 'raw dib-ctlparam) (cons 'formatted (fmt-hex dib-ctlparam))))
        (cons 'dib-tin-imgid-cnt (list (cons 'raw dib-tin-imgid-cnt) (cons 'formatted (number->string dib-tin-imgid-cnt))))
        (cons 'dib-ctccntr (list (cons 'raw dib-ctccntr) (cons 'formatted (number->string dib-ctccntr))))
        )))

    (catch (e)
      (err (str "FCSB3 parse error: " e)))))

;; dissect-fcsb3: parse FCSB3 from bytevector
;; Returns (ok fields-alist) or (err message)