;; packet-itdm.c
;; Routines for I-TDM (Internal TDM) dissection
;; Compliant to PICMG SFP.0 and SFP.1 March 24, 2005
;;
;; Copyright 2008, Dan Gora <dg [AT] adax.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/itdm.ss
;; Auto-generated from wireshark/epan/dissectors/packet-itdm.c

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
(def (dissect-itdm buffer)
  "Internal TDM"
  (try
    (let* (
           (timestamp (unwrap (read-u16be buffer 0)))
           (seqnum (unwrap (read-u8 buffer 2)))
           (last-pack (unwrap (read-u8 buffer 3)))
           (pktlen (unwrap (read-u16be buffer 3)))
           (uid (unwrap (read-u24be buffer 7)))
           (ctl-transid (unwrap (read-u32be buffer 10)))
           (ctl-flowid (unwrap (read-u24be buffer 15)))
           (ctl-emts (unwrap (read-u16be buffer 20)))
           (ctl-ptid (unwrap (read-u32be buffer 26)))
           (ctl-cksum (unwrap (read-u16be buffer 32)))
           )

      (ok (list
        (cons 'timestamp (list (cons 'raw timestamp) (cons 'formatted (number->string timestamp))))
        (cons 'seqnum (list (cons 'raw seqnum) (cons 'formatted (number->string seqnum))))
        (cons 'last-pack (list (cons 'raw last-pack) (cons 'formatted (number->string last-pack))))
        (cons 'pktlen (list (cons 'raw pktlen) (cons 'formatted (number->string pktlen))))
        (cons 'uid (list (cons 'raw uid) (cons 'formatted (number->string uid))))
        (cons 'ctl-transid (list (cons 'raw ctl-transid) (cons 'formatted (fmt-hex ctl-transid))))
        (cons 'ctl-flowid (list (cons 'raw ctl-flowid) (cons 'formatted (number->string ctl-flowid))))
        (cons 'ctl-emts (list (cons 'raw ctl-emts) (cons 'formatted (number->string ctl-emts))))
        (cons 'ctl-ptid (list (cons 'raw ctl-ptid) (cons 'formatted (fmt-hex ctl-ptid))))
        (cons 'ctl-cksum (list (cons 'raw ctl-cksum) (cons 'formatted (fmt-hex ctl-cksum))))
        )))

    (catch (e)
      (err (str "ITDM parse error: " e)))))

;; dissect-itdm: parse ITDM from bytevector
;; Returns (ok fields-alist) or (err message)