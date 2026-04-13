;;
;; packet-pktap.c
;; Routines for dissecting Apple's PKTAP header
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 2007 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/pktap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-pktap.c

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
(def (dissect-pktap buffer)
  "PKTAP packet header"
  (try
    (let* (
           (rectype (unwrap (read-u32be buffer 4)))
           (dlt (unwrap (read-u32be buffer 8)))
           (flags (unwrap (read-u32be buffer 36)))
           (pfamily (unwrap (read-u32be buffer 40)))
           (llhdrlen (unwrap (read-u32be buffer 44)))
           (lltrlrlen (unwrap (read-u32be buffer 48)))
           (pid (unwrap (read-u32be buffer 52)))
           (svc-class (unwrap (read-u32be buffer 76)))
           (iftype (unwrap (read-u16be buffer 80)))
           (ifunit (unwrap (read-u16be buffer 82)))
           (epid (unwrap (read-u32be buffer 84)))
           (hdrlen (unwrap (read-u32be buffer 88)))
           )

      (ok (list
        (cons 'rectype (list (cons 'raw rectype) (cons 'formatted (number->string rectype))))
        (cons 'dlt (list (cons 'raw dlt) (cons 'formatted (number->string dlt))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'pfamily (list (cons 'raw pfamily) (cons 'formatted (number->string pfamily))))
        (cons 'llhdrlen (list (cons 'raw llhdrlen) (cons 'formatted (number->string llhdrlen))))
        (cons 'lltrlrlen (list (cons 'raw lltrlrlen) (cons 'formatted (number->string lltrlrlen))))
        (cons 'pid (list (cons 'raw pid) (cons 'formatted (number->string pid))))
        (cons 'svc-class (list (cons 'raw svc-class) (cons 'formatted (number->string svc-class))))
        (cons 'iftype (list (cons 'raw iftype) (cons 'formatted (number->string iftype))))
        (cons 'ifunit (list (cons 'raw ifunit) (cons 'formatted (number->string ifunit))))
        (cons 'epid (list (cons 'raw epid) (cons 'formatted (number->string epid))))
        (cons 'hdrlen (list (cons 'raw hdrlen) (cons 'formatted (number->string hdrlen))))
        )))

    (catch (e)
      (err (str "PKTAP parse error: " e)))))

;; dissect-pktap: parse PKTAP from bytevector
;; Returns (ok fields-alist) or (err message)