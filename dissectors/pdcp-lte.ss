;; packet-pdcp-lte.c
;; Routines for LTE PDCP
;;
;; Martin Mathieson
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/pdcp-lte.ss
;; Auto-generated from wireshark/epan/dissectors/packet-pdcp_lte.c

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
(def (dissect-pdcp-lte buffer)
  "PDCP-LTE"
  (try
    (let* (
           (lte-security-setup-frame (unwrap (read-u32be buffer 0)))
           (lte-security (unwrap (slice buffer 0 1)))
           (lte-control-plane-reserved (unwrap (read-u8 buffer 0)))
           (lte-seq-num-5 (unwrap (read-u8 buffer 0)))
           (lte-data-control (unwrap (read-u8 buffer 0)))
           (lte-seq-num-7 (unwrap (read-u8 buffer 0)))
           (lte-reserved3 (unwrap (read-u8 buffer 0)))
           (lte-seq-num-12 (unwrap (read-u16be buffer 0)))
           (lte-seq-num-15 (unwrap (read-u16be buffer 2)))
           (lte-polling (unwrap (read-u8 buffer 4)))
           (lte-reserved5 (unwrap (read-u8 buffer 4)))
           (lte-seq-num-18 (unwrap (read-u24be buffer 4)))
           (lte-fms (unwrap (read-u16be buffer 22)))
           (lte-hrw (unwrap (read-u16be buffer 24)))
           (lte-nmp (unwrap (read-u16be buffer 25)))
           (lte-fms2 (unwrap (read-u16be buffer 27)))
           (lte-hrw2 (unwrap (read-u16be buffer 29)))
           (lte-reserved7 (unwrap (read-u8 buffer 31)))
           (lte-nmp2 (unwrap (read-u16be buffer 31)))
           (lte-fms3 (unwrap (read-u24be buffer 33)))
           (lte-hrw3 (unwrap (read-u24be buffer 36)))
           (lte-reserved8 (unwrap (read-u8 buffer 38)))
           (lte-nmp3 (unwrap (read-u24be buffer 38)))
           (lte-lsn (unwrap (read-u16be buffer 41)))
           (lte-reserved4 (unwrap (read-u16be buffer 43)))
           (lte-lsn2 (unwrap (read-u16be buffer 43)))
           (lte-reserved6 (unwrap (read-u8 buffer 45)))
           (lte-lsn3 (unwrap (read-u24be buffer 45)))
           )

      (ok (list
        (cons 'lte-security-setup-frame (list (cons 'raw lte-security-setup-frame) (cons 'formatted (number->string lte-security-setup-frame))))
        (cons 'lte-security (list (cons 'raw lte-security) (cons 'formatted (utf8->string lte-security))))
        (cons 'lte-control-plane-reserved (list (cons 'raw lte-control-plane-reserved) (cons 'formatted (number->string lte-control-plane-reserved))))
        (cons 'lte-seq-num-5 (list (cons 'raw lte-seq-num-5) (cons 'formatted (number->string lte-seq-num-5))))
        (cons 'lte-data-control (list (cons 'raw lte-data-control) (cons 'formatted (if (= lte-data-control 0) "False" "True"))))
        (cons 'lte-seq-num-7 (list (cons 'raw lte-seq-num-7) (cons 'formatted (number->string lte-seq-num-7))))
        (cons 'lte-reserved3 (list (cons 'raw lte-reserved3) (cons 'formatted (fmt-hex lte-reserved3))))
        (cons 'lte-seq-num-12 (list (cons 'raw lte-seq-num-12) (cons 'formatted (number->string lte-seq-num-12))))
        (cons 'lte-seq-num-15 (list (cons 'raw lte-seq-num-15) (cons 'formatted (number->string lte-seq-num-15))))
        (cons 'lte-polling (list (cons 'raw lte-polling) (cons 'formatted (number->string lte-polling))))
        (cons 'lte-reserved5 (list (cons 'raw lte-reserved5) (cons 'formatted (fmt-hex lte-reserved5))))
        (cons 'lte-seq-num-18 (list (cons 'raw lte-seq-num-18) (cons 'formatted (number->string lte-seq-num-18))))
        (cons 'lte-fms (list (cons 'raw lte-fms) (cons 'formatted (number->string lte-fms))))
        (cons 'lte-hrw (list (cons 'raw lte-hrw) (cons 'formatted (number->string lte-hrw))))
        (cons 'lte-nmp (list (cons 'raw lte-nmp) (cons 'formatted (number->string lte-nmp))))
        (cons 'lte-fms2 (list (cons 'raw lte-fms2) (cons 'formatted (number->string lte-fms2))))
        (cons 'lte-hrw2 (list (cons 'raw lte-hrw2) (cons 'formatted (number->string lte-hrw2))))
        (cons 'lte-reserved7 (list (cons 'raw lte-reserved7) (cons 'formatted (fmt-hex lte-reserved7))))
        (cons 'lte-nmp2 (list (cons 'raw lte-nmp2) (cons 'formatted (number->string lte-nmp2))))
        (cons 'lte-fms3 (list (cons 'raw lte-fms3) (cons 'formatted (number->string lte-fms3))))
        (cons 'lte-hrw3 (list (cons 'raw lte-hrw3) (cons 'formatted (number->string lte-hrw3))))
        (cons 'lte-reserved8 (list (cons 'raw lte-reserved8) (cons 'formatted (fmt-hex lte-reserved8))))
        (cons 'lte-nmp3 (list (cons 'raw lte-nmp3) (cons 'formatted (number->string lte-nmp3))))
        (cons 'lte-lsn (list (cons 'raw lte-lsn) (cons 'formatted (number->string lte-lsn))))
        (cons 'lte-reserved4 (list (cons 'raw lte-reserved4) (cons 'formatted (fmt-hex lte-reserved4))))
        (cons 'lte-lsn2 (list (cons 'raw lte-lsn2) (cons 'formatted (number->string lte-lsn2))))
        (cons 'lte-reserved6 (list (cons 'raw lte-reserved6) (cons 'formatted (fmt-hex lte-reserved6))))
        (cons 'lte-lsn3 (list (cons 'raw lte-lsn3) (cons 'formatted (number->string lte-lsn3))))
        )))

    (catch (e)
      (err (str "PDCP-LTE parse error: " e)))))

;; dissect-pdcp-lte: parse PDCP-LTE from bytevector
;; Returns (ok fields-alist) or (err message)