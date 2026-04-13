;; packet-bat.c
;; Routines for B.A.T.M.A.N. Layer 3 dissection
;; Copyright 2008-2010 Sven Eckelmann <sven@narfation.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bat.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bat.c

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
(def (dissect-bat buffer)
  "B.A.T.M.A.N. Layer 3 Protocol"
  (try
    (let* (
           (batman-hna-network (unwrap (read-u32be buffer 0)))
           (batman-version (unwrap (read-u8 buffer 0)))
           (vis-vis-orig (unwrap (read-u32be buffer 0)))
           (vis-tq-v23 (unwrap (read-u8 buffer 1)))
           (vis-netmask (unwrap (read-u8 buffer 1)))
           (vis-tq-v22 (unwrap (read-u16be buffer 1)))
           (batman-flags (unwrap (read-u8 buffer 1)))
           (batman-flags-unidirectional (extract-bits batman-flags 0x80 7))
           (batman-flags-directlink (extract-bits batman-flags 0x40 6))
           (batman-ttl (unwrap (read-u8 buffer 2)))
           (vis-data-ip (unwrap (read-u32be buffer 3)))
           (batman-gwflags (unwrap (read-u8 buffer 3)))
           (batman-hna-netmask (unwrap (read-u8 buffer 4)))
           (batman-seqno (unwrap (read-u16be buffer 4)))
           (vis-version (unwrap (read-u8 buffer 4)))
           (vis-gwflags (unwrap (read-u8 buffer 5)))
           (batman-gwport (unwrap (read-u16be buffer 6)))
           (max-tq-v22 (unwrap (read-u16be buffer 6)))
           (max-tq-v23 (unwrap (read-u8 buffer 6)))
           (batman-orig (unwrap (read-u32be buffer 8)))
           (batman-old-orig (unwrap (read-u32be buffer 12)))
           (batman-tq (unwrap (read-u8 buffer 16)))
           (batman-hna-len (unwrap (read-u8 buffer 17)))
           )

      (ok (list
        (cons 'batman-hna-network (list (cons 'raw batman-hna-network) (cons 'formatted (fmt-ipv4 batman-hna-network))))
        (cons 'batman-version (list (cons 'raw batman-version) (cons 'formatted (number->string batman-version))))
        (cons 'vis-vis-orig (list (cons 'raw vis-vis-orig) (cons 'formatted (fmt-ipv4 vis-vis-orig))))
        (cons 'vis-tq-v23 (list (cons 'raw vis-tq-v23) (cons 'formatted (number->string vis-tq-v23))))
        (cons 'vis-netmask (list (cons 'raw vis-netmask) (cons 'formatted (number->string vis-netmask))))
        (cons 'vis-tq-v22 (list (cons 'raw vis-tq-v22) (cons 'formatted (number->string vis-tq-v22))))
        (cons 'batman-flags (list (cons 'raw batman-flags) (cons 'formatted (fmt-hex batman-flags))))
        (cons 'batman-flags-unidirectional (list (cons 'raw batman-flags-unidirectional) (cons 'formatted (if (= batman-flags-unidirectional 0) "Not set" "Set"))))
        (cons 'batman-flags-directlink (list (cons 'raw batman-flags-directlink) (cons 'formatted (if (= batman-flags-directlink 0) "Not set" "Set"))))
        (cons 'batman-ttl (list (cons 'raw batman-ttl) (cons 'formatted (number->string batman-ttl))))
        (cons 'vis-data-ip (list (cons 'raw vis-data-ip) (cons 'formatted (fmt-ipv4 vis-data-ip))))
        (cons 'batman-gwflags (list (cons 'raw batman-gwflags) (cons 'formatted (fmt-hex batman-gwflags))))
        (cons 'batman-hna-netmask (list (cons 'raw batman-hna-netmask) (cons 'formatted (number->string batman-hna-netmask))))
        (cons 'batman-seqno (list (cons 'raw batman-seqno) (cons 'formatted (number->string batman-seqno))))
        (cons 'vis-version (list (cons 'raw vis-version) (cons 'formatted (number->string vis-version))))
        (cons 'vis-gwflags (list (cons 'raw vis-gwflags) (cons 'formatted (fmt-hex vis-gwflags))))
        (cons 'batman-gwport (list (cons 'raw batman-gwport) (cons 'formatted (number->string batman-gwport))))
        (cons 'max-tq-v22 (list (cons 'raw max-tq-v22) (cons 'formatted (number->string max-tq-v22))))
        (cons 'max-tq-v23 (list (cons 'raw max-tq-v23) (cons 'formatted (number->string max-tq-v23))))
        (cons 'batman-orig (list (cons 'raw batman-orig) (cons 'formatted (fmt-ipv4 batman-orig))))
        (cons 'batman-old-orig (list (cons 'raw batman-old-orig) (cons 'formatted (fmt-ipv4 batman-old-orig))))
        (cons 'batman-tq (list (cons 'raw batman-tq) (cons 'formatted (number->string batman-tq))))
        (cons 'batman-hna-len (list (cons 'raw batman-hna-len) (cons 'formatted (number->string batman-hna-len))))
        )))

    (catch (e)
      (err (str "BAT parse error: " e)))))

;; dissect-bat: parse BAT from bytevector
;; Returns (ok fields-alist) or (err message)