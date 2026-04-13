;; packet-c2p.c
;; Commsignia Capture Protocol dissector
;; Copyright 2025, (C) Commsignia Ltd.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/c2p.ss
;; Auto-generated from wireshark/epan/dissectors/packet-c2p.c

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
(def (dissect-c2p buffer)
  "c2p dissector"
  (try
    (let* (
           (sps-desc (unwrap (read-u8 buffer 0)))
           (socket-index-desc (unwrap (read-u8 buffer 0)))
           (nav-fix-is-valid-desc (unwrap (read-u8 buffer 0)))
           (sti-length-desc (unwrap (read-u32be buffer 0)))
           (version-desc (unwrap (read-u8 buffer 0)))
           (sps-port-desc (unwrap (read-u16be buffer 1)))
           (ethertype-desc (unwrap (read-u16be buffer 1)))
           (used-interface-desc (unwrap (read-u8 buffer 2)))
           (event-port-desc (unwrap (read-u16be buffer 3)))
           (antenna-desc (unwrap (read-u8 buffer 4)))
           (bw-res-v2xid-desc (unwrap (read-u32be buffer 9)))
           (bw-res-tx-reservation-size-bytes-desc (unwrap (read-u32be buffer 17)))
           )

      (ok (list
        (cons 'sps-desc (list (cons 'raw sps-desc) (cons 'formatted (number->string sps-desc))))
        (cons 'socket-index-desc (list (cons 'raw socket-index-desc) (cons 'formatted (number->string socket-index-desc))))
        (cons 'nav-fix-is-valid-desc (list (cons 'raw nav-fix-is-valid-desc) (cons 'formatted (number->string nav-fix-is-valid-desc))))
        (cons 'sti-length-desc (list (cons 'raw sti-length-desc) (cons 'formatted (number->string sti-length-desc))))
        (cons 'version-desc (list (cons 'raw version-desc) (cons 'formatted (number->string version-desc))))
        (cons 'sps-port-desc (list (cons 'raw sps-port-desc) (cons 'formatted (number->string sps-port-desc))))
        (cons 'ethertype-desc (list (cons 'raw ethertype-desc) (cons 'formatted (fmt-hex ethertype-desc))))
        (cons 'used-interface-desc (list (cons 'raw used-interface-desc) (cons 'formatted (number->string used-interface-desc))))
        (cons 'event-port-desc (list (cons 'raw event-port-desc) (cons 'formatted (number->string event-port-desc))))
        (cons 'antenna-desc (list (cons 'raw antenna-desc) (cons 'formatted (number->string antenna-desc))))
        (cons 'bw-res-v2xid-desc (list (cons 'raw bw-res-v2xid-desc) (cons 'formatted (number->string bw-res-v2xid-desc))))
        (cons 'bw-res-tx-reservation-size-bytes-desc (list (cons 'raw bw-res-tx-reservation-size-bytes-desc) (cons 'formatted (number->string bw-res-tx-reservation-size-bytes-desc))))
        )))

    (catch (e)
      (err (str "C2P parse error: " e)))))

;; dissect-c2p: parse C2P from bytevector
;; Returns (ok fields-alist) or (err message)