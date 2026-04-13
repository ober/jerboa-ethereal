;;
;; packet-fip.c
;; Routines for FIP dissection - FCoE Initialization Protocol
;; Copyright (c) 2008 Cisco Systems, Inc. (jeykholt@cisco.com)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Based on packet-fcoe.c, Copyright 2006, Nuova Systems, (jre@nuovasystems.com)
;; Based on packet-fcp.c, Copyright 2001, Dinesh G Dutt (ddutt@cisco.com)
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/fip.ss
;; Auto-generated from wireshark/epan/dissectors/packet-fip.c

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
(def (dissect-fip buffer)
  "FCoE Initialization Protocol"
  (try
    (let* (
           (reserved12 (unwrap (read-u16be buffer 0)))
           (ver (unwrap (read-u8 buffer 0)))
           (reserved8 (unwrap (read-u8 buffer 4)))
           (hex-subcode (unwrap (read-u8 buffer 5)))
           (dlen (unwrap (read-u16be buffer 6)))
           (flags (unwrap (read-u16be buffer 8)))
           (flag-fpma (extract-bits flags 0x0 0))
           (flag-spma (extract-bits flags 0x0 0))
           (flag-rec-p2p (extract-bits flags 0x0 0))
           (flag-avail (extract-bits flags 0x0 0))
           (flag-sol (extract-bits flags 0x0 0))
           (flag-fport (extract-bits flags 0x0 0))
           )

      (ok (list
        (cons 'reserved12 (list (cons 'raw reserved12) (cons 'formatted (fmt-hex reserved12))))
        (cons 'ver (list (cons 'raw ver) (cons 'formatted (number->string ver))))
        (cons 'reserved8 (list (cons 'raw reserved8) (cons 'formatted (fmt-hex reserved8))))
        (cons 'hex-subcode (list (cons 'raw hex-subcode) (cons 'formatted (fmt-hex hex-subcode))))
        (cons 'dlen (list (cons 'raw dlen) (cons 'formatted (number->string dlen))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flag-fpma (list (cons 'raw flag-fpma) (cons 'formatted (if (= flag-fpma 0) "Not set" "Set"))))
        (cons 'flag-spma (list (cons 'raw flag-spma) (cons 'formatted (if (= flag-spma 0) "Not set" "Set"))))
        (cons 'flag-rec-p2p (list (cons 'raw flag-rec-p2p) (cons 'formatted (if (= flag-rec-p2p 0) "Not set" "Set"))))
        (cons 'flag-avail (list (cons 'raw flag-avail) (cons 'formatted (if (= flag-avail 0) "Not set" "Set"))))
        (cons 'flag-sol (list (cons 'raw flag-sol) (cons 'formatted (if (= flag-sol 0) "Not set" "Set"))))
        (cons 'flag-fport (list (cons 'raw flag-fport) (cons 'formatted (if (= flag-fport 0) "Not set" "Set"))))
        )))

    (catch (e)
      (err (str "FIP parse error: " e)))))

;; dissect-fip: parse FIP from bytevector
;; Returns (ok fields-alist) or (err message)