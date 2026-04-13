;; packet-osi-options.c
;; Routines for the decode of ISO/OSI option part
;; Covers:
;; ISO  8473 CLNP (ConnectionLess Mode Network Service Protocol)
;; ISO 10589 ISIS (Intradomain Routing Information Exchange Protocol)
;; ISO  9542 ESIS (End System To Intermediate System Routing Exchange Protocol)
;;
;; Ralf Schneider <Ralf.Schneider@t-online.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/osi-options.ss
;; Auto-generated from wireshark/epan/dissectors/packet-osi_options.c

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
(def (dissect-osi-options buffer)
  "osi-options dissector"
  (try
    (let* (
           (options-qos-reserved (unwrap (read-u8 buffer 0)))
           (options-qos-sequencing-vs-transit-delay (unwrap (read-u8 buffer 0)))
           (options-congestion-experienced (unwrap (read-u8 buffer 0)))
           (options-transit-delay-vs-cost (unwrap (read-u8 buffer 0)))
           (options-residual-error-prob-vs-transit-delay (unwrap (read-u8 buffer 0)))
           (options-residual-error-prob-vs-cost (unwrap (read-u8 buffer 0)))
           (options-source-routing (unwrap (read-u8 buffer 0)))
           (options-route-recording (unwrap (read-u8 buffer 0)))
           (options-last-hop (unwrap (read-u8 buffer 0)))
           (options-rfd-field (unwrap (read-u8 buffer 0)))
           (options-priority (unwrap (read-u8 buffer 0)))
           (options-address-mask (unwrap (slice buffer 0 1)))
           (options-esct (unwrap (read-u16be buffer 0)))
           (options-padding (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'options-qos-reserved (list (cons 'raw options-qos-reserved) (cons 'formatted (number->string options-qos-reserved))))
        (cons 'options-qos-sequencing-vs-transit-delay (list (cons 'raw options-qos-sequencing-vs-transit-delay) (cons 'formatted (number->string options-qos-sequencing-vs-transit-delay))))
        (cons 'options-congestion-experienced (list (cons 'raw options-congestion-experienced) (cons 'formatted (number->string options-congestion-experienced))))
        (cons 'options-transit-delay-vs-cost (list (cons 'raw options-transit-delay-vs-cost) (cons 'formatted (number->string options-transit-delay-vs-cost))))
        (cons 'options-residual-error-prob-vs-transit-delay (list (cons 'raw options-residual-error-prob-vs-transit-delay) (cons 'formatted (number->string options-residual-error-prob-vs-transit-delay))))
        (cons 'options-residual-error-prob-vs-cost (list (cons 'raw options-residual-error-prob-vs-cost) (cons 'formatted (number->string options-residual-error-prob-vs-cost))))
        (cons 'options-source-routing (list (cons 'raw options-source-routing) (cons 'formatted (number->string options-source-routing))))
        (cons 'options-route-recording (list (cons 'raw options-route-recording) (cons 'formatted (number->string options-route-recording))))
        (cons 'options-last-hop (list (cons 'raw options-last-hop) (cons 'formatted (fmt-hex options-last-hop))))
        (cons 'options-rfd-field (list (cons 'raw options-rfd-field) (cons 'formatted (number->string options-rfd-field))))
        (cons 'options-priority (list (cons 'raw options-priority) (cons 'formatted (number->string options-priority))))
        (cons 'options-address-mask (list (cons 'raw options-address-mask) (cons 'formatted (fmt-bytes options-address-mask))))
        (cons 'options-esct (list (cons 'raw options-esct) (cons 'formatted (number->string options-esct))))
        (cons 'options-padding (list (cons 'raw options-padding) (cons 'formatted (fmt-bytes options-padding))))
        )))

    (catch (e)
      (err (str "OSI-OPTIONS parse error: " e)))))

;; dissect-osi-options: parse OSI-OPTIONS from bytevector
;; Returns (ok fields-alist) or (err message)