;; packet-ipmi-chassis.c
;; Sub-dissectors for IPMI messages (netFn=Chassis)
;; Copyright 2007-2008, Alexey Neyman, Pigeon Point Systems <avn@pigeonpoint.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ipmi-chassis.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ipmi_chassis.c

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
(def (dissect-ipmi-chassis buffer)
  "ipmi-chassis dissector"
  (try
    (let* (
           (chs-0f-minpercnt (unwrap (read-u8 buffer 0)))
           (chs-09-rq-param-select (unwrap (read-u8 buffer 0)))
           (chs-08-selector (unwrap (read-u8 buffer 0)))
           (chs-08-valid (unwrap (read-u8 buffer 0)))
           (chs-bo07-block-selector (unwrap (read-u8 buffer 0)))
           (chs-bo04-write-mask (unwrap (read-u8 buffer 0)))
           (chs-bo01-spsel (unwrap (read-u8 buffer 0)))
           (chs-0f-counter (unwrap (read-u32be buffer 1)))
           (chs-09-rs-param-select (unwrap (read-u8 buffer 1)))
           (chs-09-rs-valid (unwrap (read-u8 buffer 1)))
           (chs-09-rq-set-select (unwrap (read-u8 buffer 1)))
           (chs-05-fru-dev-addr (unwrap (read-u8 buffer 1)))
           (chs-00-fru-dev-addr (unwrap (read-u8 buffer 1)))
           (chs-bo07-block-data (unwrap (slice buffer 1 1)))
           (chs-bo06-session-id (unwrap (read-u32be buffer 1)))
           (chs-09-rs-param-data (unwrap (slice buffer 2 1)))
           (chs-09-rq-block-select (unwrap (read-u8 buffer 2)))
           (chs-05-sdr-dev-addr (unwrap (read-u8 buffer 2)))
           (chs-00-sdr-dev-addr (unwrap (read-u8 buffer 2)))
           (chs-05-sel-dev-addr (unwrap (read-u8 buffer 3)))
           (chs-00-sel-dev-addr (unwrap (read-u8 buffer 3)))
           (chs-05-sm-dev-addr (unwrap (read-u8 buffer 4)))
           (chs-00-sm-dev-addr (unwrap (read-u8 buffer 4)))
           (chs-bo05-byte5 (unwrap (read-u8 buffer 4)))
           (chs-05-bridge-dev-addr (unwrap (read-u8 buffer 5)))
           (chs-00-bridge-dev-addr (unwrap (read-u8 buffer 5)))
           )

      (ok (list
        (cons 'chs-0f-minpercnt (list (cons 'raw chs-0f-minpercnt) (cons 'formatted (number->string chs-0f-minpercnt))))
        (cons 'chs-09-rq-param-select (list (cons 'raw chs-09-rq-param-select) (cons 'formatted (fmt-hex chs-09-rq-param-select))))
        (cons 'chs-08-selector (list (cons 'raw chs-08-selector) (cons 'formatted (fmt-hex chs-08-selector))))
        (cons 'chs-08-valid (list (cons 'raw chs-08-valid) (cons 'formatted (if (= chs-08-valid 0) "False" "True"))))
        (cons 'chs-bo07-block-selector (list (cons 'raw chs-bo07-block-selector) (cons 'formatted (fmt-hex chs-bo07-block-selector))))
        (cons 'chs-bo04-write-mask (list (cons 'raw chs-bo04-write-mask) (cons 'formatted (fmt-hex chs-bo04-write-mask))))
        (cons 'chs-bo01-spsel (list (cons 'raw chs-bo01-spsel) (cons 'formatted (fmt-hex chs-bo01-spsel))))
        (cons 'chs-0f-counter (list (cons 'raw chs-0f-counter) (cons 'formatted (number->string chs-0f-counter))))
        (cons 'chs-09-rs-param-select (list (cons 'raw chs-09-rs-param-select) (cons 'formatted (fmt-hex chs-09-rs-param-select))))
        (cons 'chs-09-rs-valid (list (cons 'raw chs-09-rs-valid) (cons 'formatted (if (= chs-09-rs-valid 0) "False" "True"))))
        (cons 'chs-09-rq-set-select (list (cons 'raw chs-09-rq-set-select) (cons 'formatted (fmt-hex chs-09-rq-set-select))))
        (cons 'chs-05-fru-dev-addr (list (cons 'raw chs-05-fru-dev-addr) (cons 'formatted (fmt-hex chs-05-fru-dev-addr))))
        (cons 'chs-00-fru-dev-addr (list (cons 'raw chs-00-fru-dev-addr) (cons 'formatted (fmt-hex chs-00-fru-dev-addr))))
        (cons 'chs-bo07-block-data (list (cons 'raw chs-bo07-block-data) (cons 'formatted (fmt-bytes chs-bo07-block-data))))
        (cons 'chs-bo06-session-id (list (cons 'raw chs-bo06-session-id) (cons 'formatted (number->string chs-bo06-session-id))))
        (cons 'chs-09-rs-param-data (list (cons 'raw chs-09-rs-param-data) (cons 'formatted (fmt-bytes chs-09-rs-param-data))))
        (cons 'chs-09-rq-block-select (list (cons 'raw chs-09-rq-block-select) (cons 'formatted (fmt-hex chs-09-rq-block-select))))
        (cons 'chs-05-sdr-dev-addr (list (cons 'raw chs-05-sdr-dev-addr) (cons 'formatted (fmt-hex chs-05-sdr-dev-addr))))
        (cons 'chs-00-sdr-dev-addr (list (cons 'raw chs-00-sdr-dev-addr) (cons 'formatted (fmt-hex chs-00-sdr-dev-addr))))
        (cons 'chs-05-sel-dev-addr (list (cons 'raw chs-05-sel-dev-addr) (cons 'formatted (fmt-hex chs-05-sel-dev-addr))))
        (cons 'chs-00-sel-dev-addr (list (cons 'raw chs-00-sel-dev-addr) (cons 'formatted (fmt-hex chs-00-sel-dev-addr))))
        (cons 'chs-05-sm-dev-addr (list (cons 'raw chs-05-sm-dev-addr) (cons 'formatted (fmt-hex chs-05-sm-dev-addr))))
        (cons 'chs-00-sm-dev-addr (list (cons 'raw chs-00-sm-dev-addr) (cons 'formatted (fmt-hex chs-00-sm-dev-addr))))
        (cons 'chs-bo05-byte5 (list (cons 'raw chs-bo05-byte5) (cons 'formatted (fmt-hex chs-bo05-byte5))))
        (cons 'chs-05-bridge-dev-addr (list (cons 'raw chs-05-bridge-dev-addr) (cons 'formatted (fmt-hex chs-05-bridge-dev-addr))))
        (cons 'chs-00-bridge-dev-addr (list (cons 'raw chs-00-bridge-dev-addr) (cons 'formatted (fmt-hex chs-00-bridge-dev-addr))))
        )))

    (catch (e)
      (err (str "IPMI-CHASSIS parse error: " e)))))

;; dissect-ipmi-chassis: parse IPMI-CHASSIS from bytevector
;; Returns (ok fields-alist) or (err message)