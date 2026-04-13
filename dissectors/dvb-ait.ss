;; packet-dvb-ait.c
;; Routines for DVB Application Information Table (AIT) dissection
;; Copyright 2012-2013, Martin Kaiser <martin@kaiser.cx>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dvb-ait.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dvb_ait.c

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
(def (dissect-dvb-ait buffer)
  "DVB Application Information Table"
  (try
    (let* (
           (ait-descr-app-prof (unwrap (read-u16be buffer 0)))
           (ait-test-app-flag (unwrap (read-u8 buffer 0)))
           (ait-app-type (unwrap (read-u16be buffer 0)))
           (ait-descr-app-ver (unwrap (read-u24be buffer 2)))
           (ait-version-number (unwrap (read-u8 buffer 2)))
           (ait-current-next-indicator (unwrap (read-u8 buffer 2)))
           (ait-section-number (unwrap (read-u8 buffer 2)))
           (ait-last-section-number (unwrap (read-u8 buffer 2)))
           (ait-app-loop-len (unwrap (read-u16be buffer 4)))
           (ait-descr-app-svc-bound (unwrap (read-u8 buffer 5)))
           (ait-descr-app-prio (unwrap (read-u8 buffer 5)))
           (ait-descr-app-trpt-proto-label (unwrap (read-u8 buffer 5)))
           (ait-descr-app-name-lang (unwrap (slice buffer 5 3)))
           (ait-org-id (unwrap (read-u32be buffer 6)))
           (ait-app-id (unwrap (read-u16be buffer 10)))
           (ait-descr-trpt-proto-label (unwrap (read-u8 buffer 11)))
           (ait-descr-trpt-sel-remote (unwrap (read-u8 buffer 11)))
           (ait-descr-trpt-sel-onid (unwrap (read-u16be buffer 11)))
           (ait-descr-loop-len (unwrap (read-u16be buffer 12)))
           (ait-descr-trpt-sel-tsid (unwrap (read-u16be buffer 13)))
           (ait-descr-trpt-sel-svcid (unwrap (read-u16be buffer 15)))
           (ait-descr-trpt-sel-comp (unwrap (read-u8 buffer 17)))
           (ait-descr-trpt-sel-url-ext-cnt (unwrap (read-u8 buffer 18)))
           (ait-descr-trpt-sel-bytes (unwrap (slice buffer 19 1)))
           (ait-descr-len (unwrap (read-u8 buffer 19)))
           (ait-descr-sal-init-path (unwrap (slice buffer 19 1)))
           (ait-descr-data (unwrap (slice buffer 19 1)))
           (ait-descr-app-prof-len (unwrap (read-u8 buffer 20)))
           )

      (ok (list
        (cons 'ait-descr-app-prof (list (cons 'raw ait-descr-app-prof) (cons 'formatted (fmt-hex ait-descr-app-prof))))
        (cons 'ait-test-app-flag (list (cons 'raw ait-test-app-flag) (cons 'formatted (fmt-hex ait-test-app-flag))))
        (cons 'ait-app-type (list (cons 'raw ait-app-type) (cons 'formatted (fmt-hex ait-app-type))))
        (cons 'ait-descr-app-ver (list (cons 'raw ait-descr-app-ver) (cons 'formatted (fmt-hex ait-descr-app-ver))))
        (cons 'ait-version-number (list (cons 'raw ait-version-number) (cons 'formatted (fmt-hex ait-version-number))))
        (cons 'ait-current-next-indicator (list (cons 'raw ait-current-next-indicator) (cons 'formatted (number->string ait-current-next-indicator))))
        (cons 'ait-section-number (list (cons 'raw ait-section-number) (cons 'formatted (number->string ait-section-number))))
        (cons 'ait-last-section-number (list (cons 'raw ait-last-section-number) (cons 'formatted (number->string ait-last-section-number))))
        (cons 'ait-app-loop-len (list (cons 'raw ait-app-loop-len) (cons 'formatted (number->string ait-app-loop-len))))
        (cons 'ait-descr-app-svc-bound (list (cons 'raw ait-descr-app-svc-bound) (cons 'formatted (fmt-hex ait-descr-app-svc-bound))))
        (cons 'ait-descr-app-prio (list (cons 'raw ait-descr-app-prio) (cons 'formatted (fmt-hex ait-descr-app-prio))))
        (cons 'ait-descr-app-trpt-proto-label (list (cons 'raw ait-descr-app-trpt-proto-label) (cons 'formatted (fmt-hex ait-descr-app-trpt-proto-label))))
        (cons 'ait-descr-app-name-lang (list (cons 'raw ait-descr-app-name-lang) (cons 'formatted (utf8->string ait-descr-app-name-lang))))
        (cons 'ait-org-id (list (cons 'raw ait-org-id) (cons 'formatted (fmt-hex ait-org-id))))
        (cons 'ait-app-id (list (cons 'raw ait-app-id) (cons 'formatted (fmt-hex ait-app-id))))
        (cons 'ait-descr-trpt-proto-label (list (cons 'raw ait-descr-trpt-proto-label) (cons 'formatted (fmt-hex ait-descr-trpt-proto-label))))
        (cons 'ait-descr-trpt-sel-remote (list (cons 'raw ait-descr-trpt-sel-remote) (cons 'formatted (fmt-hex ait-descr-trpt-sel-remote))))
        (cons 'ait-descr-trpt-sel-onid (list (cons 'raw ait-descr-trpt-sel-onid) (cons 'formatted (fmt-hex ait-descr-trpt-sel-onid))))
        (cons 'ait-descr-loop-len (list (cons 'raw ait-descr-loop-len) (cons 'formatted (number->string ait-descr-loop-len))))
        (cons 'ait-descr-trpt-sel-tsid (list (cons 'raw ait-descr-trpt-sel-tsid) (cons 'formatted (fmt-hex ait-descr-trpt-sel-tsid))))
        (cons 'ait-descr-trpt-sel-svcid (list (cons 'raw ait-descr-trpt-sel-svcid) (cons 'formatted (fmt-hex ait-descr-trpt-sel-svcid))))
        (cons 'ait-descr-trpt-sel-comp (list (cons 'raw ait-descr-trpt-sel-comp) (cons 'formatted (fmt-hex ait-descr-trpt-sel-comp))))
        (cons 'ait-descr-trpt-sel-url-ext-cnt (list (cons 'raw ait-descr-trpt-sel-url-ext-cnt) (cons 'formatted (number->string ait-descr-trpt-sel-url-ext-cnt))))
        (cons 'ait-descr-trpt-sel-bytes (list (cons 'raw ait-descr-trpt-sel-bytes) (cons 'formatted (fmt-bytes ait-descr-trpt-sel-bytes))))
        (cons 'ait-descr-len (list (cons 'raw ait-descr-len) (cons 'formatted (number->string ait-descr-len))))
        (cons 'ait-descr-sal-init-path (list (cons 'raw ait-descr-sal-init-path) (cons 'formatted (utf8->string ait-descr-sal-init-path))))
        (cons 'ait-descr-data (list (cons 'raw ait-descr-data) (cons 'formatted (fmt-bytes ait-descr-data))))
        (cons 'ait-descr-app-prof-len (list (cons 'raw ait-descr-app-prof-len) (cons 'formatted (number->string ait-descr-app-prof-len))))
        )))

    (catch (e)
      (err (str "DVB-AIT parse error: " e)))))

;; dissect-dvb-ait: parse DVB-AIT from bytevector
;; Returns (ok fields-alist) or (err message)