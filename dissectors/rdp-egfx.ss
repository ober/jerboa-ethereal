;; packet-rdp_egfx.c
;; Routines for the EGFX RDP channel
;; Copyright 2021, David Fort <contact@hardening-consulting.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rdp-egfx.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rdp_egfx.c

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
(def (dissect-rdp-egfx buffer)
  "RDP Graphic pipeline channel Protocol"
  (try
    (let* (
           (flags (unwrap (read-u16be buffer 2)))
           (pduLength (unwrap (read-u32be buffer 4)))
           (caps-capsSetCount (unwrap (read-u16be buffer 8)))
           (cap-length (unwrap (read-u32be buffer 22)))
           (reset-width (unwrap (read-u32be buffer 26)))
           (reset-height (unwrap (read-u32be buffer 30)))
           (reset-monitorCount (unwrap (read-u32be buffer 34)))
           (reset-monitorDefLeft (unwrap (read-u32be buffer 38)))
           (reset-monitorDefTop (unwrap (read-u32be buffer 42)))
           (reset-monitorDefRight (unwrap (read-u32be buffer 46)))
           (reset-monitorDefBottom (unwrap (read-u32be buffer 50)))
           (start-timestamp (unwrap (read-u32be buffer 58)))
           (start-frameid (unwrap (read-u32be buffer 62)))
           (end-frameid (unwrap (read-u32be buffer 62)))
           (ack-queue-depth (unwrap (read-u32be buffer 62)))
           (ack-frame-id (unwrap (read-u32be buffer 66)))
           (ack-total-decoded (unwrap (read-u32be buffer 70)))
           (ackqoe-frame-id (unwrap (read-u32be buffer 70)))
           (ackqoe-timestamp (unwrap (read-u32be buffer 74)))
           (ackqoe-timediffse (unwrap (read-u16be buffer 78)))
           (ackqoe-timediffedr (unwrap (read-u16be buffer 80)))
           (codeccontextid (unwrap (read-u32be buffer 100)))
           (cachekey (unwrap (read-u64be buffer 106)))
           (cacheslot (unwrap (read-u16be buffer 120)))
           (windowid (unwrap (read-u64be buffer 136)))
           (surfaceid (unwrap (read-u16be buffer 144)))
           (watermark-width (unwrap (read-u16be buffer 148)))
           (watermark-height (unwrap (read-u16be buffer 150)))
           (watermark-opacity (unwrap (read-u16be buffer 161)))
           (watermark-hpadding (unwrap (read-u16be buffer 169)))
           (watermark-vpadding (unwrap (read-u16be buffer 171)))
           (unknown-bytes (unwrap (slice buffer 173 8)))
           (watermark-imgsize (unwrap (read-u16be buffer 181)))
           )

      (ok (list
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'pduLength (list (cons 'raw pduLength) (cons 'formatted (number->string pduLength))))
        (cons 'caps-capsSetCount (list (cons 'raw caps-capsSetCount) (cons 'formatted (number->string caps-capsSetCount))))
        (cons 'cap-length (list (cons 'raw cap-length) (cons 'formatted (number->string cap-length))))
        (cons 'reset-width (list (cons 'raw reset-width) (cons 'formatted (number->string reset-width))))
        (cons 'reset-height (list (cons 'raw reset-height) (cons 'formatted (number->string reset-height))))
        (cons 'reset-monitorCount (list (cons 'raw reset-monitorCount) (cons 'formatted (number->string reset-monitorCount))))
        (cons 'reset-monitorDefLeft (list (cons 'raw reset-monitorDefLeft) (cons 'formatted (number->string reset-monitorDefLeft))))
        (cons 'reset-monitorDefTop (list (cons 'raw reset-monitorDefTop) (cons 'formatted (number->string reset-monitorDefTop))))
        (cons 'reset-monitorDefRight (list (cons 'raw reset-monitorDefRight) (cons 'formatted (number->string reset-monitorDefRight))))
        (cons 'reset-monitorDefBottom (list (cons 'raw reset-monitorDefBottom) (cons 'formatted (number->string reset-monitorDefBottom))))
        (cons 'start-timestamp (list (cons 'raw start-timestamp) (cons 'formatted (number->string start-timestamp))))
        (cons 'start-frameid (list (cons 'raw start-frameid) (cons 'formatted (fmt-hex start-frameid))))
        (cons 'end-frameid (list (cons 'raw end-frameid) (cons 'formatted (fmt-hex end-frameid))))
        (cons 'ack-queue-depth (list (cons 'raw ack-queue-depth) (cons 'formatted (number->string ack-queue-depth))))
        (cons 'ack-frame-id (list (cons 'raw ack-frame-id) (cons 'formatted (fmt-hex ack-frame-id))))
        (cons 'ack-total-decoded (list (cons 'raw ack-total-decoded) (cons 'formatted (number->string ack-total-decoded))))
        (cons 'ackqoe-frame-id (list (cons 'raw ackqoe-frame-id) (cons 'formatted (fmt-hex ackqoe-frame-id))))
        (cons 'ackqoe-timestamp (list (cons 'raw ackqoe-timestamp) (cons 'formatted (number->string ackqoe-timestamp))))
        (cons 'ackqoe-timediffse (list (cons 'raw ackqoe-timediffse) (cons 'formatted (number->string ackqoe-timediffse))))
        (cons 'ackqoe-timediffedr (list (cons 'raw ackqoe-timediffedr) (cons 'formatted (number->string ackqoe-timediffedr))))
        (cons 'codeccontextid (list (cons 'raw codeccontextid) (cons 'formatted (fmt-hex codeccontextid))))
        (cons 'cachekey (list (cons 'raw cachekey) (cons 'formatted (fmt-hex cachekey))))
        (cons 'cacheslot (list (cons 'raw cacheslot) (cons 'formatted (fmt-hex cacheslot))))
        (cons 'windowid (list (cons 'raw windowid) (cons 'formatted (fmt-hex windowid))))
        (cons 'surfaceid (list (cons 'raw surfaceid) (cons 'formatted (fmt-hex surfaceid))))
        (cons 'watermark-width (list (cons 'raw watermark-width) (cons 'formatted (number->string watermark-width))))
        (cons 'watermark-height (list (cons 'raw watermark-height) (cons 'formatted (number->string watermark-height))))
        (cons 'watermark-opacity (list (cons 'raw watermark-opacity) (cons 'formatted (fmt-hex watermark-opacity))))
        (cons 'watermark-hpadding (list (cons 'raw watermark-hpadding) (cons 'formatted (number->string watermark-hpadding))))
        (cons 'watermark-vpadding (list (cons 'raw watermark-vpadding) (cons 'formatted (number->string watermark-vpadding))))
        (cons 'unknown-bytes (list (cons 'raw unknown-bytes) (cons 'formatted (fmt-bytes unknown-bytes))))
        (cons 'watermark-imgsize (list (cons 'raw watermark-imgsize) (cons 'formatted (number->string watermark-imgsize))))
        )))

    (catch (e)
      (err (str "RDP-EGFX parse error: " e)))))

;; dissect-rdp-egfx: parse RDP-EGFX from bytevector
;; Returns (ok fields-alist) or (err message)