;; packet-mqtt-sn.c
;;
;; Routines for MQTT-SN v1.2 <http://mqtt.org>
;; https://mqtt.org/mqtt-specification/
;; https://groups.oasis-open.org/higherlogic/ws/public/download/66091/MQTT-SN_spec_v1.2.pdf
;;
;; Copyright (c) 2015, Jan-Hendrik Bolte <jabolte@uni-osnabrueck.de>
;; Copyright (c) 2015, University of Osnabrueck
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mqtt-sn.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mqtt_sn.c

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
(def (dissect-mqtt-sn buffer)
  "MQ Telemetry Transport Protocol for Sensor Networks"
  (try
    (let* (
           (flags (unwrap (read-u8 buffer 5)))
           (adv-interv (unwrap (read-u16be buffer 8)))
           (radius (unwrap (read-u8 buffer 8)))
           (gw-id (unwrap (read-u8 buffer 8)))
           (protocol-id (unwrap (read-u8 buffer 9)))
           (keep-alive (unwrap (read-u16be buffer 10)))
           (topic-id (unwrap (read-u16be buffer 30)))
           (topic (unwrap (slice buffer 30 2)))
           (msg-id (unwrap (read-u16be buffer 34)))
           (sleep-timer (unwrap (read-u16be buffer 34)))
           (control-info (unwrap (read-u8 buffer 34)))
           )

      (ok (list
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'adv-interv (list (cons 'raw adv-interv) (cons 'formatted (number->string adv-interv))))
        (cons 'radius (list (cons 'raw radius) (cons 'formatted (number->string radius))))
        (cons 'gw-id (list (cons 'raw gw-id) (cons 'formatted (number->string gw-id))))
        (cons 'protocol-id (list (cons 'raw protocol-id) (cons 'formatted (fmt-hex protocol-id))))
        (cons 'keep-alive (list (cons 'raw keep-alive) (cons 'formatted (number->string keep-alive))))
        (cons 'topic-id (list (cons 'raw topic-id) (cons 'formatted (number->string topic-id))))
        (cons 'topic (list (cons 'raw topic) (cons 'formatted (utf8->string topic))))
        (cons 'msg-id (list (cons 'raw msg-id) (cons 'formatted (number->string msg-id))))
        (cons 'sleep-timer (list (cons 'raw sleep-timer) (cons 'formatted (number->string sleep-timer))))
        (cons 'control-info (list (cons 'raw control-info) (cons 'formatted (fmt-hex control-info))))
        )))

    (catch (e)
      (err (str "MQTT-SN parse error: " e)))))

;; dissect-mqtt-sn: parse MQTT-SN from bytevector
;; Returns (ok fields-alist) or (err message)