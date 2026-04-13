;; packet-zbee-direct.c
;; Dissector routines for the ZigBee Direct
;; Copyright 2021 DSR Corporation, http://dsr-wireless.com/
;;
;; Zigbee Direct Specification, 1.1
;; Connectivity Standards Alliance Document 20-27688-041
;; https://csa-iot.org/all-solutions/zigbee/zigbee-direct/
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/zbee-direct.ss
;; Auto-generated from wireshark/epan/dissectors/packet-zbee_direct.c

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
(def (dissect-zbee-direct buffer)
  "ZigBee Direct"
  (try
    (let* (
           (direct-comm-permit-time (unwrap (read-u8 buffer 0)))
           (direct-comm-rm-children (unwrap (read-u8 buffer 0)))
           (direct-comm-identify-time (unwrap (read-u16be buffer 0)))
           (direct-comm-fb-endpoint (unwrap (read-u8 buffer 0)))
           (direct-info-zdd-ieee (unwrap (read-u64be buffer 1)))
           (direct-comm-rejoin (unwrap (read-u8 buffer 1)))
           (direct-comm-fb-initiator (unwrap (read-u8 buffer 1)))
           (direct-info-zvd-ieee (unwrap (read-u64be buffer 9)))
           (direct-info-encryption (unwrap (read-u8 buffer 17)))
           )

      (ok (list
        (cons 'direct-comm-permit-time (list (cons 'raw direct-comm-permit-time) (cons 'formatted (number->string direct-comm-permit-time))))
        (cons 'direct-comm-rm-children (list (cons 'raw direct-comm-rm-children) (cons 'formatted (number->string direct-comm-rm-children))))
        (cons 'direct-comm-identify-time (list (cons 'raw direct-comm-identify-time) (cons 'formatted (number->string direct-comm-identify-time))))
        (cons 'direct-comm-fb-endpoint (list (cons 'raw direct-comm-fb-endpoint) (cons 'formatted (number->string direct-comm-fb-endpoint))))
        (cons 'direct-info-zdd-ieee (list (cons 'raw direct-info-zdd-ieee) (cons 'formatted (fmt-hex direct-info-zdd-ieee))))
        (cons 'direct-comm-rejoin (list (cons 'raw direct-comm-rejoin) (cons 'formatted (number->string direct-comm-rejoin))))
        (cons 'direct-comm-fb-initiator (list (cons 'raw direct-comm-fb-initiator) (cons 'formatted (number->string direct-comm-fb-initiator))))
        (cons 'direct-info-zvd-ieee (list (cons 'raw direct-info-zvd-ieee) (cons 'formatted (fmt-hex direct-info-zvd-ieee))))
        (cons 'direct-info-encryption (list (cons 'raw direct-info-encryption) (cons 'formatted (number->string direct-info-encryption))))
        )))

    (catch (e)
      (err (str "ZBEE-DIRECT parse error: " e)))))

;; dissect-zbee-direct: parse ZBEE-DIRECT from bytevector
;; Returns (ok fields-alist) or (err message)