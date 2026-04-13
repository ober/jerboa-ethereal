;; packet-bt-tracker.c
;; Routines for BitTorrent Tracker over UDP dissection
;; Copyright 2023, Ivan Nardi <nardi.ivan@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bt-tracker.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bt_tracker.c

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
(def (dissect-bt-tracker buffer)
  "BitTorrent Tracker"
  (try
    (let* (
           (tracker-extension-urldata (unwrap (slice buffer 2 1)))
           (tracker-extension-unknown (unwrap (slice buffer 2 1)))
           (tracker-protocol-id (unwrap (read-u64be buffer 2)))
           (tracker-peer-id (unwrap (slice buffer 70 20)))
           (tracker-downloaded (unwrap (read-u64be buffer 90)))
           (tracker-left (unwrap (read-u64be buffer 98)))
           (tracker-uploaded (unwrap (read-u64be buffer 106)))
           (tracker-ip-address (unwrap (read-u32be buffer 118)))
           (tracker-key (unwrap (read-u32be buffer 122)))
           (tracker-num-want (unwrap (read-u32be buffer 126)))
           (tracker-port (unwrap (read-u16be buffer 130)))
           (tracker-interval (unwrap (read-u32be buffer 140)))
           (tracker-tr-ip6 (unwrap (slice buffer 152 16)))
           (tracker-tr-port (unwrap (read-u16be buffer 152)))
           (tracker-tr-ip (unwrap (read-u32be buffer 152)))
           (tracker-connection-id (unwrap (read-u64be buffer 152)))
           (tracker-info-hash (unwrap (slice buffer 168 20)))
           (tracker-seeders (unwrap (read-u32be buffer 196)))
           (tracker-completed (unwrap (read-u32be buffer 200)))
           (tracker-leechers (unwrap (read-u32be buffer 204)))
           (tracker-transaction-id (unwrap (read-u32be buffer 212)))
           (tracker-error-msg (unwrap (slice buffer 216 1)))
           )

      (ok (list
        (cons 'tracker-extension-urldata (list (cons 'raw tracker-extension-urldata) (cons 'formatted (utf8->string tracker-extension-urldata))))
        (cons 'tracker-extension-unknown (list (cons 'raw tracker-extension-unknown) (cons 'formatted (fmt-bytes tracker-extension-unknown))))
        (cons 'tracker-protocol-id (list (cons 'raw tracker-protocol-id) (cons 'formatted (fmt-hex tracker-protocol-id))))
        (cons 'tracker-peer-id (list (cons 'raw tracker-peer-id) (cons 'formatted (fmt-bytes tracker-peer-id))))
        (cons 'tracker-downloaded (list (cons 'raw tracker-downloaded) (cons 'formatted (number->string tracker-downloaded))))
        (cons 'tracker-left (list (cons 'raw tracker-left) (cons 'formatted (number->string tracker-left))))
        (cons 'tracker-uploaded (list (cons 'raw tracker-uploaded) (cons 'formatted (number->string tracker-uploaded))))
        (cons 'tracker-ip-address (list (cons 'raw tracker-ip-address) (cons 'formatted (fmt-ipv4 tracker-ip-address))))
        (cons 'tracker-key (list (cons 'raw tracker-key) (cons 'formatted (number->string tracker-key))))
        (cons 'tracker-num-want (list (cons 'raw tracker-num-want) (cons 'formatted (number->string tracker-num-want))))
        (cons 'tracker-port (list (cons 'raw tracker-port) (cons 'formatted (number->string tracker-port))))
        (cons 'tracker-interval (list (cons 'raw tracker-interval) (cons 'formatted (number->string tracker-interval))))
        (cons 'tracker-tr-ip6 (list (cons 'raw tracker-tr-ip6) (cons 'formatted (fmt-ipv6-address tracker-tr-ip6))))
        (cons 'tracker-tr-port (list (cons 'raw tracker-tr-port) (cons 'formatted (fmt-port tracker-tr-port))))
        (cons 'tracker-tr-ip (list (cons 'raw tracker-tr-ip) (cons 'formatted (fmt-ipv4 tracker-tr-ip))))
        (cons 'tracker-connection-id (list (cons 'raw tracker-connection-id) (cons 'formatted (number->string tracker-connection-id))))
        (cons 'tracker-info-hash (list (cons 'raw tracker-info-hash) (cons 'formatted (fmt-bytes tracker-info-hash))))
        (cons 'tracker-seeders (list (cons 'raw tracker-seeders) (cons 'formatted (number->string tracker-seeders))))
        (cons 'tracker-completed (list (cons 'raw tracker-completed) (cons 'formatted (number->string tracker-completed))))
        (cons 'tracker-leechers (list (cons 'raw tracker-leechers) (cons 'formatted (number->string tracker-leechers))))
        (cons 'tracker-transaction-id (list (cons 'raw tracker-transaction-id) (cons 'formatted (number->string tracker-transaction-id))))
        (cons 'tracker-error-msg (list (cons 'raw tracker-error-msg) (cons 'formatted (utf8->string tracker-error-msg))))
        )))

    (catch (e)
      (err (str "BT-TRACKER parse error: " e)))))

;; dissect-bt-tracker: parse BT-TRACKER from bytevector
;; Returns (ok fields-alist) or (err message)