;; packet-simple.c
;; Routines for SIMPLE dissection
;; Copyright 2015 Peter Ross
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/simple.ss
;; Auto-generated from wireshark/epan/dissectors/packet-simple.c

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
(def (dissect-simple buffer)
  "Standard Interface for Multiple Platform Link Evaluation"
  (try
    (let* (
           (link16-rc (unwrap (read-u8 buffer 0)))
           (link16-network (unwrap (read-u8 buffer 0)))
           (link16-ssc2 (unwrap (read-u8 buffer 0)))
           (sync-byte-1 (unwrap (read-u8 buffer 0)))
           (sync-byte-2 (unwrap (read-u8 buffer 0)))
           (length (unwrap (read-u16be buffer 0)))
           (link16-ssc1 (unwrap (read-u16be buffer 2)))
           (sequence-number (unwrap (read-u16be buffer 2)))
           (link16-stn (unwrap (read-u16be buffer 4)))
           (packet-size (unwrap (read-u8 buffer 4)))
           (transit-time (unwrap (read-u16be buffer 4)))
           (link16-word-count (unwrap (read-u16be buffer 6)))
           (link16-loopback-id (unwrap (read-u16be buffer 8)))
           (status-word-count (unwrap (read-u8 buffer 20)))
           (status-name (unwrap (slice buffer 20 1)))
           (status-time-hours (unwrap (read-u8 buffer 20)))
           (status-node-id (unwrap (read-u8 buffer 20)))
           (status-time-seconds (unwrap (read-u8 buffer 20)))
           (status-time-minutes (unwrap (read-u8 buffer 20)))
           (status-node-entry-flag (unwrap (read-u8 buffer 20)))
           (status-relay-hop (unwrap (slice buffer 20 16)))
           (status-dx-file-id (unwrap (slice buffer 38 8)))
           (status-spare-1 (unwrap (slice buffer 46 2)))
           (status-link16-stn (unwrap (read-u16be buffer 48)))
           (status-spare-2 (unwrap (slice buffer 50 2)))
           (status-link11-pu (unwrap (read-u8 buffer 52)))
           (status-spare-3 (unwrap (slice buffer 52 4)))
           )

      (ok (list
        (cons 'link16-rc (list (cons 'raw link16-rc) (cons 'formatted (if (= link16-rc 0) "False" "True"))))
        (cons 'link16-network (list (cons 'raw link16-network) (cons 'formatted (number->string link16-network))))
        (cons 'link16-ssc2 (list (cons 'raw link16-ssc2) (cons 'formatted (number->string link16-ssc2))))
        (cons 'sync-byte-1 (list (cons 'raw sync-byte-1) (cons 'formatted (fmt-hex sync-byte-1))))
        (cons 'sync-byte-2 (list (cons 'raw sync-byte-2) (cons 'formatted (fmt-hex sync-byte-2))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'link16-ssc1 (list (cons 'raw link16-ssc1) (cons 'formatted (number->string link16-ssc1))))
        (cons 'sequence-number (list (cons 'raw sequence-number) (cons 'formatted (number->string sequence-number))))
        (cons 'link16-stn (list (cons 'raw link16-stn) (cons 'formatted (fmt-oct link16-stn))))
        (cons 'packet-size (list (cons 'raw packet-size) (cons 'formatted (number->string packet-size))))
        (cons 'transit-time (list (cons 'raw transit-time) (cons 'formatted (number->string transit-time))))
        (cons 'link16-word-count (list (cons 'raw link16-word-count) (cons 'formatted (number->string link16-word-count))))
        (cons 'link16-loopback-id (list (cons 'raw link16-loopback-id) (cons 'formatted (number->string link16-loopback-id))))
        (cons 'status-word-count (list (cons 'raw status-word-count) (cons 'formatted (number->string status-word-count))))
        (cons 'status-name (list (cons 'raw status-name) (cons 'formatted (utf8->string status-name))))
        (cons 'status-time-hours (list (cons 'raw status-time-hours) (cons 'formatted (number->string status-time-hours))))
        (cons 'status-node-id (list (cons 'raw status-node-id) (cons 'formatted (number->string status-node-id))))
        (cons 'status-time-seconds (list (cons 'raw status-time-seconds) (cons 'formatted (number->string status-time-seconds))))
        (cons 'status-time-minutes (list (cons 'raw status-time-minutes) (cons 'formatted (number->string status-time-minutes))))
        (cons 'status-node-entry-flag (list (cons 'raw status-node-entry-flag) (cons 'formatted (number->string status-node-entry-flag))))
        (cons 'status-relay-hop (list (cons 'raw status-relay-hop) (cons 'formatted (fmt-bytes status-relay-hop))))
        (cons 'status-dx-file-id (list (cons 'raw status-dx-file-id) (cons 'formatted (utf8->string status-dx-file-id))))
        (cons 'status-spare-1 (list (cons 'raw status-spare-1) (cons 'formatted (fmt-bytes status-spare-1))))
        (cons 'status-link16-stn (list (cons 'raw status-link16-stn) (cons 'formatted (fmt-oct status-link16-stn))))
        (cons 'status-spare-2 (list (cons 'raw status-spare-2) (cons 'formatted (fmt-bytes status-spare-2))))
        (cons 'status-link11-pu (list (cons 'raw status-link11-pu) (cons 'formatted (fmt-oct status-link11-pu))))
        (cons 'status-spare-3 (list (cons 'raw status-spare-3) (cons 'formatted (fmt-bytes status-spare-3))))
        )))

    (catch (e)
      (err (str "SIMPLE parse error: " e)))))

;; dissect-simple: parse SIMPLE from bytevector
;; Returns (ok fields-alist) or (err message)