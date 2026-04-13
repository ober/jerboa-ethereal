;; packet-stt.c
;;
;; Routines for Stateless Transport Tunneling (STT) packet dissection
;; Remi Vichery <remi.vichery@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Protocol ref:
;; https://tools.ietf.org/html/draft-davie-stt-07
;;

;; jerboa-ethereal/dissectors/stt.ss
;; Auto-generated from wireshark/epan/dissectors/packet-stt.c

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
(def (dissect-stt buffer)
  "Stateless Transport Tunneling"
  (try
    (let* (
           (tcp-flags (unwrap (read-u16be buffer 0)))
           (stream-id (unwrap (read-u16be buffer 0)))
           (dport (unwrap (read-u16be buffer 2)))
           (pkt-len (unwrap (read-u16be buffer 4)))
           (seg-off (unwrap (read-u16be buffer 6)))
           (pkt-id (unwrap (read-u32be buffer 8)))
           (tcp-data (unwrap (slice buffer 12 8)))
           (tcp-window (unwrap (read-u16be buffer 12)))
           (tcp-urg-ptr (unwrap (read-u16be buffer 16)))
           (flags (unwrap (read-u8 buffer 16)))
           (flag-rsvd (extract-bits flags 0xF0 4))
           (flag-tcp (extract-bits flags 0x8 3))
           (flag-ipv4 (extract-bits flags 0x4 2))
           (flag-partial (extract-bits flags 0x2 1))
           (flag-verified (extract-bits flags 0x1 0))
           (version (unwrap (read-u8 buffer 17)))
           (l4-offset (unwrap (read-u8 buffer 17)))
           (reserved-8 (unwrap (read-u8 buffer 17)))
           (mss (unwrap (read-u16be buffer 17)))
           (vlan (unwrap (read-u16be buffer 19)))
           (v (unwrap (read-u16be buffer 19)))
           (vlan-id (unwrap (read-u16be buffer 19)))
           (context-id (unwrap (read-u64be buffer 21)))
           (padding (unwrap (read-u16be buffer 29)))
           )

      (ok (list
        (cons 'tcp-flags (list (cons 'raw tcp-flags) (cons 'formatted (fmt-hex tcp-flags))))
        (cons 'stream-id (list (cons 'raw stream-id) (cons 'formatted (fmt-hex stream-id))))
        (cons 'dport (list (cons 'raw dport) (cons 'formatted (number->string dport))))
        (cons 'pkt-len (list (cons 'raw pkt-len) (cons 'formatted (number->string pkt-len))))
        (cons 'seg-off (list (cons 'raw seg-off) (cons 'formatted (number->string seg-off))))
        (cons 'pkt-id (list (cons 'raw pkt-id) (cons 'formatted (fmt-hex pkt-id))))
        (cons 'tcp-data (list (cons 'raw tcp-data) (cons 'formatted (fmt-bytes tcp-data))))
        (cons 'tcp-window (list (cons 'raw tcp-window) (cons 'formatted (number->string tcp-window))))
        (cons 'tcp-urg-ptr (list (cons 'raw tcp-urg-ptr) (cons 'formatted (number->string tcp-urg-ptr))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flag-rsvd (list (cons 'raw flag-rsvd) (cons 'formatted (if (= flag-rsvd 0) "Not set" "Set"))))
        (cons 'flag-tcp (list (cons 'raw flag-tcp) (cons 'formatted (if (= flag-tcp 0) "Not set" "Set"))))
        (cons 'flag-ipv4 (list (cons 'raw flag-ipv4) (cons 'formatted (if (= flag-ipv4 0) "Not set" "Set"))))
        (cons 'flag-partial (list (cons 'raw flag-partial) (cons 'formatted (if (= flag-partial 0) "Not set" "Set"))))
        (cons 'flag-verified (list (cons 'raw flag-verified) (cons 'formatted (if (= flag-verified 0) "Not set" "Set"))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'l4-offset (list (cons 'raw l4-offset) (cons 'formatted (number->string l4-offset))))
        (cons 'reserved-8 (list (cons 'raw reserved-8) (cons 'formatted (fmt-hex reserved-8))))
        (cons 'mss (list (cons 'raw mss) (cons 'formatted (number->string mss))))
        (cons 'vlan (list (cons 'raw vlan) (cons 'formatted (fmt-hex vlan))))
        (cons 'v (list (cons 'raw v) (cons 'formatted (number->string v))))
        (cons 'vlan-id (list (cons 'raw vlan-id) (cons 'formatted (number->string vlan-id))))
        (cons 'context-id (list (cons 'raw context-id) (cons 'formatted (fmt-hex context-id))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-hex padding))))
        )))

    (catch (e)
      (err (str "STT parse error: " e)))))

;; dissect-stt: parse STT from bytevector
;; Returns (ok fields-alist) or (err message)