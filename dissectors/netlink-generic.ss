;; packet-netlink-generic.c
;; Dissector for Linux Generic Netlink.
;;
;; Copyright (c) 2017, Peter Wu <peter@lekensteyn.nl>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/netlink-generic.ss
;; Auto-generated from wireshark/epan/dissectors/packet-netlink_generic.c

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
(def (dissect-netlink-generic buffer)
  "Linux Generic Netlink protocol"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (ctrl-group-name (unwrap (slice buffer 8 1)))
           (ctrl-group-id (unwrap (read-u32be buffer 8)))
           (ctrl-family-id (unwrap (read-u16be buffer 12)))
           (ctrl-family-name (unwrap (slice buffer 14 1)))
           (ctrl-version (unwrap (read-u32be buffer 14)))
           (ctrl-hdrsize (unwrap (read-u32be buffer 18)))
           (ctrl-maxattr (unwrap (read-u32be buffer 22)))
           (ctrl-op-id (unwrap (read-u32be buffer 26)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'ctrl-group-name (list (cons 'raw ctrl-group-name) (cons 'formatted (utf8->string ctrl-group-name))))
        (cons 'ctrl-group-id (list (cons 'raw ctrl-group-id) (cons 'formatted (fmt-hex ctrl-group-id))))
        (cons 'ctrl-family-id (list (cons 'raw ctrl-family-id) (cons 'formatted (fmt-hex ctrl-family-id))))
        (cons 'ctrl-family-name (list (cons 'raw ctrl-family-name) (cons 'formatted (utf8->string ctrl-family-name))))
        (cons 'ctrl-version (list (cons 'raw ctrl-version) (cons 'formatted (number->string ctrl-version))))
        (cons 'ctrl-hdrsize (list (cons 'raw ctrl-hdrsize) (cons 'formatted (number->string ctrl-hdrsize))))
        (cons 'ctrl-maxattr (list (cons 'raw ctrl-maxattr) (cons 'formatted (number->string ctrl-maxattr))))
        (cons 'ctrl-op-id (list (cons 'raw ctrl-op-id) (cons 'formatted (number->string ctrl-op-id))))
        )))

    (catch (e)
      (err (str "NETLINK-GENERIC parse error: " e)))))

;; dissect-netlink-generic: parse NETLINK-GENERIC from bytevector
;; Returns (ok fields-alist) or (err message)