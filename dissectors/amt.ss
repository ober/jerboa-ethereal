;; packet-amt.c
;; Routines for Automatic Multicast Tunneling (AMT) dissection
;; Copyright 2017, Alexis La Goutte (See AUTHORS)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/amt.ss
;; Auto-generated from wireshark/epan/dissectors/packet-amt.c
;; RFC 7450

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
(def (dissect-amt buffer)
  "Automatic Multicast Tunneling"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (discovery-nonce (unwrap (read-u32be buffer 11)))
           (relay-address-ipv4 (unwrap (read-u32be buffer 15)))
           (relay-address-ipv6 (unwrap (slice buffer 19 16)))
           (request-reserved (unwrap (read-u8 buffer 35)))
           (request-p (unwrap (read-u8 buffer 35)))
           (membership-query-reserved (unwrap (read-u8 buffer 42)))
           (membership-query-l (unwrap (read-u8 buffer 42)))
           (membership-query-g (unwrap (read-u8 buffer 42)))
           (multicast-data (unwrap (slice buffer 83 1)))
           (reserved (unwrap (slice buffer 83 1)))
           (response-mac (unwrap (slice buffer 84 6)))
           (request-nonce (unwrap (read-u32be buffer 90)))
           (gateway-port-number (unwrap (read-u16be buffer 94)))
           (gateway-ip-address (unwrap (slice buffer 96 16)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'discovery-nonce (list (cons 'raw discovery-nonce) (cons 'formatted (fmt-hex discovery-nonce))))
        (cons 'relay-address-ipv4 (list (cons 'raw relay-address-ipv4) (cons 'formatted (fmt-ipv4 relay-address-ipv4))))
        (cons 'relay-address-ipv6 (list (cons 'raw relay-address-ipv6) (cons 'formatted (fmt-ipv6-address relay-address-ipv6))))
        (cons 'request-reserved (list (cons 'raw request-reserved) (cons 'formatted (fmt-hex request-reserved))))
        (cons 'request-p (list (cons 'raw request-p) (cons 'formatted (if (= request-p 0) "IPv6 packet carrying an MLDv2 General Query" "IPv4 packet carrying an IGMPv3 General Query"))))
        (cons 'membership-query-reserved (list (cons 'raw membership-query-reserved) (cons 'formatted (fmt-hex membership-query-reserved))))
        (cons 'membership-query-l (list (cons 'raw membership-query-l) (cons 'formatted (number->string membership-query-l))))
        (cons 'membership-query-g (list (cons 'raw membership-query-g) (cons 'formatted (number->string membership-query-g))))
        (cons 'multicast-data (list (cons 'raw multicast-data) (cons 'formatted (fmt-bytes multicast-data))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'response-mac (list (cons 'raw response-mac) (cons 'formatted (fmt-hex response-mac))))
        (cons 'request-nonce (list (cons 'raw request-nonce) (cons 'formatted (fmt-hex request-nonce))))
        (cons 'gateway-port-number (list (cons 'raw gateway-port-number) (cons 'formatted (number->string gateway-port-number))))
        (cons 'gateway-ip-address (list (cons 'raw gateway-ip-address) (cons 'formatted (fmt-ipv6-address gateway-ip-address))))
        )))

    (catch (e)
      (err (str "AMT parse error: " e)))))

;; dissect-amt: parse AMT from bytevector
;; Returns (ok fields-alist) or (err message)