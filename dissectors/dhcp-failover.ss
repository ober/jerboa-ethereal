;; packet-dhcp-failover.c
;; Routines for ISC DHCP Server failover protocol dissection
;; Copyright 2004, M. Ortega y Strupp <moys@loplof.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dhcp-failover.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dhcp_failover.c

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
(def (dissect-dhcp-failover buffer)
  "DHCP Failover"
  (try
    (let* (
           (poffset (unwrap (read-u8 buffer 3)))
           (xid (unwrap (read-u32be buffer 8)))
           (additional-HB (unwrap (slice buffer 12 1)))
           (option-length (unwrap (read-u16be buffer 12)))
           (assigned-ip-address (unwrap (read-u32be buffer 16)))
           (delayed-service-parameter (unwrap (read-u8 buffer 16)))
           (addresses-transferred (unwrap (read-u32be buffer 16)))
           (client-identifier (unwrap (slice buffer 16 1)))
           (client-hardware-address (unwrap (slice buffer 16 1)))
           (ms-client-scope (unwrap (read-u32be buffer 16)))
           (ftddns (unwrap (slice buffer 16 1)))
           (relationship-name (unwrap (slice buffer 16 1)))
           (message (unwrap (slice buffer 16 1)))
           (mclt (unwrap (read-u32be buffer 16)))
           (vendor-class (unwrap (slice buffer 16 1)))
           (lease-expiration-time (unwrap (read-u32be buffer 16)))
           (potential-expiration-time (unwrap (read-u32be buffer 16)))
           (client-last-transaction-time (unwrap (read-u32be buffer 16)))
           (start-time-of-state (unwrap (read-u32be buffer 16)))
           (max-unacked-bndupd (unwrap (read-u32be buffer 16)))
           (hash-bucket-assignment (unwrap (slice buffer 16 1)))
           (ipflags (unwrap (read-u16be buffer 16)))
           (ipflags-reserved (extract-bits ipflags 0x80 7))
           (ipflags-bootp (extract-bits ipflags 0x40 6))
           (ipflags-mbz (extract-bits ipflags 0x3F 0))
           (ms-ipflags (unwrap (read-u8 buffer 16)))
           (protocol-version (unwrap (read-u8 buffer 16)))
           (options (unwrap (slice buffer 16 1)))
           (ms-scope-id (unwrap (read-u32be buffer 16)))
           (infoblox-client-hostname (unwrap (slice buffer 20 1)))
           (ms-client-name (unwrap (slice buffer 20 1)))
           (ms-client-description (unwrap (slice buffer 20 1)))
           (ms-client-subnet-mask (unwrap (read-u32be buffer 20)))
           (ms-server-ip (unwrap (read-u32be buffer 20)))
           (ms-server-name (unwrap (slice buffer 20 1)))
           (ms-client-nap-probation (unwrap (read-u32be buffer 20)))
           (ms-client-nap-capable (unwrap (read-u8 buffer 20)))
           (ms-client-matched-policy (unwrap (slice buffer 20 1)))
           (ms-extended-address-state (unwrap (read-u32be buffer 20)))
           (unknown-data (unwrap (slice buffer 20 1)))
           (length (unwrap (read-u16be buffer 24)))
           )

      (ok (list
        (cons 'poffset (list (cons 'raw poffset) (cons 'formatted (number->string poffset))))
        (cons 'xid (list (cons 'raw xid) (cons 'formatted (fmt-hex xid))))
        (cons 'additional-HB (list (cons 'raw additional-HB) (cons 'formatted (fmt-bytes additional-HB))))
        (cons 'option-length (list (cons 'raw option-length) (cons 'formatted (number->string option-length))))
        (cons 'assigned-ip-address (list (cons 'raw assigned-ip-address) (cons 'formatted (fmt-ipv4 assigned-ip-address))))
        (cons 'delayed-service-parameter (list (cons 'raw delayed-service-parameter) (cons 'formatted (number->string delayed-service-parameter))))
        (cons 'addresses-transferred (list (cons 'raw addresses-transferred) (cons 'formatted (number->string addresses-transferred))))
        (cons 'client-identifier (list (cons 'raw client-identifier) (cons 'formatted (utf8->string client-identifier))))
        (cons 'client-hardware-address (list (cons 'raw client-hardware-address) (cons 'formatted (utf8->string client-hardware-address))))
        (cons 'ms-client-scope (list (cons 'raw ms-client-scope) (cons 'formatted (fmt-ipv4 ms-client-scope))))
        (cons 'ftddns (list (cons 'raw ftddns) (cons 'formatted (utf8->string ftddns))))
        (cons 'relationship-name (list (cons 'raw relationship-name) (cons 'formatted (utf8->string relationship-name))))
        (cons 'message (list (cons 'raw message) (cons 'formatted (utf8->string message))))
        (cons 'mclt (list (cons 'raw mclt) (cons 'formatted (number->string mclt))))
        (cons 'vendor-class (list (cons 'raw vendor-class) (cons 'formatted (utf8->string vendor-class))))
        (cons 'lease-expiration-time (list (cons 'raw lease-expiration-time) (cons 'formatted (number->string lease-expiration-time))))
        (cons 'potential-expiration-time (list (cons 'raw potential-expiration-time) (cons 'formatted (number->string potential-expiration-time))))
        (cons 'client-last-transaction-time (list (cons 'raw client-last-transaction-time) (cons 'formatted (number->string client-last-transaction-time))))
        (cons 'start-time-of-state (list (cons 'raw start-time-of-state) (cons 'formatted (number->string start-time-of-state))))
        (cons 'max-unacked-bndupd (list (cons 'raw max-unacked-bndupd) (cons 'formatted (number->string max-unacked-bndupd))))
        (cons 'hash-bucket-assignment (list (cons 'raw hash-bucket-assignment) (cons 'formatted (fmt-bytes hash-bucket-assignment))))
        (cons 'ipflags (list (cons 'raw ipflags) (cons 'formatted (fmt-hex ipflags))))
        (cons 'ipflags-reserved (list (cons 'raw ipflags-reserved) (cons 'formatted (if (= ipflags-reserved 0) "Not set" "Set"))))
        (cons 'ipflags-bootp (list (cons 'raw ipflags-bootp) (cons 'formatted (if (= ipflags-bootp 0) "Not set" "Set"))))
        (cons 'ipflags-mbz (list (cons 'raw ipflags-mbz) (cons 'formatted (if (= ipflags-mbz 0) "Not set" "Set"))))
        (cons 'ms-ipflags (list (cons 'raw ms-ipflags) (cons 'formatted (fmt-hex ms-ipflags))))
        (cons 'protocol-version (list (cons 'raw protocol-version) (cons 'formatted (number->string protocol-version))))
        (cons 'options (list (cons 'raw options) (cons 'formatted (fmt-bytes options))))
        (cons 'ms-scope-id (list (cons 'raw ms-scope-id) (cons 'formatted (fmt-ipv4 ms-scope-id))))
        (cons 'infoblox-client-hostname (list (cons 'raw infoblox-client-hostname) (cons 'formatted (utf8->string infoblox-client-hostname))))
        (cons 'ms-client-name (list (cons 'raw ms-client-name) (cons 'formatted (utf8->string ms-client-name))))
        (cons 'ms-client-description (list (cons 'raw ms-client-description) (cons 'formatted (utf8->string ms-client-description))))
        (cons 'ms-client-subnet-mask (list (cons 'raw ms-client-subnet-mask) (cons 'formatted (fmt-ipv4 ms-client-subnet-mask))))
        (cons 'ms-server-ip (list (cons 'raw ms-server-ip) (cons 'formatted (fmt-ipv4 ms-server-ip))))
        (cons 'ms-server-name (list (cons 'raw ms-server-name) (cons 'formatted (utf8->string ms-server-name))))
        (cons 'ms-client-nap-probation (list (cons 'raw ms-client-nap-probation) (cons 'formatted (number->string ms-client-nap-probation))))
        (cons 'ms-client-nap-capable (list (cons 'raw ms-client-nap-capable) (cons 'formatted (number->string ms-client-nap-capable))))
        (cons 'ms-client-matched-policy (list (cons 'raw ms-client-matched-policy) (cons 'formatted (utf8->string ms-client-matched-policy))))
        (cons 'ms-extended-address-state (list (cons 'raw ms-extended-address-state) (cons 'formatted (fmt-hex ms-extended-address-state))))
        (cons 'unknown-data (list (cons 'raw unknown-data) (cons 'formatted (fmt-bytes unknown-data))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        )))

    (catch (e)
      (err (str "DHCP-FAILOVER parse error: " e)))))

;; dissect-dhcp-failover: parse DHCP-FAILOVER from bytevector
;; Returns (ok fields-alist) or (err message)