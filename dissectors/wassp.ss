;; packet-wassp.c
;; Routines for the disassembly of the Chantry/Enterasys/ExtremeNetworks AP-Controller
;; tunneling protocol.
;;
;; By Zhong Wei Situ <zsitu@extremenetworks.com>
;; Copyright 2019 Extreme Networks
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/wassp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-wassp.c

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
(def (dissect-wassp buffer)
  "Wireless Access Station Session Protocol"
  (try
    (let* (
           (tlv-unknown (unwrap (read-u32be buffer 0)))
           (tlv-length (unwrap (read-u16be buffer 0)))
           (tlv-type-sub (unwrap (read-u16be buffer 0)))
           (tlv-value-string (unwrap (slice buffer 4 1)))
           (tlv-value-octext (unwrap (slice buffer 4 1)))
           (tlv-value-ip (unwrap (read-u32be buffer 4)))
           (tlv-eid-rustate (unwrap (read-u8 buffer 4)))
           (tlv-value-int (unwrap (read-u8 buffer 4)))
           (macaddr (unwrap (slice buffer 4 6)))
           (tlv-invalid (unwrap (read-u32be buffer 4)))
           (mu-netflow-record (unwrap (slice buffer 4 1)))
           (mu-netflow-in-bytes (unwrap (read-u32be buffer 4)))
           (mu-netflow-in-packets (unwrap (read-u32be buffer 8)))
           (mu-netflow-ip-protocol-number (unwrap (read-u8 buffer 12)))
           (mu-netflow-source-tos (unwrap (read-u8 buffer 13)))
           (mu-netflow-source-port (unwrap (read-u16be buffer 14)))
           (mu-netflow-source-ip (unwrap (read-u32be buffer 16)))
           (mu-netflow-input-snmp (unwrap (read-u16be buffer 20)))
           (mu-netflow-dest-port (unwrap (read-u16be buffer 22)))
           (mu-netflow-dest-ip (unwrap (read-u32be buffer 24)))
           (mu-netflow-output-snmp (unwrap (read-u16be buffer 28)))
           (mu-netflow-last-time (unwrap (read-u32be buffer 30)))
           (mu-netflow-first-time (unwrap (read-u32be buffer 34)))
           (mu-netflow-in-source-mac (unwrap (slice buffer 38 6)))
           (mu-netflow-in-dest-mac (unwrap (slice buffer 44 6)))
           (mu-type (unwrap (read-u8 buffer 50)))
           (mu-qos (unwrap (read-u8 buffer 50)))
           (mu-action-ssid (unwrap (read-u16be buffer 50)))
           (mu-action-field-value (unwrap (read-u16be buffer 50)))
           (mu-mac (unwrap (slice buffer 50 6)))
           (mu-resv1 (unwrap (read-u16be buffer 50)))
           )

      (ok (list
        (cons 'tlv-unknown (list (cons 'raw tlv-unknown) (cons 'formatted (number->string tlv-unknown))))
        (cons 'tlv-length (list (cons 'raw tlv-length) (cons 'formatted (number->string tlv-length))))
        (cons 'tlv-type-sub (list (cons 'raw tlv-type-sub) (cons 'formatted (number->string tlv-type-sub))))
        (cons 'tlv-value-string (list (cons 'raw tlv-value-string) (cons 'formatted (utf8->string tlv-value-string))))
        (cons 'tlv-value-octext (list (cons 'raw tlv-value-octext) (cons 'formatted (fmt-bytes tlv-value-octext))))
        (cons 'tlv-value-ip (list (cons 'raw tlv-value-ip) (cons 'formatted (fmt-ipv4 tlv-value-ip))))
        (cons 'tlv-eid-rustate (list (cons 'raw tlv-eid-rustate) (cons 'formatted (if (= tlv-eid-rustate 0) "False" "True"))))
        (cons 'tlv-value-int (list (cons 'raw tlv-value-int) (cons 'formatted (number->string tlv-value-int))))
        (cons 'macaddr (list (cons 'raw macaddr) (cons 'formatted (fmt-mac macaddr))))
        (cons 'tlv-invalid (list (cons 'raw tlv-invalid) (cons 'formatted (number->string tlv-invalid))))
        (cons 'mu-netflow-record (list (cons 'raw mu-netflow-record) (cons 'formatted (fmt-bytes mu-netflow-record))))
        (cons 'mu-netflow-in-bytes (list (cons 'raw mu-netflow-in-bytes) (cons 'formatted (number->string mu-netflow-in-bytes))))
        (cons 'mu-netflow-in-packets (list (cons 'raw mu-netflow-in-packets) (cons 'formatted (number->string mu-netflow-in-packets))))
        (cons 'mu-netflow-ip-protocol-number (list (cons 'raw mu-netflow-ip-protocol-number) (cons 'formatted (number->string mu-netflow-ip-protocol-number))))
        (cons 'mu-netflow-source-tos (list (cons 'raw mu-netflow-source-tos) (cons 'formatted (fmt-hex mu-netflow-source-tos))))
        (cons 'mu-netflow-source-port (list (cons 'raw mu-netflow-source-port) (cons 'formatted (number->string mu-netflow-source-port))))
        (cons 'mu-netflow-source-ip (list (cons 'raw mu-netflow-source-ip) (cons 'formatted (fmt-ipv4 mu-netflow-source-ip))))
        (cons 'mu-netflow-input-snmp (list (cons 'raw mu-netflow-input-snmp) (cons 'formatted (number->string mu-netflow-input-snmp))))
        (cons 'mu-netflow-dest-port (list (cons 'raw mu-netflow-dest-port) (cons 'formatted (number->string mu-netflow-dest-port))))
        (cons 'mu-netflow-dest-ip (list (cons 'raw mu-netflow-dest-ip) (cons 'formatted (fmt-ipv4 mu-netflow-dest-ip))))
        (cons 'mu-netflow-output-snmp (list (cons 'raw mu-netflow-output-snmp) (cons 'formatted (number->string mu-netflow-output-snmp))))
        (cons 'mu-netflow-last-time (list (cons 'raw mu-netflow-last-time) (cons 'formatted (number->string mu-netflow-last-time))))
        (cons 'mu-netflow-first-time (list (cons 'raw mu-netflow-first-time) (cons 'formatted (number->string mu-netflow-first-time))))
        (cons 'mu-netflow-in-source-mac (list (cons 'raw mu-netflow-in-source-mac) (cons 'formatted (fmt-mac mu-netflow-in-source-mac))))
        (cons 'mu-netflow-in-dest-mac (list (cons 'raw mu-netflow-in-dest-mac) (cons 'formatted (fmt-mac mu-netflow-in-dest-mac))))
        (cons 'mu-type (list (cons 'raw mu-type) (cons 'formatted (number->string mu-type))))
        (cons 'mu-qos (list (cons 'raw mu-qos) (cons 'formatted (number->string mu-qos))))
        (cons 'mu-action-ssid (list (cons 'raw mu-action-ssid) (cons 'formatted (number->string mu-action-ssid))))
        (cons 'mu-action-field-value (list (cons 'raw mu-action-field-value) (cons 'formatted (number->string mu-action-field-value))))
        (cons 'mu-mac (list (cons 'raw mu-mac) (cons 'formatted (fmt-mac mu-mac))))
        (cons 'mu-resv1 (list (cons 'raw mu-resv1) (cons 'formatted (number->string mu-resv1))))
        )))

    (catch (e)
      (err (str "WASSP parse error: " e)))))

;; dissect-wassp: parse WASSP from bytevector
;; Returns (ok fields-alist) or (err message)