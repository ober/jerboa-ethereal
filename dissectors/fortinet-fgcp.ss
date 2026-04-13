;; packet-fortinet-fgcp.c
;; Routines for FortiGate Cluster Protocol dissection
;; Copyright 2023, Alexis La Goutte <alexis.lagoutte at gmail dot com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; No spec/doc is available based on reverse/analysis of protocol...
;;
;;

;; jerboa-ethereal/dissectors/fortinet-fgcp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-fortinet_fgcp.c

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
(def (dissect-fortinet-fgcp buffer)
  "FortiGate Cluster Protocol - HeartBeat"
  (try
    (let* (
           (fgcp-hb-magic (unwrap (read-u16be buffer 0)))
           (fgcp-hb-flag (unwrap (read-u8 buffer 3)))
           (fgcp-hb-flag-b74 (extract-bits fgcp-hb-flag 0xF0 4))
           (fgcp-hb-flag-b3 (extract-bits fgcp-hb-flag 0x8 3))
           (fgcp-hb-flag-b2 (extract-bits fgcp-hb-flag 0x4 2))
           (fgcp-hb-flag-authentication (extract-bits fgcp-hb-flag 0x2 1))
           (fgcp-hb-flag-encryption (extract-bits fgcp-hb-flag 0x1 0))
           (fgcp-hb-gn (unwrap (slice buffer 4 32)))
           (fgcp-hb-group-id (unwrap (read-u16be buffer 38)))
           (fgcp-hb-port (unwrap (slice buffer 52 16)))
           (fgcp-hb-revision (unwrap (read-u16be buffer 68)))
           (fgcp-hb-unknown-uint16 (unwrap (read-u16be buffer 70)))
           (fgcp-hb-sn (unwrap (slice buffer 72 16)))
           (fgcp-hb-payload-encrypted (unwrap (slice buffer 88 1)))
           (fgcp-hb-tlv-length (unwrap (read-u16be buffer 90)))
           (fgcp-hb-tlv-value (unwrap (slice buffer 92 1)))
           (fgcp-hb-tlv-vcluster-id (unwrap (read-u8 buffer 92)))
           (fgcp-hb-tlv-priority (unwrap (read-u8 buffer 93)))
           (fgcp-hb-tlv-override (unwrap (read-u8 buffer 94)))
           (fgcp-hb-tlv-ha-checksum-global (unwrap (slice buffer 95 16)))
           (fgcp-hb-tlv-ha-checksum-vdom (unwrap (slice buffer 111 16)))
           (fgcp-hb-tlv-ha-checksum-root (unwrap (slice buffer 127 16)))
           (fgcp-hb-tlv-interface-inventory-number (unwrap (read-u16be buffer 143)))
           (fgcp-hb-authentication (unwrap (slice buffer 168 32)))
           )

      (ok (list
        (cons 'fgcp-hb-magic (list (cons 'raw fgcp-hb-magic) (cons 'formatted (fmt-hex fgcp-hb-magic))))
        (cons 'fgcp-hb-flag (list (cons 'raw fgcp-hb-flag) (cons 'formatted (fmt-hex fgcp-hb-flag))))
        (cons 'fgcp-hb-flag-b74 (list (cons 'raw fgcp-hb-flag-b74) (cons 'formatted (if (= fgcp-hb-flag-b74 0) "Not set" "Set"))))
        (cons 'fgcp-hb-flag-b3 (list (cons 'raw fgcp-hb-flag-b3) (cons 'formatted (if (= fgcp-hb-flag-b3 0) "Not set" "Set"))))
        (cons 'fgcp-hb-flag-b2 (list (cons 'raw fgcp-hb-flag-b2) (cons 'formatted (if (= fgcp-hb-flag-b2 0) "Not set" "Set"))))
        (cons 'fgcp-hb-flag-authentication (list (cons 'raw fgcp-hb-flag-authentication) (cons 'formatted (if (= fgcp-hb-flag-authentication 0) "Not set" "Set"))))
        (cons 'fgcp-hb-flag-encryption (list (cons 'raw fgcp-hb-flag-encryption) (cons 'formatted (if (= fgcp-hb-flag-encryption 0) "Not set" "Set"))))
        (cons 'fgcp-hb-gn (list (cons 'raw fgcp-hb-gn) (cons 'formatted (utf8->string fgcp-hb-gn))))
        (cons 'fgcp-hb-group-id (list (cons 'raw fgcp-hb-group-id) (cons 'formatted (number->string fgcp-hb-group-id))))
        (cons 'fgcp-hb-port (list (cons 'raw fgcp-hb-port) (cons 'formatted (utf8->string fgcp-hb-port))))
        (cons 'fgcp-hb-revision (list (cons 'raw fgcp-hb-revision) (cons 'formatted (number->string fgcp-hb-revision))))
        (cons 'fgcp-hb-unknown-uint16 (list (cons 'raw fgcp-hb-unknown-uint16) (cons 'formatted (number->string fgcp-hb-unknown-uint16))))
        (cons 'fgcp-hb-sn (list (cons 'raw fgcp-hb-sn) (cons 'formatted (utf8->string fgcp-hb-sn))))
        (cons 'fgcp-hb-payload-encrypted (list (cons 'raw fgcp-hb-payload-encrypted) (cons 'formatted (fmt-bytes fgcp-hb-payload-encrypted))))
        (cons 'fgcp-hb-tlv-length (list (cons 'raw fgcp-hb-tlv-length) (cons 'formatted (number->string fgcp-hb-tlv-length))))
        (cons 'fgcp-hb-tlv-value (list (cons 'raw fgcp-hb-tlv-value) (cons 'formatted (fmt-bytes fgcp-hb-tlv-value))))
        (cons 'fgcp-hb-tlv-vcluster-id (list (cons 'raw fgcp-hb-tlv-vcluster-id) (cons 'formatted (number->string fgcp-hb-tlv-vcluster-id))))
        (cons 'fgcp-hb-tlv-priority (list (cons 'raw fgcp-hb-tlv-priority) (cons 'formatted (number->string fgcp-hb-tlv-priority))))
        (cons 'fgcp-hb-tlv-override (list (cons 'raw fgcp-hb-tlv-override) (cons 'formatted (number->string fgcp-hb-tlv-override))))
        (cons 'fgcp-hb-tlv-ha-checksum-global (list (cons 'raw fgcp-hb-tlv-ha-checksum-global) (cons 'formatted (fmt-bytes fgcp-hb-tlv-ha-checksum-global))))
        (cons 'fgcp-hb-tlv-ha-checksum-vdom (list (cons 'raw fgcp-hb-tlv-ha-checksum-vdom) (cons 'formatted (fmt-bytes fgcp-hb-tlv-ha-checksum-vdom))))
        (cons 'fgcp-hb-tlv-ha-checksum-root (list (cons 'raw fgcp-hb-tlv-ha-checksum-root) (cons 'formatted (fmt-bytes fgcp-hb-tlv-ha-checksum-root))))
        (cons 'fgcp-hb-tlv-interface-inventory-number (list (cons 'raw fgcp-hb-tlv-interface-inventory-number) (cons 'formatted (number->string fgcp-hb-tlv-interface-inventory-number))))
        (cons 'fgcp-hb-authentication (list (cons 'raw fgcp-hb-authentication) (cons 'formatted (fmt-bytes fgcp-hb-authentication))))
        )))

    (catch (e)
      (err (str "FORTINET-FGCP parse error: " e)))))

;; dissect-fortinet-fgcp: parse FORTINET-FGCP from bytevector
;; Returns (ok fields-alist) or (err message)