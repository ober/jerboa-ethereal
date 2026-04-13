;; packet-cdp.c
;; Routines for the disassembly of the "Cisco Discovery Protocol"
;; (c) Copyright Hannes R. Boehm <hannes@boehm.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/cdp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cdp.c

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
(def (dissect-cdp buffer)
  "Cisco Discovery Protocol"
  (try
    (let* (
           (deviceid (unwrap (slice buffer 8 1)))
           (portid (unwrap (slice buffer 8 1)))
           (odr-default-gateway (unwrap (read-u32be buffer 20)))
           (ip-prefix (unwrap (read-u32be buffer 32)))
           (oui (unwrap (read-u24be buffer 37)))
           (cluster-master-ip (unwrap (read-u32be buffer 37)))
           (cluster-ip (unwrap (read-u32be buffer 37)))
           (cluster-version (unwrap (read-u8 buffer 37)))
           (cluster-sub-version (unwrap (read-u8 buffer 37)))
           (cluster-status (unwrap (read-u8 buffer 37)))
           (cluster-unknown (unwrap (read-u8 buffer 37)))
           (cluster-commander-mac (unwrap (slice buffer 37 6)))
           (cluster-switch-mac (unwrap (slice buffer 37 6)))
           (cluster-management-vlan (unwrap (read-u16be buffer 37)))
           (hello-unknown (unwrap (slice buffer 37 1)))
           (vtp-management-domain (unwrap (slice buffer 37 1)))
           (native-vlan (unwrap (read-u16be buffer 37)))
           (duplex (unwrap (read-u8 buffer 37)))
           (voice-vlan (unwrap (read-u16be buffer 37)))
           (mtu (unwrap (read-u32be buffer 37)))
           (trust-bitmap (unwrap (read-u8 buffer 37)))
           (untrusted-port-cos (unwrap (read-u8 buffer 37)))
           (system-name (unwrap (slice buffer 37 1)))
           (system-object-identifier (unwrap (slice buffer 37 1)))
           (number-of-addresses (unwrap (read-u32be buffer 41)))
           (location-unknown (unwrap (read-u8 buffer 45)))
           (location (unwrap (slice buffer 45 1)))
           (request-id (unwrap (read-u16be buffer 57)))
           (management-id (unwrap (read-u16be buffer 57)))
           (encrypted-data (unwrap (slice buffer 69 20)))
           (seen-sequence (unwrap (read-u32be buffer 69)))
           (sequence-number (unwrap (read-u32be buffer 69)))
           (model-number (unwrap (slice buffer 69 16)))
           (unknown-pad (unwrap (read-u16be buffer 69)))
           (hardware-version-id (unwrap (slice buffer 69 3)))
           (system-serial-number (unwrap (slice buffer 69 11)))
           (nrgyz-unknown-values (unwrap (slice buffer 69 8)))
           (len-tlv-table (unwrap (read-u16be buffer 69)))
           (num-tlvs-table (unwrap (read-u16be buffer 69)))
           (tlvlength (unwrap (read-u16be buffer 73)))
           (platform (unwrap (slice buffer 73 1)))
           (data (unwrap (slice buffer 73 1)))
           (version (unwrap (read-u8 buffer 89)))
           )

      (ok (list
        (cons 'deviceid (list (cons 'raw deviceid) (cons 'formatted (utf8->string deviceid))))
        (cons 'portid (list (cons 'raw portid) (cons 'formatted (utf8->string portid))))
        (cons 'odr-default-gateway (list (cons 'raw odr-default-gateway) (cons 'formatted (fmt-ipv4 odr-default-gateway))))
        (cons 'ip-prefix (list (cons 'raw ip-prefix) (cons 'formatted (fmt-ipv4 ip-prefix))))
        (cons 'oui (list (cons 'raw oui) (cons 'formatted (number->string oui))))
        (cons 'cluster-master-ip (list (cons 'raw cluster-master-ip) (cons 'formatted (fmt-ipv4 cluster-master-ip))))
        (cons 'cluster-ip (list (cons 'raw cluster-ip) (cons 'formatted (fmt-ipv4 cluster-ip))))
        (cons 'cluster-version (list (cons 'raw cluster-version) (cons 'formatted (fmt-hex cluster-version))))
        (cons 'cluster-sub-version (list (cons 'raw cluster-sub-version) (cons 'formatted (fmt-hex cluster-sub-version))))
        (cons 'cluster-status (list (cons 'raw cluster-status) (cons 'formatted (fmt-hex cluster-status))))
        (cons 'cluster-unknown (list (cons 'raw cluster-unknown) (cons 'formatted (fmt-hex cluster-unknown))))
        (cons 'cluster-commander-mac (list (cons 'raw cluster-commander-mac) (cons 'formatted (fmt-mac cluster-commander-mac))))
        (cons 'cluster-switch-mac (list (cons 'raw cluster-switch-mac) (cons 'formatted (fmt-mac cluster-switch-mac))))
        (cons 'cluster-management-vlan (list (cons 'raw cluster-management-vlan) (cons 'formatted (number->string cluster-management-vlan))))
        (cons 'hello-unknown (list (cons 'raw hello-unknown) (cons 'formatted (fmt-bytes hello-unknown))))
        (cons 'vtp-management-domain (list (cons 'raw vtp-management-domain) (cons 'formatted (utf8->string vtp-management-domain))))
        (cons 'native-vlan (list (cons 'raw native-vlan) (cons 'formatted (number->string native-vlan))))
        (cons 'duplex (list (cons 'raw duplex) (cons 'formatted (if (= duplex 0) "False" "True"))))
        (cons 'voice-vlan (list (cons 'raw voice-vlan) (cons 'formatted (number->string voice-vlan))))
        (cons 'mtu (list (cons 'raw mtu) (cons 'formatted (number->string mtu))))
        (cons 'trust-bitmap (list (cons 'raw trust-bitmap) (cons 'formatted (fmt-hex trust-bitmap))))
        (cons 'untrusted-port-cos (list (cons 'raw untrusted-port-cos) (cons 'formatted (fmt-hex untrusted-port-cos))))
        (cons 'system-name (list (cons 'raw system-name) (cons 'formatted (utf8->string system-name))))
        (cons 'system-object-identifier (list (cons 'raw system-object-identifier) (cons 'formatted (fmt-bytes system-object-identifier))))
        (cons 'number-of-addresses (list (cons 'raw number-of-addresses) (cons 'formatted (number->string number-of-addresses))))
        (cons 'location-unknown (list (cons 'raw location-unknown) (cons 'formatted (fmt-hex location-unknown))))
        (cons 'location (list (cons 'raw location) (cons 'formatted (utf8->string location))))
        (cons 'request-id (list (cons 'raw request-id) (cons 'formatted (number->string request-id))))
        (cons 'management-id (list (cons 'raw management-id) (cons 'formatted (number->string management-id))))
        (cons 'encrypted-data (list (cons 'raw encrypted-data) (cons 'formatted (fmt-bytes encrypted-data))))
        (cons 'seen-sequence (list (cons 'raw seen-sequence) (cons 'formatted (number->string seen-sequence))))
        (cons 'sequence-number (list (cons 'raw sequence-number) (cons 'formatted (number->string sequence-number))))
        (cons 'model-number (list (cons 'raw model-number) (cons 'formatted (utf8->string model-number))))
        (cons 'unknown-pad (list (cons 'raw unknown-pad) (cons 'formatted (fmt-hex unknown-pad))))
        (cons 'hardware-version-id (list (cons 'raw hardware-version-id) (cons 'formatted (utf8->string hardware-version-id))))
        (cons 'system-serial-number (list (cons 'raw system-serial-number) (cons 'formatted (utf8->string system-serial-number))))
        (cons 'nrgyz-unknown-values (list (cons 'raw nrgyz-unknown-values) (cons 'formatted (fmt-bytes nrgyz-unknown-values))))
        (cons 'len-tlv-table (list (cons 'raw len-tlv-table) (cons 'formatted (number->string len-tlv-table))))
        (cons 'num-tlvs-table (list (cons 'raw num-tlvs-table) (cons 'formatted (number->string num-tlvs-table))))
        (cons 'tlvlength (list (cons 'raw tlvlength) (cons 'formatted (number->string tlvlength))))
        (cons 'platform (list (cons 'raw platform) (cons 'formatted (utf8->string platform))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        )))

    (catch (e)
      (err (str "CDP parse error: " e)))))

;; dissect-cdp: parse CDP from bytevector
;; Returns (ok fields-alist) or (err message)