;; packet-mojito.c
;; Routines for Dissecting the Gnutella Mojito DHT Protocol
;; http://limewire.negatis.com/index.php?title=Mojito_Message_Format
;;
;; Copyright (c) 2008 by Travis Dawson <travis.dawson@sprint.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mojito.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mojito.c

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
(def (dissect-mojito buffer)
  "Mojito DHT"
  (try
    (let* (
           (socketaddress-version (unwrap (read-u8 buffer 0)))
           (target-kuid (unwrap (slice buffer 0 20)))
           (opcode-data (unwrap (slice buffer 0 1)))
           (socketaddress-ipv4 (unwrap (read-u32be buffer 1)))
           (socketaddress-ipv6 (unwrap (slice buffer 5 16)))
           (socketaddress-port (unwrap (read-u16be buffer 21)))
           (contactvendor (unwrap (slice buffer 23 4)))
           (contactversion (unwrap (read-u16be buffer 27)))
           (contactkuid (unwrap (slice buffer 29 20)))
           (messageid (unwrap (slice buffer 49 16)))
           (fdhtmessage (unwrap (read-u8 buffer 65)))
           (length (unwrap (read-u32be buffer 68)))
           (vendor (unwrap (slice buffer 73 4)))
           (origmjrversion (unwrap (read-u8 buffer 77)))
           (origmnrversion (unwrap (read-u8 buffer 78)))
           (instanceid (unwrap (read-u8 buffer 99)))
           (flags (unwrap (read-u8 buffer 100)))
           (flags-shutdown (unwrap (read-u8 buffer 100)))
           (flags-firewalled (unwrap (read-u8 buffer 100)))
           (extendedlength (unwrap (read-u16be buffer 101)))
           (bigintegerlen (unwrap (read-u8 buffer 103)))
           (bigint-value-one (unwrap (read-u8 buffer 104)))
           (bigint-value-two (unwrap (read-u16be buffer 104)))
           (bigint-value-three (unwrap (read-u24be buffer 104)))
           (bigint-value-four (unwrap (read-u32be buffer 104)))
           (bigintegerval (unwrap (slice buffer 104 1)))
           (storestatuscode-count (unwrap (read-u8 buffer 134)))
           (storestatuscode-kuid (unwrap (slice buffer 135 20)))
           (storestatuscode-secondary-kuid (unwrap (slice buffer 155 20)))
           (sectokenlen (unwrap (read-u8 buffer 179)))
           (sectoken (unwrap (slice buffer 180 1)))
           (contactcount (unwrap (read-u8 buffer 180)))
           (dhtvaluetype (unwrap (slice buffer 222 4)))
           (requestload (unwrap (read-u32be buffer 226)))
           (dhtvaluecount (unwrap (read-u8 buffer 230)))
           (dhtvalue-kuid (unwrap (slice buffer 231 20)))
           (dhtvalue-valuetype (unwrap (slice buffer 251 4)))
           (dhtvalue-version (unwrap (read-u16be buffer 255)))
           (mjrversion (unwrap (read-u8 buffer 255)))
           (mnrversion (unwrap (read-u8 buffer 256)))
           (dhtvalue-length (unwrap (read-u16be buffer 257)))
           (dhtvalue-value (unwrap (slice buffer 259 1)))
           (kuidcount (unwrap (read-u8 buffer 259)))
           (kuid (unwrap (slice buffer 260 20)))
           )

      (ok (list
        (cons 'socketaddress-version (list (cons 'raw socketaddress-version) (cons 'formatted (number->string socketaddress-version))))
        (cons 'target-kuid (list (cons 'raw target-kuid) (cons 'formatted (fmt-bytes target-kuid))))
        (cons 'opcode-data (list (cons 'raw opcode-data) (cons 'formatted (fmt-bytes opcode-data))))
        (cons 'socketaddress-ipv4 (list (cons 'raw socketaddress-ipv4) (cons 'formatted (fmt-ipv4 socketaddress-ipv4))))
        (cons 'socketaddress-ipv6 (list (cons 'raw socketaddress-ipv6) (cons 'formatted (fmt-ipv6-address socketaddress-ipv6))))
        (cons 'socketaddress-port (list (cons 'raw socketaddress-port) (cons 'formatted (number->string socketaddress-port))))
        (cons 'contactvendor (list (cons 'raw contactvendor) (cons 'formatted (utf8->string contactvendor))))
        (cons 'contactversion (list (cons 'raw contactversion) (cons 'formatted (number->string contactversion))))
        (cons 'contactkuid (list (cons 'raw contactkuid) (cons 'formatted (fmt-bytes contactkuid))))
        (cons 'messageid (list (cons 'raw messageid) (cons 'formatted (fmt-bytes messageid))))
        (cons 'fdhtmessage (list (cons 'raw fdhtmessage) (cons 'formatted (fmt-hex fdhtmessage))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'vendor (list (cons 'raw vendor) (cons 'formatted (utf8->string vendor))))
        (cons 'origmjrversion (list (cons 'raw origmjrversion) (cons 'formatted (number->string origmjrversion))))
        (cons 'origmnrversion (list (cons 'raw origmnrversion) (cons 'formatted (number->string origmnrversion))))
        (cons 'instanceid (list (cons 'raw instanceid) (cons 'formatted (number->string instanceid))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flags-shutdown (list (cons 'raw flags-shutdown) (cons 'formatted (number->string flags-shutdown))))
        (cons 'flags-firewalled (list (cons 'raw flags-firewalled) (cons 'formatted (number->string flags-firewalled))))
        (cons 'extendedlength (list (cons 'raw extendedlength) (cons 'formatted (number->string extendedlength))))
        (cons 'bigintegerlen (list (cons 'raw bigintegerlen) (cons 'formatted (number->string bigintegerlen))))
        (cons 'bigint-value-one (list (cons 'raw bigint-value-one) (cons 'formatted (number->string bigint-value-one))))
        (cons 'bigint-value-two (list (cons 'raw bigint-value-two) (cons 'formatted (number->string bigint-value-two))))
        (cons 'bigint-value-three (list (cons 'raw bigint-value-three) (cons 'formatted (number->string bigint-value-three))))
        (cons 'bigint-value-four (list (cons 'raw bigint-value-four) (cons 'formatted (number->string bigint-value-four))))
        (cons 'bigintegerval (list (cons 'raw bigintegerval) (cons 'formatted (fmt-bytes bigintegerval))))
        (cons 'storestatuscode-count (list (cons 'raw storestatuscode-count) (cons 'formatted (number->string storestatuscode-count))))
        (cons 'storestatuscode-kuid (list (cons 'raw storestatuscode-kuid) (cons 'formatted (fmt-bytes storestatuscode-kuid))))
        (cons 'storestatuscode-secondary-kuid (list (cons 'raw storestatuscode-secondary-kuid) (cons 'formatted (fmt-bytes storestatuscode-secondary-kuid))))
        (cons 'sectokenlen (list (cons 'raw sectokenlen) (cons 'formatted (number->string sectokenlen))))
        (cons 'sectoken (list (cons 'raw sectoken) (cons 'formatted (fmt-bytes sectoken))))
        (cons 'contactcount (list (cons 'raw contactcount) (cons 'formatted (number->string contactcount))))
        (cons 'dhtvaluetype (list (cons 'raw dhtvaluetype) (cons 'formatted (utf8->string dhtvaluetype))))
        (cons 'requestload (list (cons 'raw requestload) (cons 'formatted (number->string requestload))))
        (cons 'dhtvaluecount (list (cons 'raw dhtvaluecount) (cons 'formatted (number->string dhtvaluecount))))
        (cons 'dhtvalue-kuid (list (cons 'raw dhtvalue-kuid) (cons 'formatted (fmt-bytes dhtvalue-kuid))))
        (cons 'dhtvalue-valuetype (list (cons 'raw dhtvalue-valuetype) (cons 'formatted (utf8->string dhtvalue-valuetype))))
        (cons 'dhtvalue-version (list (cons 'raw dhtvalue-version) (cons 'formatted (number->string dhtvalue-version))))
        (cons 'mjrversion (list (cons 'raw mjrversion) (cons 'formatted (number->string mjrversion))))
        (cons 'mnrversion (list (cons 'raw mnrversion) (cons 'formatted (number->string mnrversion))))
        (cons 'dhtvalue-length (list (cons 'raw dhtvalue-length) (cons 'formatted (number->string dhtvalue-length))))
        (cons 'dhtvalue-value (list (cons 'raw dhtvalue-value) (cons 'formatted (utf8->string dhtvalue-value))))
        (cons 'kuidcount (list (cons 'raw kuidcount) (cons 'formatted (number->string kuidcount))))
        (cons 'kuid (list (cons 'raw kuid) (cons 'formatted (fmt-bytes kuid))))
        )))

    (catch (e)
      (err (str "MOJITO parse error: " e)))))

;; dissect-mojito: parse MOJITO from bytevector
;; Returns (ok fields-alist) or (err message)