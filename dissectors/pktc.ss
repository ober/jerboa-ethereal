;; packet-pktc.c
;; Routines for PacketCable (PKTC) Kerberized Key Management and
;; PacketCable (PKTC) MTA FQDN                  packet disassembly
;;
;; References:
;; [1] PacketCable 1.0 Security Specification, PKT-SP-SEC-I11-040730, July 30,
;; 2004, Cable Television Laboratories, Inc., http://www.PacketCable.com/
;; http://www.cablelabs.com/wp-content/uploads/specdocs/PKT-SP-SEC-I11-040730.pdf
;;
;; Ronnie Sahlberg 2004
;; Thomas Anders 2004
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/pktc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-pktc.c

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
(def (dissect-pktc buffer)
  "PacketCable"
  (try
    (let* (
           (snmpEngineID-len (unwrap (read-u8 buffer 0)))
           (snmpEngineID (unwrap (slice buffer 1 1)))
           (snmpEngineBoots (unwrap (read-u32be buffer 1)))
           (mtafqdn-enterprise (unwrap (read-u32be buffer 1)))
           (version-major (unwrap (read-u8 buffer 2)))
           (version-minor (unwrap (read-u8 buffer 2)))
           (snmpEngineTime (unwrap (read-u32be buffer 5)))
           (mtafqdn-version (unwrap (read-u8 buffer 5)))
           (mtafqdn-mac (unwrap (slice buffer 6 6)))
           (usmUserName-len (unwrap (read-u8 buffer 9)))
           (usmUserName (unwrap (slice buffer 10 1)))
           (ipsec-spi (unwrap (read-u32be buffer 10)))
           (mtafqdn-pub-key-hash (unwrap (slice buffer 12 20)))
           (list-of-ciphersuites-len (unwrap (read-u8 buffer 14)))
           (mtafqdn-fqdn (unwrap (slice buffer 32 1)))
           (mtafqdn-ip (unwrap (read-u32be buffer 32)))
           (ack-required-flag (unwrap (read-u8 buffer 57)))
           (server-nonce (unwrap (read-u32be buffer 98)))
           (server-principal (unwrap (slice buffer 102 1)))
           (timestamp (unwrap (slice buffer 102 13)))
           (sec-param-lifetime (unwrap (read-u32be buffer 115)))
           (grace-period (unwrap (read-u32be buffer 119)))
           (reestablish-flag (unwrap (read-u8 buffer 123)))
           (sha1-hmac (unwrap (slice buffer 124 20)))
           )

      (ok (list
        (cons 'snmpEngineID-len (list (cons 'raw snmpEngineID-len) (cons 'formatted (number->string snmpEngineID-len))))
        (cons 'snmpEngineID (list (cons 'raw snmpEngineID) (cons 'formatted (fmt-bytes snmpEngineID))))
        (cons 'snmpEngineBoots (list (cons 'raw snmpEngineBoots) (cons 'formatted (number->string snmpEngineBoots))))
        (cons 'mtafqdn-enterprise (list (cons 'raw mtafqdn-enterprise) (cons 'formatted (number->string mtafqdn-enterprise))))
        (cons 'version-major (list (cons 'raw version-major) (cons 'formatted (number->string version-major))))
        (cons 'version-minor (list (cons 'raw version-minor) (cons 'formatted (number->string version-minor))))
        (cons 'snmpEngineTime (list (cons 'raw snmpEngineTime) (cons 'formatted (number->string snmpEngineTime))))
        (cons 'mtafqdn-version (list (cons 'raw mtafqdn-version) (cons 'formatted (number->string mtafqdn-version))))
        (cons 'mtafqdn-mac (list (cons 'raw mtafqdn-mac) (cons 'formatted (fmt-mac mtafqdn-mac))))
        (cons 'usmUserName-len (list (cons 'raw usmUserName-len) (cons 'formatted (number->string usmUserName-len))))
        (cons 'usmUserName (list (cons 'raw usmUserName) (cons 'formatted (utf8->string usmUserName))))
        (cons 'ipsec-spi (list (cons 'raw ipsec-spi) (cons 'formatted (fmt-hex ipsec-spi))))
        (cons 'mtafqdn-pub-key-hash (list (cons 'raw mtafqdn-pub-key-hash) (cons 'formatted (fmt-bytes mtafqdn-pub-key-hash))))
        (cons 'list-of-ciphersuites-len (list (cons 'raw list-of-ciphersuites-len) (cons 'formatted (number->string list-of-ciphersuites-len))))
        (cons 'mtafqdn-fqdn (list (cons 'raw mtafqdn-fqdn) (cons 'formatted (utf8->string mtafqdn-fqdn))))
        (cons 'mtafqdn-ip (list (cons 'raw mtafqdn-ip) (cons 'formatted (fmt-ipv4 mtafqdn-ip))))
        (cons 'ack-required-flag (list (cons 'raw ack-required-flag) (cons 'formatted (number->string ack-required-flag))))
        (cons 'server-nonce (list (cons 'raw server-nonce) (cons 'formatted (fmt-hex server-nonce))))
        (cons 'server-principal (list (cons 'raw server-principal) (cons 'formatted (utf8->string server-principal))))
        (cons 'timestamp (list (cons 'raw timestamp) (cons 'formatted (utf8->string timestamp))))
        (cons 'sec-param-lifetime (list (cons 'raw sec-param-lifetime) (cons 'formatted (number->string sec-param-lifetime))))
        (cons 'grace-period (list (cons 'raw grace-period) (cons 'formatted (number->string grace-period))))
        (cons 'reestablish-flag (list (cons 'raw reestablish-flag) (cons 'formatted (number->string reestablish-flag))))
        (cons 'sha1-hmac (list (cons 'raw sha1-hmac) (cons 'formatted (fmt-bytes sha1-hmac))))
        )))

    (catch (e)
      (err (str "PKTC parse error: " e)))))

;; dissect-pktc: parse PKTC from bytevector
;; Returns (ok fields-alist) or (err message)