;; packet-ppcap.c
;; Copyright 2012, 2014, Ericsson AB
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;;

;; jerboa-ethereal/dissectors/ppcap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ppcap.c

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
(def (dissect-ppcap buffer)
  "Proprietary PCAP"
  (try
    (let* (
           (payload-type (unwrap (slice buffer 0 1)))
           (reserved (unwrap (read-u16be buffer 0)))
           (ssn (unwrap (read-u16be buffer 4)))
           (spc (unwrap (read-u24be buffer 5)))
           (opc (unwrap (read-u16be buffer 5)))
           (source-ip-address1 (unwrap (read-u32be buffer 5)))
           (source-ip-address2 (unwrap (slice buffer 5 16)))
           (source-nodeid (unwrap (slice buffer 5 1)))
           (destreserved (unwrap (read-u16be buffer 5)))
           (ssn1 (unwrap (read-u8 buffer 9)))
           (spc1 (unwrap (read-u24be buffer 10)))
           (dpc (unwrap (read-u32be buffer 10)))
           (destination-ip-address1 (unwrap (read-u32be buffer 10)))
           (destination-ip-address2 (unwrap (slice buffer 10 16)))
           (destination-nodeid (unwrap (slice buffer 10 1)))
           (info (unwrap (slice buffer 10 1)))
           (local-port (unwrap (read-u16be buffer 10)))
           (remote-port (unwrap (read-u16be buffer 10)))
           (transport-prot (unwrap (slice buffer 10 4)))
           (length (unwrap (read-u16be buffer 14)))
           (sctp-assoc (unwrap (slice buffer 14 1)))
           (payload-data (unwrap (slice buffer 14 1)))
           )

      (ok (list
        (cons 'payload-type (list (cons 'raw payload-type) (cons 'formatted (utf8->string payload-type))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (number->string reserved))))
        (cons 'ssn (list (cons 'raw ssn) (cons 'formatted (number->string ssn))))
        (cons 'spc (list (cons 'raw spc) (cons 'formatted (number->string spc))))
        (cons 'opc (list (cons 'raw opc) (cons 'formatted (number->string opc))))
        (cons 'source-ip-address1 (list (cons 'raw source-ip-address1) (cons 'formatted (fmt-ipv4 source-ip-address1))))
        (cons 'source-ip-address2 (list (cons 'raw source-ip-address2) (cons 'formatted (fmt-ipv6-address source-ip-address2))))
        (cons 'source-nodeid (list (cons 'raw source-nodeid) (cons 'formatted (utf8->string source-nodeid))))
        (cons 'destreserved (list (cons 'raw destreserved) (cons 'formatted (number->string destreserved))))
        (cons 'ssn1 (list (cons 'raw ssn1) (cons 'formatted (number->string ssn1))))
        (cons 'spc1 (list (cons 'raw spc1) (cons 'formatted (number->string spc1))))
        (cons 'dpc (list (cons 'raw dpc) (cons 'formatted (number->string dpc))))
        (cons 'destination-ip-address1 (list (cons 'raw destination-ip-address1) (cons 'formatted (fmt-ipv4 destination-ip-address1))))
        (cons 'destination-ip-address2 (list (cons 'raw destination-ip-address2) (cons 'formatted (fmt-ipv6-address destination-ip-address2))))
        (cons 'destination-nodeid (list (cons 'raw destination-nodeid) (cons 'formatted (utf8->string destination-nodeid))))
        (cons 'info (list (cons 'raw info) (cons 'formatted (utf8->string info))))
        (cons 'local-port (list (cons 'raw local-port) (cons 'formatted (number->string local-port))))
        (cons 'remote-port (list (cons 'raw remote-port) (cons 'formatted (number->string remote-port))))
        (cons 'transport-prot (list (cons 'raw transport-prot) (cons 'formatted (utf8->string transport-prot))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'sctp-assoc (list (cons 'raw sctp-assoc) (cons 'formatted (utf8->string sctp-assoc))))
        (cons 'payload-data (list (cons 'raw payload-data) (cons 'formatted (fmt-bytes payload-data))))
        )))

    (catch (e)
      (err (str "PPCAP parse error: " e)))))

;; dissect-ppcap: parse PPCAP from bytevector
;; Returns (ok fields-alist) or (err message)