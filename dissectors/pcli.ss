;; packet-pcli.c
;; Routines for Packet Cable Lawful Intercept packet disassembly
;;
;; Packet Cable Lawful Intercept is described by various PacketCable/CableLabs
;; specs.
;;
;; One spec is PacketCable(TM) Electronic Surveillance Specification
;; PKT-SP-ESP-I01-991229, the front page of which speaks of it as
;; being "Interim".  It does not appear to be available from the
;; CableLabs Web site, but is available through the Wayback Machine
;; at
;;
;; http://web.archive.org/web/20030428211154/http://www.packetcable.com/downloads/specs/pkt-sp-esp-I01-991229.pdf
;;
;; See Section 4 "Call Content Connection Interface".  In that spec, the
;; packets have a 4-octet Call Content Connection (CCC) Identifier, followed
;; by the Intercepted Information.  The Intercepted Information is an IP
;; datagram, starting with an IP header.
;;
;; However, later specifications, such as PacketCable(TM) 1.5 Specifications,
;; Electronic Surveillance, PKT-SP-ESP1.5-I02-070412, at
;;
;; http://www.cablelabs.com/wp-content/uploads/specdocs/PKT-SP-ESP1.5-I02-070412.pdf
;;
;; the front page of which speaks of it as being "ISSUED", in Section 5 "Call
;; Content Connection Interface", gives a header with a 4-octet CCC
;; Identifier followed by an 8-byte NTP-format timestamp.
;;
;; The PacketCable(TM) 2.0, PacketCable Electronic Surveillance Delivery
;; Function to Collection Function Interface Specification,
;; PKT-SP-ES-DCI-C01-140314, at
;;
;; http://www.cablelabs.com/wp-content/uploads/specdocs/PKT-SP-ES-DCI-C01-140314.pdf
;;
;; which speaks of it as being "CLOSED" ("A static document, reviewed,
;; tested, validated, and closed to further engineering change requests to
;; the specification through CableLabs."), shows in section 7 "CALL CONTENT
;; CONNECTION (CCC) INTERFACE", a header with the 4-octet CCC Identifier,
;; the 8-byte NTP-format timestamp, and an 8-octet Case ID.
;;
;; So we may need a preference for the version.
;;
;; Copyright (c) 2000 by Ed Warnicke <hagbard@physics.rutgers.edu>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/pcli.ss
;; Auto-generated from wireshark/epan/dissectors/packet-pcli.c

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
(def (dissect-pcli buffer)
  "Packet Cable Lawful Intercept"
  (try
    (let* (
           (case-id (unwrap (read-u64be buffer 8)))
           (header (unwrap (read-u32be buffer 16)))
           )

      (ok (list
        (cons 'case-id (list (cons 'raw case-id) (cons 'formatted (fmt-hex case-id))))
        (cons 'header (list (cons 'raw header) (cons 'formatted (fmt-hex header))))
        )))

    (catch (e)
      (err (str "PCLI parse error: " e)))))

;; dissect-pcli: parse PCLI from bytevector
;; Returns (ok fields-alist) or (err message)