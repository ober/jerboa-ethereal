;; packet-netanalyzer.c
;; Dissector for Hilscher netANALYZER frames.
;; Copyright 2008-2016, Hilscher GmbH, Holger Pfrommer hpfrommer[AT]hilscher.com
;;
;; Packet structure:
;; +---------------------------+
;; |           Header          |
;; |         (4 Octets)        |
;; +---------------------------+
;; |           Payload         |
;; .                           .
;; .                           .
;; .                           .
;;
;; Description:
;; The header field contains a 32-bit value in little-endian byte order.
;; The low-order 8 bits are a set of error flags for the packet:
;; 0x00000001 - MII RX_ER
;; 0x00000002 - alignment error
;; 0x00000004 - FCS error
;; 0x00000008 - frame too long
;; 0x00000010 - SFD error
;; 0x00000020 - frame shorter than 64 bytes
;; 0x00000040 - preamble shorter than 7 bytes
;; 0x00000080 - preamble longer than 7 bytes/li>
;; The next bit, 0x00000100, is set if the packet arrived on the GPIO port rather tha the Ethernet port.
;; The next bit, 0x00000200, is set if the packet was received in transparent capture mode.
;; That should never be set for LINKTYPE_NETANALYZER and should always be set for LINKTYPE_NETANALYZER_TRANSPARENT.
;; The next 4 bits, 0x00003C00, are a bitfield giving the version of the header field; version can be 1 or 2.
;; The next 2 bits, 0x0000C000, are the capture port/GPIO number, from 0 to 3.
;; The next 12 bits, 0x0FFF0000, are the frame length, in bytes.
;; The topmost 4 bits, 0xF0000000, for version 2 header, these bits are the type of the following packet
;; (0: Ethernet, 1: PROFIBUS, 2: buffer state entry, 3: timetick, 4..15: reserved).
;; The payload is an Ethernet frame, beginning with the MAC header and ending with the FCS, for LINKTYPE_NETANALYZER,
;; and an Ethernet frame, beginning with the preamble and ending with the FCS, for LINKTYPE_NETANALYZER_TRANSPARENT.
;;
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald[AT]wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/netanalyzer.ss
;; Auto-generated from wireshark/epan/dissectors/packet-netanalyzer.c

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
(def (dissect-netanalyzer buffer)
  "netANALYZER"
  (try
    (let* (
           (status (unwrap (read-u8 buffer 0)))
           (length (unwrap (read-u16be buffer 0)))
           (port (unwrap (read-u8 buffer 0)))
           )

      (ok (list
        (cons 'status (list (cons 'raw status) (cons 'formatted (fmt-hex status))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'port (list (cons 'raw port) (cons 'formatted (number->string port))))
        )))

    (catch (e)
      (err (str "NETANALYZER parse error: " e)))))

;; dissect-netanalyzer: parse NETANALYZER from bytevector
;; Returns (ok fields-alist) or (err message)