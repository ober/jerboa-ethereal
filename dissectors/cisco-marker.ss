;; packet-cisco-marker.c
;; Routines for CISCO's ERSPAN3 Marker Packet
;; See: http://www.cisco.com/c/en/us/products/collateral/switches/nexus-9000-series-switches/white-paper-c11-733921.html#_Toc413144488
;; See: https://www.cisco.com/c/en/us/td/docs/switches/datacenter/nexus9000/sw/93x/system-management/b-cisco-nexus-9000-series-nx-os-system-management-configuration-guide-93x/b-cisco-nexus-9000-series-nx-os-system-management-configuration-guide-93x_chapter_011110.html
;; Copyright 2015, Peter Membrey
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-time.c
;; Fixed with additional documentation from Cisco and real-life observations
;; by Stéphane Lapie <stephane.lapie@darkbsd.org>
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/cisco-marker.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cisco_marker.c

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
(def (dissect-cisco-marker buffer)
  "CISCO ERSPAN3 Marker Packet"
  (try
    (let* (
           (erspan-prop-header (unwrap (slice buffer 0 20)))
           (erspan-info (unwrap (read-u8 buffer 20)))
           (erspan-version (unwrap (read-u16be buffer 22)))
           (erspan-type (unwrap (read-u16be buffer 22)))
           (erspan-ssid (unwrap (read-u16be buffer 22)))
           (erspan-granularity (unwrap (read-u16be buffer 24)))
           (erspan-utcoffset (unwrap (read-u16be buffer 24)))
           (erspan-timestamp (unwrap (slice buffer 26 8)))
           (erspan-utc-sec (unwrap (read-u32be buffer 34)))
           (erspan-utc-usec (unwrap (read-u32be buffer 38)))
           (erspan-sequence-number (unwrap (read-u32be buffer 42)))
           (erspan-reserved (unwrap (read-u32be buffer 46)))
           (erspan-tail (unwrap (read-u64be buffer 50)))
           )

      (ok (list
        (cons 'erspan-prop-header (list (cons 'raw erspan-prop-header) (cons 'formatted (fmt-bytes erspan-prop-header))))
        (cons 'erspan-info (list (cons 'raw erspan-info) (cons 'formatted (number->string erspan-info))))
        (cons 'erspan-version (list (cons 'raw erspan-version) (cons 'formatted (number->string erspan-version))))
        (cons 'erspan-type (list (cons 'raw erspan-type) (cons 'formatted (number->string erspan-type))))
        (cons 'erspan-ssid (list (cons 'raw erspan-ssid) (cons 'formatted (number->string erspan-ssid))))
        (cons 'erspan-granularity (list (cons 'raw erspan-granularity) (cons 'formatted (number->string erspan-granularity))))
        (cons 'erspan-utcoffset (list (cons 'raw erspan-utcoffset) (cons 'formatted (number->string erspan-utcoffset))))
        (cons 'erspan-timestamp (list (cons 'raw erspan-timestamp) (cons 'formatted (number->string erspan-timestamp))))
        (cons 'erspan-utc-sec (list (cons 'raw erspan-utc-sec) (cons 'formatted (number->string erspan-utc-sec))))
        (cons 'erspan-utc-usec (list (cons 'raw erspan-utc-usec) (cons 'formatted (number->string erspan-utc-usec))))
        (cons 'erspan-sequence-number (list (cons 'raw erspan-sequence-number) (cons 'formatted (number->string erspan-sequence-number))))
        (cons 'erspan-reserved (list (cons 'raw erspan-reserved) (cons 'formatted (fmt-hex erspan-reserved))))
        (cons 'erspan-tail (list (cons 'raw erspan-tail) (cons 'formatted (fmt-hex erspan-tail))))
        )))

    (catch (e)
      (err (str "CISCO-MARKER parse error: " e)))))

;; dissect-cisco-marker: parse CISCO-MARKER from bytevector
;; Returns (ok fields-alist) or (err message)