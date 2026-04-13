;; packet-rdp_cliprdr.c
;; Routines for the clipboard redirection RDP channel
;; Copyright 2023, David Fort <contact@hardening-consulting.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rdp-cliprdr.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rdp_cliprdr.c

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
(def (dissect-rdp-cliprdr buffer)
  "RDP clipboard redirection channel Protocol"
  (try
    (let* (
           (dataLen (unwrap (read-u32be buffer 4)))
           (formatId (unwrap (read-u32be buffer 8)))
           (formatLongName (unwrap (slice buffer 12 1)))
           (formatShortName (unwrap (slice buffer 12 32)))
           (formatDataResponse (unwrap (slice buffer 12 1)))
           (cCapabilitiesSets (unwrap (read-u16be buffer 12)))
           (pad1 (unwrap (read-u16be buffer 14)))
           (capaSet-type (unwrap (read-u16be buffer 16)))
           (capaSet-len (unwrap (read-u16be buffer 18)))
           (lindex (unwrap (read-u32be buffer 32)))
           (dwFlags (unwrap (read-u32be buffer 36)))
           (nPositionLow (unwrap (read-u32be buffer 40)))
           (nPositionHigh (unwrap (read-u32be buffer 44)))
           (cbRequested (unwrap (read-u32be buffer 48)))
           (clipDataId (unwrap (read-u32be buffer 52)))
           (streamId (unwrap (read-u32be buffer 52)))
           )

      (ok (list
        (cons 'dataLen (list (cons 'raw dataLen) (cons 'formatted (number->string dataLen))))
        (cons 'formatId (list (cons 'raw formatId) (cons 'formatted (fmt-hex formatId))))
        (cons 'formatLongName (list (cons 'raw formatLongName) (cons 'formatted (utf8->string formatLongName))))
        (cons 'formatShortName (list (cons 'raw formatShortName) (cons 'formatted (utf8->string formatShortName))))
        (cons 'formatDataResponse (list (cons 'raw formatDataResponse) (cons 'formatted (fmt-bytes formatDataResponse))))
        (cons 'cCapabilitiesSets (list (cons 'raw cCapabilitiesSets) (cons 'formatted (number->string cCapabilitiesSets))))
        (cons 'pad1 (list (cons 'raw pad1) (cons 'formatted (number->string pad1))))
        (cons 'capaSet-type (list (cons 'raw capaSet-type) (cons 'formatted (fmt-hex capaSet-type))))
        (cons 'capaSet-len (list (cons 'raw capaSet-len) (cons 'formatted (number->string capaSet-len))))
        (cons 'lindex (list (cons 'raw lindex) (cons 'formatted (number->string lindex))))
        (cons 'dwFlags (list (cons 'raw dwFlags) (cons 'formatted (fmt-hex dwFlags))))
        (cons 'nPositionLow (list (cons 'raw nPositionLow) (cons 'formatted (number->string nPositionLow))))
        (cons 'nPositionHigh (list (cons 'raw nPositionHigh) (cons 'formatted (number->string nPositionHigh))))
        (cons 'cbRequested (list (cons 'raw cbRequested) (cons 'formatted (number->string cbRequested))))
        (cons 'clipDataId (list (cons 'raw clipDataId) (cons 'formatted (fmt-hex clipDataId))))
        (cons 'streamId (list (cons 'raw streamId) (cons 'formatted (fmt-hex streamId))))
        )))

    (catch (e)
      (err (str "RDP-CLIPRDR parse error: " e)))))

;; dissect-rdp-cliprdr: parse RDP-CLIPRDR from bytevector
;; Returns (ok fields-alist) or (err message)