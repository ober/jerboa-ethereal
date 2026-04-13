;; packet-3com-njack.c
;; Routines for the disassembly of the 3com NetworkJack management protocol
;;
;; Copyright 2005 Joerg Mayer (see AUTHORS file)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/3com-njack.ss
;; Auto-generated from wireshark/epan/dissectors/packet-3com_njack.c

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
(def (dissect-3com-njack buffer)
  "3com Network Jack"
  (try
    (let* (
           (magic (unwrap (slice buffer 0 5)))
           (tlv-length (unwrap (read-u8 buffer 3)))
           (type (unwrap (read-u8 buffer 5)))
           (set-length (unwrap (read-u16be buffer 6)))
           (set-salt (unwrap (read-u32be buffer 8)))
           (tlv-devicemac (unwrap (slice buffer 12 6)))
           (set-authdata (unwrap (slice buffer 12 16)))
           (tlv-version (unwrap (read-u32be buffer 18)))
           (tlv-typeip (unwrap (read-u32be buffer 22)))
           (tlv-typestring (unwrap (slice buffer 26 1)))
           (getresp-unknown1 (unwrap (read-u8 buffer 29)))
           (tlv-data (unwrap (slice buffer 30 1)))
           )

      (ok (list
        (cons 'magic (list (cons 'raw magic) (cons 'formatted (utf8->string magic))))
        (cons 'tlv-length (list (cons 'raw tlv-length) (cons 'formatted (fmt-hex tlv-length))))
        (cons 'type (list (cons 'raw type) (cons 'formatted (fmt-hex type))))
        (cons 'set-length (list (cons 'raw set-length) (cons 'formatted (fmt-hex set-length))))
        (cons 'set-salt (list (cons 'raw set-salt) (cons 'formatted (fmt-hex set-salt))))
        (cons 'tlv-devicemac (list (cons 'raw tlv-devicemac) (cons 'formatted (fmt-mac tlv-devicemac))))
        (cons 'set-authdata (list (cons 'raw set-authdata) (cons 'formatted (fmt-bytes set-authdata))))
        (cons 'tlv-version (list (cons 'raw tlv-version) (cons 'formatted (fmt-ipv4 tlv-version))))
        (cons 'tlv-typeip (list (cons 'raw tlv-typeip) (cons 'formatted (fmt-ipv4 tlv-typeip))))
        (cons 'tlv-typestring (list (cons 'raw tlv-typestring) (cons 'formatted (utf8->string tlv-typestring))))
        (cons 'getresp-unknown1 (list (cons 'raw getresp-unknown1) (cons 'formatted (fmt-hex getresp-unknown1))))
        (cons 'tlv-data (list (cons 'raw tlv-data) (cons 'formatted (fmt-bytes tlv-data))))
        )))

    (catch (e)
      (err (str "3COM-NJACK parse error: " e)))))

;; dissect-3com-njack: parse 3COM-NJACK from bytevector
;; Returns (ok fields-alist) or (err message)