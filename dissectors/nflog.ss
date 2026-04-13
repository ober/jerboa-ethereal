;; packet-nflog.c
;; Copyright 2011,2012 Jakub Zawadzki <darkjames-ws@darkjames.pl>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nflog.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nflog.c

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
(def (dissect-nflog buffer)
  "Linux Netfilter NFLOG"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 1)))
           (resid (unwrap (read-u16be buffer 2)))
           (tlv (unwrap (slice buffer 4 1)))
           (tlv-length (unwrap (read-u16be buffer 4)))
           (tlv-ifindex-indev (unwrap (read-u32be buffer 4)))
           (tlv-ifindex-outdev (unwrap (read-u32be buffer 4)))
           (tlv-ifindex-physindev (unwrap (read-u32be buffer 4)))
           (tlv-ifindex-physoutdev (unwrap (read-u32be buffer 4)))
           (tlv-prefix (unwrap (slice buffer 4 1)))
           (tlv-uid (unwrap (read-u32be buffer 4)))
           (tlv-gid (unwrap (read-u32be buffer 4)))
           (tlv-hwheader-len (unwrap (read-u16be buffer 4)))
           (tlv-ct (unwrap (slice buffer 4 1)))
           (tlv-unknown (unwrap (slice buffer 4 1)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'resid (list (cons 'raw resid) (cons 'formatted (number->string resid))))
        (cons 'tlv (list (cons 'raw tlv) (cons 'formatted (fmt-bytes tlv))))
        (cons 'tlv-length (list (cons 'raw tlv-length) (cons 'formatted (number->string tlv-length))))
        (cons 'tlv-ifindex-indev (list (cons 'raw tlv-ifindex-indev) (cons 'formatted (number->string tlv-ifindex-indev))))
        (cons 'tlv-ifindex-outdev (list (cons 'raw tlv-ifindex-outdev) (cons 'formatted (number->string tlv-ifindex-outdev))))
        (cons 'tlv-ifindex-physindev (list (cons 'raw tlv-ifindex-physindev) (cons 'formatted (number->string tlv-ifindex-physindev))))
        (cons 'tlv-ifindex-physoutdev (list (cons 'raw tlv-ifindex-physoutdev) (cons 'formatted (number->string tlv-ifindex-physoutdev))))
        (cons 'tlv-prefix (list (cons 'raw tlv-prefix) (cons 'formatted (utf8->string tlv-prefix))))
        (cons 'tlv-uid (list (cons 'raw tlv-uid) (cons 'formatted (number->string tlv-uid))))
        (cons 'tlv-gid (list (cons 'raw tlv-gid) (cons 'formatted (number->string tlv-gid))))
        (cons 'tlv-hwheader-len (list (cons 'raw tlv-hwheader-len) (cons 'formatted (number->string tlv-hwheader-len))))
        (cons 'tlv-ct (list (cons 'raw tlv-ct) (cons 'formatted (utf8->string tlv-ct))))
        (cons 'tlv-unknown (list (cons 'raw tlv-unknown) (cons 'formatted (fmt-bytes tlv-unknown))))
        )))

    (catch (e)
      (err (str "NFLOG parse error: " e)))))

;; dissect-nflog: parse NFLOG from bytevector
;; Returns (ok fields-alist) or (err message)