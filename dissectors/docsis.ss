;; packet-docsis.c
;; Routines for docsis dissection
;; Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/docsis.ss
;; Auto-generated from wireshark/epan/dissectors/packet-docsis.c

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
(def (dissect-docsis buffer)
  "DOCSIS"
  (try
    (let* (
           (concat-cnt (unwrap (read-u8 buffer 1)))
           (requested-size (unwrap (read-u16be buffer 1)))
           (mini-slots (unwrap (read-u8 buffer 1)))
           (macparm (unwrap (read-u8 buffer 1)))
           (ehdrlen (unwrap (read-u8 buffer 1)))
           (sid (unwrap (read-u16be buffer 2)))
           (len (unwrap (read-u16be buffer 2)))
           (encrypted-payload (unwrap (slice buffer 12 1)))
           )

      (ok (list
        (cons 'concat-cnt (list (cons 'raw concat-cnt) (cons 'formatted (number->string concat-cnt))))
        (cons 'requested-size (list (cons 'raw requested-size) (cons 'formatted (number->string requested-size))))
        (cons 'mini-slots (list (cons 'raw mini-slots) (cons 'formatted (number->string mini-slots))))
        (cons 'macparm (list (cons 'raw macparm) (cons 'formatted (fmt-hex macparm))))
        (cons 'ehdrlen (list (cons 'raw ehdrlen) (cons 'formatted (number->string ehdrlen))))
        (cons 'sid (list (cons 'raw sid) (cons 'formatted (number->string sid))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'encrypted-payload (list (cons 'raw encrypted-payload) (cons 'formatted (fmt-bytes encrypted-payload))))
        )))

    (catch (e)
      (err (str "DOCSIS parse error: " e)))))

;; dissect-docsis: parse DOCSIS from bytevector
;; Returns (ok fields-alist) or (err message)