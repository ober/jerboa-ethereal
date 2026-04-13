;; packet-starteam.c
;; Routines for Borland StarTeam packet dissection
;;
;; metatech <metatech[AT]flashmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/starteam.ss
;; Auto-generated from wireshark/epan/dissectors/packet-starteam.c

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
(def (dissect-starteam buffer)
  "StarTeam"
  (try
    (let* (
           (mdh-ctimestamp (unwrap (read-u32be buffer 0)))
           (mdh-flags (unwrap (read-u32be buffer 0)))
           (mdh-keyid (unwrap (read-u32be buffer 0)))
           (mdh-reserved (unwrap (read-u32be buffer 0)))
           (ph-signature (unwrap (slice buffer 20 4)))
           (ph-packet-size (unwrap (read-u32be buffer 20)))
           (ph-data-size (unwrap (read-u32be buffer 20)))
           (ph-data-flags (unwrap (read-u32be buffer 20)))
           (id-revision-level (unwrap (read-u16be buffer 36)))
           (id-client (unwrap (slice buffer 36 16)))
           (id-connect (unwrap (read-u32be buffer 36)))
           (id-component (unwrap (read-u32be buffer 36)))
           (id-command-time (unwrap (read-u32be buffer 36)))
           (id-command-userid (unwrap (read-u32be buffer 36)))
           (data-data (unwrap (slice buffer 74 1)))
           (mdh-session-tag (unwrap (read-u32be buffer 75)))
           )

      (ok (list
        (cons 'mdh-ctimestamp (list (cons 'raw mdh-ctimestamp) (cons 'formatted (number->string mdh-ctimestamp))))
        (cons 'mdh-flags (list (cons 'raw mdh-flags) (cons 'formatted (fmt-hex mdh-flags))))
        (cons 'mdh-keyid (list (cons 'raw mdh-keyid) (cons 'formatted (fmt-hex mdh-keyid))))
        (cons 'mdh-reserved (list (cons 'raw mdh-reserved) (cons 'formatted (fmt-hex mdh-reserved))))
        (cons 'ph-signature (list (cons 'raw ph-signature) (cons 'formatted (utf8->string ph-signature))))
        (cons 'ph-packet-size (list (cons 'raw ph-packet-size) (cons 'formatted (number->string ph-packet-size))))
        (cons 'ph-data-size (list (cons 'raw ph-data-size) (cons 'formatted (number->string ph-data-size))))
        (cons 'ph-data-flags (list (cons 'raw ph-data-flags) (cons 'formatted (fmt-hex ph-data-flags))))
        (cons 'id-revision-level (list (cons 'raw id-revision-level) (cons 'formatted (number->string id-revision-level))))
        (cons 'id-client (list (cons 'raw id-client) (cons 'formatted (utf8->string id-client))))
        (cons 'id-connect (list (cons 'raw id-connect) (cons 'formatted (fmt-hex id-connect))))
        (cons 'id-component (list (cons 'raw id-component) (cons 'formatted (number->string id-component))))
        (cons 'id-command-time (list (cons 'raw id-command-time) (cons 'formatted (fmt-hex id-command-time))))
        (cons 'id-command-userid (list (cons 'raw id-command-userid) (cons 'formatted (fmt-hex id-command-userid))))
        (cons 'data-data (list (cons 'raw data-data) (cons 'formatted (utf8->string data-data))))
        (cons 'mdh-session-tag (list (cons 'raw mdh-session-tag) (cons 'formatted (number->string mdh-session-tag))))
        )))

    (catch (e)
      (err (str "STARTEAM parse error: " e)))))

;; dissect-starteam: parse STARTEAM from bytevector
;; Returns (ok fields-alist) or (err message)