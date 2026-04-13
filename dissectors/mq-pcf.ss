;; packet-mq-pcf.c
;; Routines for IBM WebSphere MQ PCF packet dissection
;;
;; metatech <metatech@flashmail.com>
;; Robert Grange <robionekenobi@bluewin.ch>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mq-pcf.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mq_pcf.c

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
(def (dissect-mq-pcf buffer)
  "WebSphere MQ Programmable Command Formats"
  (try
    (let* (
           (cfh-length (unwrap (read-u32be buffer 0)))
           (cfh-version (unwrap (read-u32be buffer 0)))
           (cfh-MsgSeqNbr (unwrap (read-u32be buffer 0)))
           (cfh-ParmCount (unwrap (read-u32be buffer 0)))
           (pcf-prmlen (unwrap (read-u32be buffer 4)))
           (pcf-prmcount (unwrap (read-u32be buffer 4)))
           (pcf-prmstrlen (unwrap (read-u32be buffer 4)))
           (pcf-stringlist (unwrap (slice buffer 4 1)))
           (pcf-bytestring (unwrap (slice buffer 4 1)))
           (pcf-prmunused (unwrap (read-u32be buffer 4)))
           (pcf-int64list (unwrap (read-u64be buffer 4)))
           )

      (ok (list
        (cons 'cfh-length (list (cons 'raw cfh-length) (cons 'formatted (number->string cfh-length))))
        (cons 'cfh-version (list (cons 'raw cfh-version) (cons 'formatted (number->string cfh-version))))
        (cons 'cfh-MsgSeqNbr (list (cons 'raw cfh-MsgSeqNbr) (cons 'formatted (number->string cfh-MsgSeqNbr))))
        (cons 'cfh-ParmCount (list (cons 'raw cfh-ParmCount) (cons 'formatted (number->string cfh-ParmCount))))
        (cons 'pcf-prmlen (list (cons 'raw pcf-prmlen) (cons 'formatted (number->string pcf-prmlen))))
        (cons 'pcf-prmcount (list (cons 'raw pcf-prmcount) (cons 'formatted (number->string pcf-prmcount))))
        (cons 'pcf-prmstrlen (list (cons 'raw pcf-prmstrlen) (cons 'formatted (number->string pcf-prmstrlen))))
        (cons 'pcf-stringlist (list (cons 'raw pcf-stringlist) (cons 'formatted (utf8->string pcf-stringlist))))
        (cons 'pcf-bytestring (list (cons 'raw pcf-bytestring) (cons 'formatted (fmt-bytes pcf-bytestring))))
        (cons 'pcf-prmunused (list (cons 'raw pcf-prmunused) (cons 'formatted (number->string pcf-prmunused))))
        (cons 'pcf-int64list (list (cons 'raw pcf-int64list) (cons 'formatted (number->string pcf-int64list))))
        )))

    (catch (e)
      (err (str "MQ-PCF parse error: " e)))))

;; dissect-mq-pcf: parse MQ-PCF from bytevector
;; Returns (ok fields-alist) or (err message)