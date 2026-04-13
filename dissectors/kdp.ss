;; packet-kdp.c
;; Routines for KDP (Kontiki Delivery Protocol) packet disassembly
;;
;; Copyright (c) 2008 by Kontiki Inc.
;; Wade Hennessey <wade@kontiki.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/kdp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-kdp.c

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
(def (dissect-kdp buffer)
  "Kontiki Delivery Protocol"
  (try
    (let* (
           (xml-body (unwrap (slice buffer 0 1)))
           (version (unwrap (read-u8 buffer 0)))
           (headerlen (unwrap (read-u8 buffer 1)))
           (dup-flag (unwrap (read-u8 buffer 2)))
           (bcst-flag (unwrap (read-u8 buffer 2)))
           (rst-flag (unwrap (read-u8 buffer 2)))
           (ack-flag (unwrap (read-u8 buffer 2)))
           (syn-flag (unwrap (read-u8 buffer 2)))
           (drop-flag (unwrap (read-u8 buffer 2)))
           (flags (unwrap (read-u8 buffer 2)))
           (errors (unwrap (read-u8 buffer 3)))
           (destflowid (unwrap (read-u32be buffer 4)))
           (srcflowid (unwrap (read-u32be buffer 4)))
           (sequence (unwrap (read-u32be buffer 4)))
           (ack (unwrap (read-u32be buffer 4)))
           (maxsegmentsize (unwrap (read-u32be buffer 4)))
           (optionnumber (unwrap (read-u8 buffer 4)))
           (optionlen (unwrap (read-u8 buffer 4)))
           (option1 (unwrap (read-u16be buffer 4)))
           (option2 (unwrap (read-u16be buffer 4)))
           (option3 (unwrap (read-u16be buffer 4)))
           (option6 (unwrap (slice buffer 4 1)))
           (option7 (unwrap (read-u16be buffer 4)))
           (option8 (unwrap (read-u16be buffer 4)))
           (option9 (unwrap (read-u16be buffer 4)))
           (option-unknown (unwrap (slice buffer 4 1)))
           (fragment (unwrap (read-u16be buffer 4)))
           (fragtotal (unwrap (read-u16be buffer 4)))
           (body (unwrap (slice buffer 4 1)))
           )

      (ok (list
        (cons 'xml-body (list (cons 'raw xml-body) (cons 'formatted (utf8->string xml-body))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'headerlen (list (cons 'raw headerlen) (cons 'formatted (number->string headerlen))))
        (cons 'dup-flag (list (cons 'raw dup-flag) (cons 'formatted (number->string dup-flag))))
        (cons 'bcst-flag (list (cons 'raw bcst-flag) (cons 'formatted (number->string bcst-flag))))
        (cons 'rst-flag (list (cons 'raw rst-flag) (cons 'formatted (number->string rst-flag))))
        (cons 'ack-flag (list (cons 'raw ack-flag) (cons 'formatted (number->string ack-flag))))
        (cons 'syn-flag (list (cons 'raw syn-flag) (cons 'formatted (number->string syn-flag))))
        (cons 'drop-flag (list (cons 'raw drop-flag) (cons 'formatted (number->string drop-flag))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'errors (list (cons 'raw errors) (cons 'formatted (number->string errors))))
        (cons 'destflowid (list (cons 'raw destflowid) (cons 'formatted (fmt-hex destflowid))))
        (cons 'srcflowid (list (cons 'raw srcflowid) (cons 'formatted (fmt-hex srcflowid))))
        (cons 'sequence (list (cons 'raw sequence) (cons 'formatted (fmt-hex sequence))))
        (cons 'ack (list (cons 'raw ack) (cons 'formatted (fmt-hex ack))))
        (cons 'maxsegmentsize (list (cons 'raw maxsegmentsize) (cons 'formatted (fmt-hex maxsegmentsize))))
        (cons 'optionnumber (list (cons 'raw optionnumber) (cons 'formatted (fmt-hex optionnumber))))
        (cons 'optionlen (list (cons 'raw optionlen) (cons 'formatted (fmt-hex optionlen))))
        (cons 'option1 (list (cons 'raw option1) (cons 'formatted (fmt-hex option1))))
        (cons 'option2 (list (cons 'raw option2) (cons 'formatted (fmt-hex option2))))
        (cons 'option3 (list (cons 'raw option3) (cons 'formatted (fmt-hex option3))))
        (cons 'option6 (list (cons 'raw option6) (cons 'formatted (fmt-bytes option6))))
        (cons 'option7 (list (cons 'raw option7) (cons 'formatted (fmt-hex option7))))
        (cons 'option8 (list (cons 'raw option8) (cons 'formatted (fmt-hex option8))))
        (cons 'option9 (list (cons 'raw option9) (cons 'formatted (fmt-hex option9))))
        (cons 'option-unknown (list (cons 'raw option-unknown) (cons 'formatted (fmt-bytes option-unknown))))
        (cons 'fragment (list (cons 'raw fragment) (cons 'formatted (fmt-hex fragment))))
        (cons 'fragtotal (list (cons 'raw fragtotal) (cons 'formatted (fmt-hex fragtotal))))
        (cons 'body (list (cons 'raw body) (cons 'formatted (fmt-bytes body))))
        )))

    (catch (e)
      (err (str "KDP parse error: " e)))))

;; dissect-kdp: parse KDP from bytevector
;; Returns (ok fields-alist) or (err message)