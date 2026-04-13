;; packet-srt.c
;; Routines for Secure Reliable Transport Protocol dissection
;; Copyright (c) 2018 Haivision Systems Inc. <info@srtalliance.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/srt.ss
;; Auto-generated from wireshark/epan/dissectors/packet-srt.c

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
(def (dissect-srt buffer)
  "SRT Protocol"
  (try
    (let* (
           (seqno (unwrap (read-u32be buffer 0)))
           (iscontrol (unwrap (read-u8 buffer 0)))
           (exttype-none (unwrap (read-u16be buffer 2)))
           (msgno-rexmit (unwrap (read-u8 buffer 4)))
           (msgno-inorder (unwrap (read-u32be buffer 4)))
           (addinfo (unwrap (read-u32be buffer 4)))
           (msgno (unwrap (read-u32be buffer 4)))
           (ackno (unwrap (read-u32be buffer 4)))
           (timestamp (unwrap (read-u32be buffer 8)))
           (id (unwrap (read-u32be buffer 12)))
           (handshake-version (unwrap (read-u32be buffer 16)))
           (handshake-isn (unwrap (read-u32be buffer 24)))
           (handshake-mtu (unwrap (read-u32be buffer 28)))
           (handshake-flow-window (unwrap (read-u32be buffer 32)))
           (handshake-failure-type (unwrap (read-u32be buffer 36)))
           (handshake-id (unwrap (read-u32be buffer 40)))
           (handshake-cookie (unwrap (read-u32be buffer 44)))
           (handshake-peerip (unwrap (slice buffer 48 16)))
           )

      (ok (list
        (cons 'seqno (list (cons 'raw seqno) (cons 'formatted (number->string seqno))))
        (cons 'iscontrol (list (cons 'raw iscontrol) (cons 'formatted (if (= iscontrol 0) "False" "True"))))
        (cons 'exttype-none (list (cons 'raw exttype-none) (cons 'formatted (fmt-hex exttype-none))))
        (cons 'msgno-rexmit (list (cons 'raw msgno-rexmit) (cons 'formatted (if (= msgno-rexmit 0) "False" "True"))))
        (cons 'msgno-inorder (list (cons 'raw msgno-inorder) (cons 'formatted (number->string msgno-inorder))))
        (cons 'addinfo (list (cons 'raw addinfo) (cons 'formatted (number->string addinfo))))
        (cons 'msgno (list (cons 'raw msgno) (cons 'formatted (number->string msgno))))
        (cons 'ackno (list (cons 'raw ackno) (cons 'formatted (number->string ackno))))
        (cons 'timestamp (list (cons 'raw timestamp) (cons 'formatted (number->string timestamp))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'handshake-version (list (cons 'raw handshake-version) (cons 'formatted (number->string handshake-version))))
        (cons 'handshake-isn (list (cons 'raw handshake-isn) (cons 'formatted (number->string handshake-isn))))
        (cons 'handshake-mtu (list (cons 'raw handshake-mtu) (cons 'formatted (number->string handshake-mtu))))
        (cons 'handshake-flow-window (list (cons 'raw handshake-flow-window) (cons 'formatted (number->string handshake-flow-window))))
        (cons 'handshake-failure-type (list (cons 'raw handshake-failure-type) (cons 'formatted (number->string handshake-failure-type))))
        (cons 'handshake-id (list (cons 'raw handshake-id) (cons 'formatted (number->string handshake-id))))
        (cons 'handshake-cookie (list (cons 'raw handshake-cookie) (cons 'formatted (fmt-hex handshake-cookie))))
        (cons 'handshake-peerip (list (cons 'raw handshake-peerip) (cons 'formatted (utf8->string handshake-peerip))))
        )))

    (catch (e)
      (err (str "SRT parse error: " e)))))

;; dissect-srt: parse SRT from bytevector
;; Returns (ok fields-alist) or (err message)