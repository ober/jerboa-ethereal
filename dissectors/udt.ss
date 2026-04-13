;; packet-udt.c
;;
;; Routines for UDT packet dissection
;; http://udt.sourceforge.net
;; draft-gg-udt
;;
;; Copyright 2013 (c) chas williams <chas@cmf.nrl.navy.mil>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-tftp.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/udt.ss
;; Auto-generated from wireshark/epan/dissectors/packet-udt.c

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
(def (dissect-udt buffer)
  "UDT Protocol"
  (try
    (let* (
           (seqno (unwrap (read-u32be buffer 0)))
           (msgno (unwrap (read-u32be buffer 4)))
           (msgno-inorder (unwrap (read-u32be buffer 4)))
           (msgno-last (unwrap (read-u32be buffer 4)))
           (msgno-first (unwrap (read-u32be buffer 4)))
           (addinfo (unwrap (read-u32be buffer 4)))
           (ackno (unwrap (read-u32be buffer 4)))
           (timestamp (unwrap (read-u32be buffer 8)))
           (id (unwrap (read-u32be buffer 12)))
           (ack-seqno (unwrap (read-u32be buffer 16)))
           (handshake-version (unwrap (read-u32be buffer 16)))
           (rtt (unwrap (read-u32be buffer 20)))
           (rttvar (unwrap (read-u32be buffer 24)))
           (handshake-isn (unwrap (read-u32be buffer 24)))
           (bufavail (unwrap (read-u32be buffer 28)))
           (handshake-mtu (unwrap (read-u32be buffer 28)))
           (rate (unwrap (read-u32be buffer 32)))
           (handshake-flow-window (unwrap (read-u32be buffer 32)))
           (linkcap (unwrap (read-u32be buffer 36)))
           (handshake-reqtype (unwrap (read-u32be buffer 36)))
           (handshake-id (unwrap (read-u32be buffer 40)))
           (handshake-cookie (unwrap (read-u32be buffer 44)))
           (handshake-peerip (unwrap (slice buffer 48 16)))
           )

      (ok (list
        (cons 'seqno (list (cons 'raw seqno) (cons 'formatted (number->string seqno))))
        (cons 'msgno (list (cons 'raw msgno) (cons 'formatted (number->string msgno))))
        (cons 'msgno-inorder (list (cons 'raw msgno-inorder) (cons 'formatted (number->string msgno-inorder))))
        (cons 'msgno-last (list (cons 'raw msgno-last) (cons 'formatted (number->string msgno-last))))
        (cons 'msgno-first (list (cons 'raw msgno-first) (cons 'formatted (number->string msgno-first))))
        (cons 'addinfo (list (cons 'raw addinfo) (cons 'formatted (number->string addinfo))))
        (cons 'ackno (list (cons 'raw ackno) (cons 'formatted (number->string ackno))))
        (cons 'timestamp (list (cons 'raw timestamp) (cons 'formatted (number->string timestamp))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (fmt-hex id))))
        (cons 'ack-seqno (list (cons 'raw ack-seqno) (cons 'formatted (number->string ack-seqno))))
        (cons 'handshake-version (list (cons 'raw handshake-version) (cons 'formatted (number->string handshake-version))))
        (cons 'rtt (list (cons 'raw rtt) (cons 'formatted (number->string rtt))))
        (cons 'rttvar (list (cons 'raw rttvar) (cons 'formatted (number->string rttvar))))
        (cons 'handshake-isn (list (cons 'raw handshake-isn) (cons 'formatted (number->string handshake-isn))))
        (cons 'bufavail (list (cons 'raw bufavail) (cons 'formatted (number->string bufavail))))
        (cons 'handshake-mtu (list (cons 'raw handshake-mtu) (cons 'formatted (number->string handshake-mtu))))
        (cons 'rate (list (cons 'raw rate) (cons 'formatted (number->string rate))))
        (cons 'handshake-flow-window (list (cons 'raw handshake-flow-window) (cons 'formatted (number->string handshake-flow-window))))
        (cons 'linkcap (list (cons 'raw linkcap) (cons 'formatted (number->string linkcap))))
        (cons 'handshake-reqtype (list (cons 'raw handshake-reqtype) (cons 'formatted (number->string handshake-reqtype))))
        (cons 'handshake-id (list (cons 'raw handshake-id) (cons 'formatted (number->string handshake-id))))
        (cons 'handshake-cookie (list (cons 'raw handshake-cookie) (cons 'formatted (fmt-hex handshake-cookie))))
        (cons 'handshake-peerip (list (cons 'raw handshake-peerip) (cons 'formatted (fmt-bytes handshake-peerip))))
        )))

    (catch (e)
      (err (str "UDT parse error: " e)))))

;; dissect-udt: parse UDT from bytevector
;; Returns (ok fields-alist) or (err message)