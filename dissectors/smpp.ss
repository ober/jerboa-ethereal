;; packet-smpp.c
;; Routines for Short Message Peer to Peer dissection
;; Copyright 2001, Tom Uijldert.
;;
;; Data Coding Scheme decoding for GSM (SMS and CBS),
;; provided by Olivier Biot.
;;
;; Dissection of multiple SMPP PDUs within one packet
;; provided by Chris Wilson.
;;
;; Statistics support using Stats Tree API
;; provided by Abhik Sarkar
;;
;; Support for SMPP 5.0
;; introduced by Abhik Sarkar
;;
;; Support for Huawei SMPP+ extensions
;; introduced by Xu Bo and enhanced by Abhik Sarkar
;;
;; Enhanced error code handling
;; provided by Stipe Tolj from Kannel.
;;
;; Refer to the AUTHORS file or the AUTHORS section in the man page
;; for contacting the author(s) of this file.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; ----------
;;
;; Dissector of an SMPP (Short Message Peer to Peer) PDU, as defined by the
;; SMS forum (www.smsforum.net) in "SMPP protocol specification v3.4"
;; (document version: 12-Oct-1999 Issue 1.2)
;;

;; jerboa-ethereal/dissectors/smpp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-smpp.c

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
(def (dissect-smpp buffer)
  "Short Message Peer to Peer"
  (try
    (let* (
           (command-length (unwrap (read-u32be buffer 0)))
           (command-request (unwrap (read-u8 buffer 4)))
           (command-response (unwrap (read-u8 buffer 4)))
           (sequence-number (unwrap (read-u32be buffer 12)))
           (protocol-id (unwrap (read-u8 buffer 26)))
           (short-message-bin (unwrap (slice buffer 30 1)))
           (sm-default-msg-id (unwrap (read-u8 buffer 42)))
           (error-code (unwrap (read-u8 buffer 61)))
           (smpp-length-auth (unwrap (read-u32be buffer 65)))
           (smpp-service-id (unwrap (read-u32be buffer 73)))
           )

      (ok (list
        (cons 'command-length (list (cons 'raw command-length) (cons 'formatted (number->string command-length))))
        (cons 'command-request (list (cons 'raw command-request) (cons 'formatted (number->string command-request))))
        (cons 'command-response (list (cons 'raw command-response) (cons 'formatted (number->string command-response))))
        (cons 'sequence-number (list (cons 'raw sequence-number) (cons 'formatted (number->string sequence-number))))
        (cons 'protocol-id (list (cons 'raw protocol-id) (cons 'formatted (fmt-hex protocol-id))))
        (cons 'short-message-bin (list (cons 'raw short-message-bin) (cons 'formatted (fmt-bytes short-message-bin))))
        (cons 'sm-default-msg-id (list (cons 'raw sm-default-msg-id) (cons 'formatted (number->string sm-default-msg-id))))
        (cons 'error-code (list (cons 'raw error-code) (cons 'formatted (number->string error-code))))
        (cons 'smpp-length-auth (list (cons 'raw smpp-length-auth) (cons 'formatted (number->string smpp-length-auth))))
        (cons 'smpp-service-id (list (cons 'raw smpp-service-id) (cons 'formatted (number->string smpp-service-id))))
        )))

    (catch (e)
      (err (str "SMPP parse error: " e)))))

;; dissect-smpp: parse SMPP from bytevector
;; Returns (ok fields-alist) or (err message)