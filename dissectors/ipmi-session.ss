;; packet-ipmi-session.c
;; Routines for dissection of IPMI session wrapper (v1.5 and v2.0)
;; Copyright 2007-2008, Alexey Neyman, Pigeon Point Systems <avn@pigeonpoint.com>
;; Copyright Duncan Laurie <duncan@sun.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Partially copied from packet-ipmi.c.
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ipmi-session.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ipmi_session.c

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
(def (dissect-ipmi-session buffer)
  "Intelligent Platform Management Interface (Session Wrapper)"
  (try
    (let* (
           (session-payloadtype-enc (unwrap (read-u8 buffer 0)))
           (session-payloadtype-auth (unwrap (read-u8 buffer 0)))
           (session-oem-iana (unwrap (slice buffer 0 4)))
           (session-oem-payload-id (unwrap (slice buffer 4 2)))
           (session-msg-len-2b (unwrap (read-u16be buffer 14)))
           (session-sequence (unwrap (read-u32be buffer 16)))
           (session-id (unwrap (read-u32be buffer 20)))
           (session-authcode (unwrap (slice buffer 24 16)))
           (session-msg-len-1b (unwrap (read-u8 buffer 40)))
           (session-trailer (unwrap (slice buffer 40 1)))
           )

      (ok (list
        (cons 'session-payloadtype-enc (list (cons 'raw session-payloadtype-enc) (cons 'formatted (if (= session-payloadtype-enc 0) "Payload is unencrypted" "Payload is encrypted"))))
        (cons 'session-payloadtype-auth (list (cons 'raw session-payloadtype-auth) (cons 'formatted (if (= session-payloadtype-auth 0) "Payload is unauthenticated" "Payload is authenticated"))))
        (cons 'session-oem-iana (list (cons 'raw session-oem-iana) (cons 'formatted (fmt-bytes session-oem-iana))))
        (cons 'session-oem-payload-id (list (cons 'raw session-oem-payload-id) (cons 'formatted (fmt-bytes session-oem-payload-id))))
        (cons 'session-msg-len-2b (list (cons 'raw session-msg-len-2b) (cons 'formatted (number->string session-msg-len-2b))))
        (cons 'session-sequence (list (cons 'raw session-sequence) (cons 'formatted (fmt-hex session-sequence))))
        (cons 'session-id (list (cons 'raw session-id) (cons 'formatted (fmt-hex session-id))))
        (cons 'session-authcode (list (cons 'raw session-authcode) (cons 'formatted (fmt-bytes session-authcode))))
        (cons 'session-msg-len-1b (list (cons 'raw session-msg-len-1b) (cons 'formatted (number->string session-msg-len-1b))))
        (cons 'session-trailer (list (cons 'raw session-trailer) (cons 'formatted (fmt-bytes session-trailer))))
        )))

    (catch (e)
      (err (str "IPMI-SESSION parse error: " e)))))

;; dissect-ipmi-session: parse IPMI-SESSION from bytevector
;; Returns (ok fields-alist) or (err message)