;; packet-openvpn.c
;; routines for openvpn packet disassembly
;; - http://www.openvpn.net
;; - http://fengnet.com/book/vpns%20illustrated%20tunnels%20%20vpnsand%20ipsec/ch08lev1sec5.html
;;
;; Created as part of a semester project at the University of Applied Sciences Hagenberg
;; (http://www.fh-ooe.at/en/hagenberg-campus/)
;;
;; Copyright (c) 2013:
;; Hofer Manuel (manuel@mnlhfr.at)
;; Nemeth Franz
;; Scheipner Alexander
;; Stiftinger Thomas
;; Werner Sebastian
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/openvpn.ss
;; Auto-generated from wireshark/epan/dissectors/packet-openvpn.c

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
(def (dissect-openvpn buffer)
  "OpenVPN Protocol"
  (try
    (let* (
           (plen (unwrap (read-u16be buffer 0)))
           (pdu-type (unwrap (read-u8 buffer 0)))
           (keyid (unwrap (read-u8 buffer 0)))
           (peerid (unwrap (read-u24be buffer 1)))
           (sessionid (unwrap (read-u64be buffer 4)))
           (pid (unwrap (read-u32be buffer 12)))
           (hmac (unwrap (slice buffer 20 32)))
           (mpid-arraylength (unwrap (read-u8 buffer 52)))
           (mpid-arrayelement (unwrap (read-u32be buffer 53)))
           (rsessionid (unwrap (read-u64be buffer 57)))
           (mpid (unwrap (read-u32be buffer 65)))
           (data (unwrap (slice buffer 69 1)))
           )

      (ok (list
        (cons 'plen (list (cons 'raw plen) (cons 'formatted (number->string plen))))
        (cons 'pdu-type (list (cons 'raw pdu-type) (cons 'formatted (fmt-hex pdu-type))))
        (cons 'keyid (list (cons 'raw keyid) (cons 'formatted (number->string keyid))))
        (cons 'peerid (list (cons 'raw peerid) (cons 'formatted (number->string peerid))))
        (cons 'sessionid (list (cons 'raw sessionid) (cons 'formatted (number->string sessionid))))
        (cons 'pid (list (cons 'raw pid) (cons 'formatted (number->string pid))))
        (cons 'hmac (list (cons 'raw hmac) (cons 'formatted (fmt-bytes hmac))))
        (cons 'mpid-arraylength (list (cons 'raw mpid-arraylength) (cons 'formatted (number->string mpid-arraylength))))
        (cons 'mpid-arrayelement (list (cons 'raw mpid-arrayelement) (cons 'formatted (number->string mpid-arrayelement))))
        (cons 'rsessionid (list (cons 'raw rsessionid) (cons 'formatted (number->string rsessionid))))
        (cons 'mpid (list (cons 'raw mpid) (cons 'formatted (number->string mpid))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        )))

    (catch (e)
      (err (str "OPENVPN parse error: " e)))))

;; dissect-openvpn: parse OPENVPN from bytevector
;; Returns (ok fields-alist) or (err message)