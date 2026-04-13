;; packet-icq.c
;; Routines for ICQ packet disassembly
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/icq.ss
;; Auto-generated from wireshark/epan/dissectors/packet-icq.c

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
(def (dissect-icq buffer)
  "ICQ Protocol"
  (try
    (let* (
           (type (unwrap (read-u8 buffer 0)))
           (msg-length (unwrap (read-u16be buffer 2)))
           (msg (unwrap (slice buffer 4 1)))
           (msg-authorization (unwrap (read-u8 buffer 4)))
           (x1 (unwrap (read-u16be buffer 4)))
           (num-uin-pairs (unwrap (slice buffer 4 1)))
           (msg-contact (unwrap (slice buffer 4 1)))
           (text-code-length (unwrap (read-u16be buffer 4)))
           (text-code (unwrap (slice buffer 4 1)))
           (receiver-uin (unwrap (read-u32be buffer 4)))
           (login-time (unwrap (read-u32be buffer 4)))
           (login-port (unwrap (read-u32be buffer 4)))
           (login-password (unwrap (slice buffer 4 2)))
           (number-of-uins (unwrap (read-u8 buffer 4)))
           (user-online-ip (unwrap (read-u32be buffer 8)))
           (user-online-port (unwrap (read-u32be buffer 8)))
           (user-online-realip (unwrap (read-u32be buffer 8)))
           (user-online-version (unwrap (read-u32be buffer 8)))
           (multi-num-packets (unwrap (read-u8 buffer 8)))
           (meta-user-result (unwrap (read-u8 buffer 10)))
           (meta-user-length (unwrap (read-u16be buffer 13)))
           (meta-user-found-authorization (unwrap (read-u8 buffer 19)))
           (meta-user-x2 (unwrap (read-u16be buffer 19)))
           (meta-user-x3 (unwrap (read-u32be buffer 21)))
           (meta-user-countrycode (unwrap (read-u16be buffer 25)))
           (meta-user-timezone (unwrap (read-u8 buffer 27)))
           (meta-user-info-authorization (unwrap (read-u8 buffer 27)))
           (meta-user-webaware (unwrap (read-u8 buffer 27)))
           (meta-user-hideip (unwrap (read-u8 buffer 27)))
           (uin (unwrap (read-u32be buffer 27)))
           (recv-time (unwrap (slice buffer 27 2)))
           (rand-user-ip (unwrap (read-u32be buffer 27)))
           (rand-user-port (unwrap (read-u32be buffer 27)))
           (rand-user-realip (unwrap (read-u32be buffer 27)))
           (rand-user-class (unwrap (read-u8 buffer 27)))
           (rand-user-tcpversion (unwrap (read-u16be buffer 27)))
           (version (unwrap (read-u16be buffer 27)))
           (sessionid (unwrap (read-u32be buffer 27)))
           (seqnum1 (unwrap (read-u16be buffer 27)))
           (seqnum2 (unwrap (read-u16be buffer 27)))
           (checkcode (unwrap (read-u32be buffer 27)))
           )

      (ok (list
        (cons 'type (list (cons 'raw type) (cons 'formatted (if (= type 0) "False" "True"))))
        (cons 'msg-length (list (cons 'raw msg-length) (cons 'formatted (number->string msg-length))))
        (cons 'msg (list (cons 'raw msg) (cons 'formatted (utf8->string msg))))
        (cons 'msg-authorization (list (cons 'raw msg-authorization) (cons 'formatted (number->string msg-authorization))))
        (cons 'x1 (list (cons 'raw x1) (cons 'formatted (fmt-hex x1))))
        (cons 'num-uin-pairs (list (cons 'raw num-uin-pairs) (cons 'formatted (utf8->string num-uin-pairs))))
        (cons 'msg-contact (list (cons 'raw msg-contact) (cons 'formatted (utf8->string msg-contact))))
        (cons 'text-code-length (list (cons 'raw text-code-length) (cons 'formatted (number->string text-code-length))))
        (cons 'text-code (list (cons 'raw text-code) (cons 'formatted (utf8->string text-code))))
        (cons 'receiver-uin (list (cons 'raw receiver-uin) (cons 'formatted (number->string receiver-uin))))
        (cons 'login-time (list (cons 'raw login-time) (cons 'formatted (number->string login-time))))
        (cons 'login-port (list (cons 'raw login-port) (cons 'formatted (number->string login-port))))
        (cons 'login-password (list (cons 'raw login-password) (cons 'formatted (utf8->string login-password))))
        (cons 'number-of-uins (list (cons 'raw number-of-uins) (cons 'formatted (number->string number-of-uins))))
        (cons 'user-online-ip (list (cons 'raw user-online-ip) (cons 'formatted (fmt-ipv4 user-online-ip))))
        (cons 'user-online-port (list (cons 'raw user-online-port) (cons 'formatted (number->string user-online-port))))
        (cons 'user-online-realip (list (cons 'raw user-online-realip) (cons 'formatted (fmt-ipv4 user-online-realip))))
        (cons 'user-online-version (list (cons 'raw user-online-version) (cons 'formatted (fmt-hex user-online-version))))
        (cons 'multi-num-packets (list (cons 'raw multi-num-packets) (cons 'formatted (number->string multi-num-packets))))
        (cons 'meta-user-result (list (cons 'raw meta-user-result) (cons 'formatted (number->string meta-user-result))))
        (cons 'meta-user-length (list (cons 'raw meta-user-length) (cons 'formatted (number->string meta-user-length))))
        (cons 'meta-user-found-authorization (list (cons 'raw meta-user-found-authorization) (cons 'formatted (number->string meta-user-found-authorization))))
        (cons 'meta-user-x2 (list (cons 'raw meta-user-x2) (cons 'formatted (fmt-hex meta-user-x2))))
        (cons 'meta-user-x3 (list (cons 'raw meta-user-x3) (cons 'formatted (fmt-hex meta-user-x3))))
        (cons 'meta-user-countrycode (list (cons 'raw meta-user-countrycode) (cons 'formatted (number->string meta-user-countrycode))))
        (cons 'meta-user-timezone (list (cons 'raw meta-user-timezone) (cons 'formatted (number->string meta-user-timezone))))
        (cons 'meta-user-info-authorization (list (cons 'raw meta-user-info-authorization) (cons 'formatted (if (= meta-user-info-authorization 0) "False" "True"))))
        (cons 'meta-user-webaware (list (cons 'raw meta-user-webaware) (cons 'formatted (if (= meta-user-webaware 0) "False" "True"))))
        (cons 'meta-user-hideip (list (cons 'raw meta-user-hideip) (cons 'formatted (if (= meta-user-hideip 0) "False" "True"))))
        (cons 'uin (list (cons 'raw uin) (cons 'formatted (number->string uin))))
        (cons 'recv-time (list (cons 'raw recv-time) (cons 'formatted (fmt-bytes recv-time))))
        (cons 'rand-user-ip (list (cons 'raw rand-user-ip) (cons 'formatted (fmt-ipv4 rand-user-ip))))
        (cons 'rand-user-port (list (cons 'raw rand-user-port) (cons 'formatted (number->string rand-user-port))))
        (cons 'rand-user-realip (list (cons 'raw rand-user-realip) (cons 'formatted (fmt-ipv4 rand-user-realip))))
        (cons 'rand-user-class (list (cons 'raw rand-user-class) (cons 'formatted (number->string rand-user-class))))
        (cons 'rand-user-tcpversion (list (cons 'raw rand-user-tcpversion) (cons 'formatted (number->string rand-user-tcpversion))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'sessionid (list (cons 'raw sessionid) (cons 'formatted (fmt-hex sessionid))))
        (cons 'seqnum1 (list (cons 'raw seqnum1) (cons 'formatted (fmt-hex seqnum1))))
        (cons 'seqnum2 (list (cons 'raw seqnum2) (cons 'formatted (fmt-hex seqnum2))))
        (cons 'checkcode (list (cons 'raw checkcode) (cons 'formatted (fmt-hex checkcode))))
        )))

    (catch (e)
      (err (str "ICQ parse error: " e)))))

;; dissect-icq: parse ICQ from bytevector
;; Returns (ok fields-alist) or (err message)