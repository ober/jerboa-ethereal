;; packet-glbp.c
;;
;; Cisco's GLBP:  Gateway Load Balancing Protocol
;;
;; Copyright 2007 Joerg Mayer (see AUTHORS file)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/glbp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-glbp.c

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
(def (dissect-glbp buffer)
  "Gateway Load Balancing Protocol"
  (try
    (let* (
           (hello-unknown10 (unwrap (slice buffer 0 1)))
           (hello-unknown11 (unwrap (slice buffer 0 1)))
           (hello-priority (unwrap (read-u8 buffer 0)))
           (hello-unknown12 (unwrap (slice buffer 0 2)))
           (version (unwrap (read-u8 buffer 0)))
           (unknown1 (unwrap (read-u8 buffer 0)))
           (group (unwrap (read-u16be buffer 0)))
           (hello-helloint (unwrap (read-u32be buffer 2)))
           (unknown2 (unwrap (slice buffer 2 2)))
           (ownerid (unwrap (slice buffer 4 6)))
           (hello-holdint (unwrap (read-u32be buffer 6)))
           (hello-redirect (unwrap (read-u16be buffer 10)))
           (tlv (unwrap (slice buffer 10 1)))
           (length (unwrap (read-u8 buffer 10)))
           (hello-timeout (unwrap (read-u16be buffer 12)))
           (hello-unknown13 (unwrap (slice buffer 14 2)))
           (hello-addrlen (unwrap (read-u8 buffer 16)))
           (hello-virtualipv4 (unwrap (read-u32be buffer 16)))
           (hello-virtualipv6 (unwrap (slice buffer 16 16)))
           (hello-virtualunk (unwrap (slice buffer 16 1)))
           (reqresp-forwarder (unwrap (read-u8 buffer 16)))
           (reqresp-unknown21 (unwrap (slice buffer 16 1)))
           (reqresp-priority (unwrap (read-u8 buffer 17)))
           (reqresp-weight (unwrap (read-u8 buffer 17)))
           (reqresp-unknown22 (unwrap (slice buffer 17 7)))
           (reqresp-virtualmac (unwrap (slice buffer 24 6)))
           (auth-authlength (unwrap (read-u8 buffer 30)))
           (auth-plainpass (unwrap (slice buffer 30 1)))
           (auth-md5hash (unwrap (slice buffer 30 1)))
           (auth-md5chainindex (unwrap (read-u32be buffer 30)))
           (auth-md5chainhash (unwrap (slice buffer 30 1)))
           (auth-authunknown (unwrap (slice buffer 30 1)))
           (unknown-data (unwrap (slice buffer 30 1)))
           )

      (ok (list
        (cons 'hello-unknown10 (list (cons 'raw hello-unknown10) (cons 'formatted (fmt-bytes hello-unknown10))))
        (cons 'hello-unknown11 (list (cons 'raw hello-unknown11) (cons 'formatted (fmt-bytes hello-unknown11))))
        (cons 'hello-priority (list (cons 'raw hello-priority) (cons 'formatted (number->string hello-priority))))
        (cons 'hello-unknown12 (list (cons 'raw hello-unknown12) (cons 'formatted (fmt-bytes hello-unknown12))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'unknown1 (list (cons 'raw unknown1) (cons 'formatted (number->string unknown1))))
        (cons 'group (list (cons 'raw group) (cons 'formatted (number->string group))))
        (cons 'hello-helloint (list (cons 'raw hello-helloint) (cons 'formatted (number->string hello-helloint))))
        (cons 'unknown2 (list (cons 'raw unknown2) (cons 'formatted (fmt-bytes unknown2))))
        (cons 'ownerid (list (cons 'raw ownerid) (cons 'formatted (fmt-mac ownerid))))
        (cons 'hello-holdint (list (cons 'raw hello-holdint) (cons 'formatted (number->string hello-holdint))))
        (cons 'hello-redirect (list (cons 'raw hello-redirect) (cons 'formatted (number->string hello-redirect))))
        (cons 'tlv (list (cons 'raw tlv) (cons 'formatted (fmt-bytes tlv))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'hello-timeout (list (cons 'raw hello-timeout) (cons 'formatted (number->string hello-timeout))))
        (cons 'hello-unknown13 (list (cons 'raw hello-unknown13) (cons 'formatted (fmt-bytes hello-unknown13))))
        (cons 'hello-addrlen (list (cons 'raw hello-addrlen) (cons 'formatted (number->string hello-addrlen))))
        (cons 'hello-virtualipv4 (list (cons 'raw hello-virtualipv4) (cons 'formatted (fmt-ipv4 hello-virtualipv4))))
        (cons 'hello-virtualipv6 (list (cons 'raw hello-virtualipv6) (cons 'formatted (fmt-ipv6-address hello-virtualipv6))))
        (cons 'hello-virtualunk (list (cons 'raw hello-virtualunk) (cons 'formatted (fmt-bytes hello-virtualunk))))
        (cons 'reqresp-forwarder (list (cons 'raw reqresp-forwarder) (cons 'formatted (number->string reqresp-forwarder))))
        (cons 'reqresp-unknown21 (list (cons 'raw reqresp-unknown21) (cons 'formatted (fmt-bytes reqresp-unknown21))))
        (cons 'reqresp-priority (list (cons 'raw reqresp-priority) (cons 'formatted (number->string reqresp-priority))))
        (cons 'reqresp-weight (list (cons 'raw reqresp-weight) (cons 'formatted (number->string reqresp-weight))))
        (cons 'reqresp-unknown22 (list (cons 'raw reqresp-unknown22) (cons 'formatted (fmt-bytes reqresp-unknown22))))
        (cons 'reqresp-virtualmac (list (cons 'raw reqresp-virtualmac) (cons 'formatted (fmt-mac reqresp-virtualmac))))
        (cons 'auth-authlength (list (cons 'raw auth-authlength) (cons 'formatted (number->string auth-authlength))))
        (cons 'auth-plainpass (list (cons 'raw auth-plainpass) (cons 'formatted (utf8->string auth-plainpass))))
        (cons 'auth-md5hash (list (cons 'raw auth-md5hash) (cons 'formatted (fmt-bytes auth-md5hash))))
        (cons 'auth-md5chainindex (list (cons 'raw auth-md5chainindex) (cons 'formatted (number->string auth-md5chainindex))))
        (cons 'auth-md5chainhash (list (cons 'raw auth-md5chainhash) (cons 'formatted (fmt-bytes auth-md5chainhash))))
        (cons 'auth-authunknown (list (cons 'raw auth-authunknown) (cons 'formatted (fmt-bytes auth-authunknown))))
        (cons 'unknown-data (list (cons 'raw unknown-data) (cons 'formatted (fmt-bytes unknown-data))))
        )))

    (catch (e)
      (err (str "GLBP parse error: " e)))))

;; dissect-glbp: parse GLBP from bytevector
;; Returns (ok fields-alist) or (err message)