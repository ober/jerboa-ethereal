;; packet-lon.c
;; Traffic analyzer for Lontalk/EIA-709.1 networks
;; Daniel Willmann <daniel@totalueberwachung.de>
;; (c) 2011 Daniel Willmann
;;
;; Used some code by habibi_khalid <khalidhabibi@gmx.de> and
;; Honorine_KEMGNE_NGUIFFO <honorinekemgne@yahoo.fr> from
;; https://gitlab.com/wireshark/wireshark/-/issues/4704
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/lon.ss
;; Auto-generated from wireshark/epan/dissectors/packet-lon.c

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
(def (dissect-lon buffer)
  "Local Operating Network"
  (try
    (let* (
           (ppdu (unwrap (read-u8 buffer 0)))
           (ppdu-prio (extract-bits ppdu 0x80 7))
           (ppdu-alt (extract-bits ppdu 0x40 6))
           (ppdu-deltabl (extract-bits ppdu 0x3F 0))
           (npdu (unwrap (read-u8 buffer 0)))
           (npdu-version (extract-bits npdu 0xC0 6))
           (addr-dstgrp (unwrap (read-u8 buffer 10)))
           (addr-dstnode (unwrap (read-u8 buffer 10)))
           (addr-grp (unwrap (read-u8 buffer 10)))
           (addr-grpmem (unwrap (read-u8 buffer 10)))
           (addr-srcsub (unwrap (read-u8 buffer 16)))
           (addr-srcnode (unwrap (read-u8 buffer 16)))
           (addr-dstsub (unwrap (read-u8 buffer 16)))
           (addr-uid (unwrap (slice buffer 16 6)))
           (domain (unwrap (slice buffer 25 1)))
           (tpdu (unwrap (read-u8 buffer 34)))
           (mlen (unwrap (read-u8 buffer 34)))
           (mlist (unwrap (read-u8 buffer 34)))
           (spdu (unwrap (read-u8 buffer 34)))
           (auth (extract-bits spdu 0x80 7))
           (authpdu (unwrap (read-u8 buffer 34)))
           (authpdu-fmt (extract-bits authpdu 0xC 2))
           (trans-no (extract-bits authpdu 0xF 0))
           )

      (ok (list
        (cons 'ppdu (list (cons 'raw ppdu) (cons 'formatted (fmt-hex ppdu))))
        (cons 'ppdu-prio (list (cons 'raw ppdu-prio) (cons 'formatted (if (= ppdu-prio 0) "Not set" "Set"))))
        (cons 'ppdu-alt (list (cons 'raw ppdu-alt) (cons 'formatted (if (= ppdu-alt 0) "Not set" "Set"))))
        (cons 'ppdu-deltabl (list (cons 'raw ppdu-deltabl) (cons 'formatted (if (= ppdu-deltabl 0) "Not set" "Set"))))
        (cons 'npdu (list (cons 'raw npdu) (cons 'formatted (number->string npdu))))
        (cons 'npdu-version (list (cons 'raw npdu-version) (cons 'formatted (if (= npdu-version 0) "Not set" "Set"))))
        (cons 'addr-dstgrp (list (cons 'raw addr-dstgrp) (cons 'formatted (fmt-hex addr-dstgrp))))
        (cons 'addr-dstnode (list (cons 'raw addr-dstnode) (cons 'formatted (fmt-hex addr-dstnode))))
        (cons 'addr-grp (list (cons 'raw addr-grp) (cons 'formatted (fmt-hex addr-grp))))
        (cons 'addr-grpmem (list (cons 'raw addr-grpmem) (cons 'formatted (fmt-hex addr-grpmem))))
        (cons 'addr-srcsub (list (cons 'raw addr-srcsub) (cons 'formatted (fmt-hex addr-srcsub))))
        (cons 'addr-srcnode (list (cons 'raw addr-srcnode) (cons 'formatted (fmt-hex addr-srcnode))))
        (cons 'addr-dstsub (list (cons 'raw addr-dstsub) (cons 'formatted (fmt-hex addr-dstsub))))
        (cons 'addr-uid (list (cons 'raw addr-uid) (cons 'formatted (fmt-bytes addr-uid))))
        (cons 'domain (list (cons 'raw domain) (cons 'formatted (fmt-bytes domain))))
        (cons 'tpdu (list (cons 'raw tpdu) (cons 'formatted (fmt-hex tpdu))))
        (cons 'mlen (list (cons 'raw mlen) (cons 'formatted (fmt-hex mlen))))
        (cons 'mlist (list (cons 'raw mlist) (cons 'formatted (fmt-hex mlist))))
        (cons 'spdu (list (cons 'raw spdu) (cons 'formatted (fmt-hex spdu))))
        (cons 'auth (list (cons 'raw auth) (cons 'formatted (if (= auth 0) "Not set" "Set"))))
        (cons 'authpdu (list (cons 'raw authpdu) (cons 'formatted (fmt-hex authpdu))))
        (cons 'authpdu-fmt (list (cons 'raw authpdu-fmt) (cons 'formatted (if (= authpdu-fmt 0) "Not set" "Set"))))
        (cons 'trans-no (list (cons 'raw trans-no) (cons 'formatted (if (= trans-no 0) "Not set" "Set"))))
        )))

    (catch (e)
      (err (str "LON parse error: " e)))))

;; dissect-lon: parse LON from bytevector
;; Returns (ok fields-alist) or (err message)