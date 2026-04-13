;; packet-vrrp.c
;; Routines for the Virtual Router Redundancy Protocol (VRRP)
;;
;; VRRPv2: RFC3768 (superseeding RFC2338)
;; VRRPv3: RFC5798
;;
;; Heikki Vatiainen <hessu@cs.tut.fi>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/vrrp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-vrrp.c
;; RFC 3768

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
(def (dissect-vrrp buffer)
  "Virtual Router Redundancy Protocol"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (virt-rtr-id (unwrap (read-u8 buffer 1)))
           (prio (unwrap (read-u8 buffer 2)))
           (addr-count (unwrap (read-u8 buffer 3)))
           (reserved-mbz (unwrap (read-u8 buffer 4)))
           (short-adver-int (unwrap (read-u16be buffer 4)))
           (adver-int (unwrap (read-u8 buffer 7)))
           (ip6 (unwrap (slice buffer 16 16)))
           (ip (unwrap (read-u32be buffer 32)))
           (auth-string (unwrap (slice buffer 36 1)))
           (ver-type (unwrap (read-u8 buffer 37)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'virt-rtr-id (list (cons 'raw virt-rtr-id) (cons 'formatted (number->string virt-rtr-id))))
        (cons 'prio (list (cons 'raw prio) (cons 'formatted (number->string prio))))
        (cons 'addr-count (list (cons 'raw addr-count) (cons 'formatted (number->string addr-count))))
        (cons 'reserved-mbz (list (cons 'raw reserved-mbz) (cons 'formatted (number->string reserved-mbz))))
        (cons 'short-adver-int (list (cons 'raw short-adver-int) (cons 'formatted (number->string short-adver-int))))
        (cons 'adver-int (list (cons 'raw adver-int) (cons 'formatted (number->string adver-int))))
        (cons 'ip6 (list (cons 'raw ip6) (cons 'formatted (fmt-ipv6-address ip6))))
        (cons 'ip (list (cons 'raw ip) (cons 'formatted (fmt-ipv4 ip))))
        (cons 'auth-string (list (cons 'raw auth-string) (cons 'formatted (utf8->string auth-string))))
        (cons 'ver-type (list (cons 'raw ver-type) (cons 'formatted (number->string ver-type))))
        )))

    (catch (e)
      (err (str "VRRP parse error: " e)))))

;; dissect-vrrp: parse VRRP from bytevector
;; Returns (ok fields-alist) or (err message)