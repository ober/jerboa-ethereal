;; packet-egd.c
;; Routines for Ethernet Global Data dissection
;; EGD Home: www.gefanuc.com
;;
;; Copyright 2008
;; 29 July 2008 -- ryan wamsley
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/egd.ss
;; Auto-generated from wireshark/epan/dissectors/packet-egd.c

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
(def (dissect-egd buffer)
  "Ethernet Global Data"
  (try
    (let* (
           (type (unwrap (read-u8 buffer 0)))
           (ver (unwrap (read-u8 buffer 0)))
           (rid (unwrap (read-u16be buffer 0)))
           (pid (unwrap (read-u32be buffer 2)))
           (exid (unwrap (read-u32be buffer 6)))
           (notime (unwrap (read-u64be buffer 10)))
           (csig (unwrap (read-u32be buffer 22)))
           (resv (unwrap (read-u32be buffer 26)))
           )

      (ok (list
        (cons 'type (list (cons 'raw type) (cons 'formatted (number->string type))))
        (cons 'ver (list (cons 'raw ver) (cons 'formatted (number->string ver))))
        (cons 'rid (list (cons 'raw rid) (cons 'formatted (number->string rid))))
        (cons 'pid (list (cons 'raw pid) (cons 'formatted (fmt-ipv4 pid))))
        (cons 'exid (list (cons 'raw exid) (cons 'formatted (fmt-hex exid))))
        (cons 'notime (list (cons 'raw notime) (cons 'formatted (fmt-hex notime))))
        (cons 'csig (list (cons 'raw csig) (cons 'formatted (number->string csig))))
        (cons 'resv (list (cons 'raw resv) (cons 'formatted (number->string resv))))
        )))

    (catch (e)
      (err (str "EGD parse error: " e)))))

;; dissect-egd: parse EGD from bytevector
;; Returns (ok fields-alist) or (err message)