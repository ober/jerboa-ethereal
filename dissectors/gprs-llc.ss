;; packet-gprs-llc.c
;; Routines for Logical Link Control GPRS dissection ETSI 4.64(TS 101 351 V8.7.0)
;; Copyright 2000, Josef Korelus <jkor@quick.cz>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gprs-llc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gprs_llc.c

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
(def (dissect-gprs-llc buffer)
  "Logical Link Control GPRS"
  (try
    (let* (
           (fcs (unwrap (read-u24be buffer 0)))
           (cr (unwrap (read-u8 buffer 0)))
           (pd (unwrap (read-u8 buffer 0)))
           (dummy-ui (unwrap (read-u8 buffer 0)))
           (ifmt (unwrap (read-u24be buffer 0)))
           (Ai (unwrap (read-u8 buffer 0)))
           (izerobit (unwrap (read-u24be buffer 0)))
           (isack-ns (unwrap (read-u24be buffer 0)))
           (isack-nr (unwrap (read-u24be buffer 0)))
           (kmask (unwrap (read-u8 buffer 3)))
           (k (unwrap (read-u8 buffer 3)))
           (Un (unwrap (read-u8 buffer 7)))
           (PF (unwrap (read-u8 buffer 7)))
           (tom-rl (unwrap (read-u8 buffer 8)))
           (tom-pd (unwrap (read-u8 buffer 8)))
           (tom-header (unwrap (read-u8 buffer 8)))
           (tom-data (unwrap (read-u8 buffer 8)))
           )

      (ok (list
        (cons 'fcs (list (cons 'raw fcs) (cons 'formatted (fmt-hex fcs))))
        (cons 'cr (list (cons 'raw cr) (cons 'formatted (if (= cr 0) "DownLink/UpLink = Response/Command" "DownLink/UpLink = Command/Response"))))
        (cons 'pd (list (cons 'raw pd) (cons 'formatted (if (= pd 0) "OK" "Invalid frame PD=1"))))
        (cons 'dummy-ui (list (cons 'raw dummy-ui) (cons 'formatted (number->string dummy-ui))))
        (cons 'ifmt (list (cons 'raw ifmt) (cons 'formatted (fmt-hex ifmt))))
        (cons 'Ai (list (cons 'raw Ai) (cons 'formatted (if (= Ai 0) "The peer LLE is not requested to send an acknowledgment." "To solicit an acknowledgement from the peer LLE. "))))
        (cons 'izerobit (list (cons 'raw izerobit) (cons 'formatted (number->string izerobit))))
        (cons 'isack-ns (list (cons 'raw isack-ns) (cons 'formatted (number->string isack-ns))))
        (cons 'isack-nr (list (cons 'raw isack-nr) (cons 'formatted (number->string isack-nr))))
        (cons 'kmask (list (cons 'raw kmask) (cons 'formatted (number->string kmask))))
        (cons 'k (list (cons 'raw k) (cons 'formatted (number->string k))))
        (cons 'Un (list (cons 'raw Un) (cons 'formatted (fmt-hex Un))))
        (cons 'PF (list (cons 'raw PF) (cons 'formatted (number->string PF))))
        (cons 'tom-rl (list (cons 'raw tom-rl) (cons 'formatted (number->string tom-rl))))
        (cons 'tom-pd (list (cons 'raw tom-pd) (cons 'formatted (fmt-hex tom-pd))))
        (cons 'tom-header (list (cons 'raw tom-header) (cons 'formatted (fmt-hex tom-header))))
        (cons 'tom-data (list (cons 'raw tom-data) (cons 'formatted (fmt-hex tom-data))))
        )))

    (catch (e)
      (err (str "GPRS-LLC parse error: " e)))))

;; dissect-gprs-llc: parse GPRS-LLC from bytevector
;; Returns (ok fields-alist) or (err message)