;; Routines for UMTS FP Hint protocol disassembly
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/fp-hint.ss
;; Auto-generated from wireshark/epan/dissectors/packet-fp_hint.c

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
(def (dissect-fp-hint buffer)
  "FP Hint"
  (try
    (let* (
           (urnti (unwrap (read-u32be buffer 0)))
           (ctmux (unwrap (read-u8 buffer 0)))
           (ciphered (unwrap (read-u8 buffer 0)))
           (deciphered (unwrap (read-u8 buffer 0)))
           (chcnt (unwrap (read-u8 buffer 12)))
           (dchid (unwrap (read-u8 buffer 12)))
           (tf-n (unwrap (read-u16be buffer 12)))
           (tf-size (unwrap (read-u32be buffer 12)))
           (macdflowid (unwrap (read-u8 buffer 20)))
           (ddi-value (unwrap (read-u8 buffer 22)))
           (ddi-logical (unwrap (read-u8 buffer 22)))
           (ddi-size (unwrap (read-u16be buffer 22)))
           )

      (ok (list
        (cons 'urnti (list (cons 'raw urnti) (cons 'formatted (fmt-hex urnti))))
        (cons 'ctmux (list (cons 'raw ctmux) (cons 'formatted (if (= ctmux 0) "C/T Mux field not present" "C/T Mux field present"))))
        (cons 'ciphered (list (cons 'raw ciphered) (cons 'formatted (if (= ciphered 0) "Not ciphered" "Ciphered"))))
        (cons 'deciphered (list (cons 'raw deciphered) (cons 'formatted (if (= deciphered 0) "Not deciphered" "Deciphered"))))
        (cons 'chcnt (list (cons 'raw chcnt) (cons 'formatted (number->string chcnt))))
        (cons 'dchid (list (cons 'raw dchid) (cons 'formatted (number->string dchid))))
        (cons 'tf-n (list (cons 'raw tf-n) (cons 'formatted (number->string tf-n))))
        (cons 'tf-size (list (cons 'raw tf-size) (cons 'formatted (number->string tf-size))))
        (cons 'macdflowid (list (cons 'raw macdflowid) (cons 'formatted (number->string macdflowid))))
        (cons 'ddi-value (list (cons 'raw ddi-value) (cons 'formatted (number->string ddi-value))))
        (cons 'ddi-logical (list (cons 'raw ddi-logical) (cons 'formatted (number->string ddi-logical))))
        (cons 'ddi-size (list (cons 'raw ddi-size) (cons 'formatted (number->string ddi-size))))
        )))

    (catch (e)
      (err (str "FP-HINT parse error: " e)))))

;; dissect-fp-hint: parse FP-HINT from bytevector
;; Returns (ok fields-alist) or (err message)