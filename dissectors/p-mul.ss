;; packet-p_mul.c
;;
;; Routines for P_Mul (ACP142) packet disassembly.
;; A protocol for reliable multicast messaging in bandwidth constrained
;; and delayed acknowledgement (EMCON) environments.
;;
;; Copyright 2005, Stig Bjorlykke <stig@bjorlykke.org>, Thales Norway AS
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Ref:  http://jcs.dtic.mil/j6/cceb/acps/acp142/
;;

;; jerboa-ethereal/dissectors/p-mul.ss
;; Auto-generated from wireshark/epan/dissectors/packet-p_mul.c

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
(def (dissect-p-mul buffer)
  "P_Mul (ACP142)"
  (try
    (let* (
           (miss-seq-no (unwrap (read-u16be buffer 0)))
           (hf-length (unwrap (read-u16be buffer 0)))
           (hf-priority (unwrap (read-u8 buffer 2)))
           (hf-unused8 (unwrap (read-u8 buffer 2)))
           (unused (unwrap (read-u8 buffer 3)))
           (pdus (unwrap (read-u16be buffer 4)))
           (no (unwrap (read-u16be buffer 4)))
           (hf-unused16 (unwrap (read-u16be buffer 4)))
           (hf-checksum (unwrap (read-u16be buffer 6)))
           (good (unwrap (read-u8 buffer 6)))
           (bad (unwrap (read-u8 buffer 6)))
           (id-ack (unwrap (read-u32be buffer 8)))
           (count (unwrap (read-u16be buffer 12)))
           (len (unwrap (read-u8 buffer 26)))
           (of-dest (unwrap (read-u16be buffer 28)))
           (of-res (unwrap (read-u16be buffer 30)))
           (length (unwrap (read-u16be buffer 40)))
           (seq-range (unwrap (slice buffer 50 6)))
           (seq-range-from (unwrap (read-u16be buffer 50)))
           (seq-range-delimiter (unwrap (read-u16be buffer 50)))
           (seq-range-to (unwrap (read-u16be buffer 50)))
           (seq-no (unwrap (read-u16be buffer 56)))
           (option (unwrap (read-u64be buffer 58)))
           (mc-group (unwrap (read-u32be buffer 66)))
           (id (unwrap (read-u32be buffer 70)))
           (group (unwrap (read-u32be buffer 74)))
           )

      (ok (list
        (cons 'miss-seq-no (list (cons 'raw miss-seq-no) (cons 'formatted (number->string miss-seq-no))))
        (cons 'hf-length (list (cons 'raw hf-length) (cons 'formatted (number->string hf-length))))
        (cons 'hf-priority (list (cons 'raw hf-priority) (cons 'formatted (number->string hf-priority))))
        (cons 'hf-unused8 (list (cons 'raw hf-unused8) (cons 'formatted (number->string hf-unused8))))
        (cons 'unused (list (cons 'raw unused) (cons 'formatted (number->string unused))))
        (cons 'pdus (list (cons 'raw pdus) (cons 'formatted (number->string pdus))))
        (cons 'no (list (cons 'raw no) (cons 'formatted (number->string no))))
        (cons 'hf-unused16 (list (cons 'raw hf-unused16) (cons 'formatted (number->string hf-unused16))))
        (cons 'hf-checksum (list (cons 'raw hf-checksum) (cons 'formatted (fmt-hex hf-checksum))))
        (cons 'good (list (cons 'raw good) (cons 'formatted (number->string good))))
        (cons 'bad (list (cons 'raw bad) (cons 'formatted (number->string bad))))
        (cons 'id-ack (list (cons 'raw id-ack) (cons 'formatted (fmt-ipv4 id-ack))))
        (cons 'count (list (cons 'raw count) (cons 'formatted (number->string count))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'of-dest (list (cons 'raw of-dest) (cons 'formatted (number->string of-dest))))
        (cons 'of-res (list (cons 'raw of-res) (cons 'formatted (number->string of-res))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'seq-range (list (cons 'raw seq-range) (cons 'formatted (fmt-bytes seq-range))))
        (cons 'seq-range-from (list (cons 'raw seq-range-from) (cons 'formatted (number->string seq-range-from))))
        (cons 'seq-range-delimiter (list (cons 'raw seq-range-delimiter) (cons 'formatted (number->string seq-range-delimiter))))
        (cons 'seq-range-to (list (cons 'raw seq-range-to) (cons 'formatted (number->string seq-range-to))))
        (cons 'seq-no (list (cons 'raw seq-no) (cons 'formatted (number->string seq-no))))
        (cons 'option (list (cons 'raw option) (cons 'formatted (number->string option))))
        (cons 'mc-group (list (cons 'raw mc-group) (cons 'formatted (number->string mc-group))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (fmt-ipv4 id))))
        (cons 'group (list (cons 'raw group) (cons 'formatted (number->string group))))
        )))

    (catch (e)
      (err (str "P-MUL parse error: " e)))))

;; dissect-p-mul: parse P-MUL from bytevector
;; Returns (ok fields-alist) or (err message)