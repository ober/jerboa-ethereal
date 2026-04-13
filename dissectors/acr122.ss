;; packet-acr122.c
;; Routines for ACR122 USB NFC dongle
;;
;; Copyright 2013, Michal Labedzki for Tieto Corporation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/acr122.ss
;; Auto-generated from wireshark/epan/dissectors/packet-acr122.c

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
(def (dissect-acr122 buffer)
  "Advanced Card Systems ACR122"
  (try
    (let* (
           (hf-class (unwrap (read-u8 buffer 0)))
           (hf-ins (unwrap (read-u8 buffer 1)))
           (hf-p1 (unwrap (read-u8 buffer 2)))
           (hf-p2 (unwrap (read-u8 buffer 3)))
           (hf-length (unwrap (read-u8 buffer 4)))
           (green-blinking-state (unwrap (read-u8 buffer 5)))
           (red-blinking-state (unwrap (read-u8 buffer 5)))
           (green-mask (unwrap (read-u8 buffer 5)))
           (red-mask (unwrap (read-u8 buffer 5)))
           (initial-green-blinking-state (unwrap (read-u8 buffer 5)))
           (initial-red-blinking-state (unwrap (read-u8 buffer 5)))
           (final-green-state (unwrap (read-u8 buffer 5)))
           (final-red-state (unwrap (read-u8 buffer 5)))
           (number-of-repetition (unwrap (read-u8 buffer 7)))
           (hf-key (unwrap (slice buffer 9 6)))
           (hf-version (unwrap (read-u16be buffer 17)))
           (number (unwrap (read-u8 buffer 21)))
           (byte (unwrap (read-u8 buffer 27)))
           (block-number (unwrap (read-u8 buffer 28)))
           (for (unwrap (read-u32be buffer 29)))
           (version (unwrap (slice buffer 29 1)))
           (hf-data (unwrap (slice buffer 29 1)))
           (hf-value (unwrap (read-u32be buffer 29)))
           (hf-uid (unwrap (slice buffer 29 1)))
           (hf-ats (unwrap (slice buffer 29 1)))
           (word-sw1 (unwrap (read-u8 buffer 29)))
           (word-sw2 (unwrap (read-u8 buffer 30)))
           (word-led-reserved (unwrap (read-u8 buffer 30)))
           (word-led-green (unwrap (read-u8 buffer 30)))
           (word-led-red (unwrap (read-u8 buffer 30)))
           (operating-auto-picc-polling (unwrap (read-u8 buffer 30)))
           (operating-auto-ats-generation (unwrap (read-u8 buffer 30)))
           (operating-polling-interval (unwrap (read-u8 buffer 30)))
           (operating-felica-424k (unwrap (read-u8 buffer 30)))
           (operating-felica-212k (unwrap (read-u8 buffer 30)))
           (operating-topaz (unwrap (read-u8 buffer 30)))
           (operating-iso-14443-type-b (unwrap (read-u8 buffer 30)))
           (operating-iso-14443-type-a (unwrap (read-u8 buffer 30)))
           )

      (ok (list
        (cons 'hf-class (list (cons 'raw hf-class) (cons 'formatted (fmt-hex hf-class))))
        (cons 'hf-ins (list (cons 'raw hf-ins) (cons 'formatted (fmt-hex hf-ins))))
        (cons 'hf-p1 (list (cons 'raw hf-p1) (cons 'formatted (fmt-hex hf-p1))))
        (cons 'hf-p2 (list (cons 'raw hf-p2) (cons 'formatted (fmt-hex hf-p2))))
        (cons 'hf-length (list (cons 'raw hf-length) (cons 'formatted (fmt-hex hf-length))))
        (cons 'green-blinking-state (list (cons 'raw green-blinking-state) (cons 'formatted (number->string green-blinking-state))))
        (cons 'red-blinking-state (list (cons 'raw red-blinking-state) (cons 'formatted (number->string red-blinking-state))))
        (cons 'green-mask (list (cons 'raw green-mask) (cons 'formatted (number->string green-mask))))
        (cons 'red-mask (list (cons 'raw red-mask) (cons 'formatted (number->string red-mask))))
        (cons 'initial-green-blinking-state (list (cons 'raw initial-green-blinking-state) (cons 'formatted (number->string initial-green-blinking-state))))
        (cons 'initial-red-blinking-state (list (cons 'raw initial-red-blinking-state) (cons 'formatted (number->string initial-red-blinking-state))))
        (cons 'final-green-state (list (cons 'raw final-green-state) (cons 'formatted (number->string final-green-state))))
        (cons 'final-red-state (list (cons 'raw final-red-state) (cons 'formatted (number->string final-red-state))))
        (cons 'number-of-repetition (list (cons 'raw number-of-repetition) (cons 'formatted (number->string number-of-repetition))))
        (cons 'hf-key (list (cons 'raw hf-key) (cons 'formatted (fmt-bytes hf-key))))
        (cons 'hf-version (list (cons 'raw hf-version) (cons 'formatted (fmt-hex hf-version))))
        (cons 'number (list (cons 'raw number) (cons 'formatted (number->string number))))
        (cons 'byte (list (cons 'raw byte) (cons 'formatted (fmt-hex byte))))
        (cons 'block-number (list (cons 'raw block-number) (cons 'formatted (number->string block-number))))
        (cons 'for (list (cons 'raw for) (cons 'formatted (number->string for))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (utf8->string version))))
        (cons 'hf-data (list (cons 'raw hf-data) (cons 'formatted (fmt-bytes hf-data))))
        (cons 'hf-value (list (cons 'raw hf-value) (cons 'formatted (number->string hf-value))))
        (cons 'hf-uid (list (cons 'raw hf-uid) (cons 'formatted (fmt-bytes hf-uid))))
        (cons 'hf-ats (list (cons 'raw hf-ats) (cons 'formatted (fmt-bytes hf-ats))))
        (cons 'word-sw1 (list (cons 'raw word-sw1) (cons 'formatted (fmt-hex word-sw1))))
        (cons 'word-sw2 (list (cons 'raw word-sw2) (cons 'formatted (fmt-hex word-sw2))))
        (cons 'word-led-reserved (list (cons 'raw word-led-reserved) (cons 'formatted (fmt-hex word-led-reserved))))
        (cons 'word-led-green (list (cons 'raw word-led-green) (cons 'formatted (number->string word-led-green))))
        (cons 'word-led-red (list (cons 'raw word-led-red) (cons 'formatted (number->string word-led-red))))
        (cons 'operating-auto-picc-polling (list (cons 'raw operating-auto-picc-polling) (cons 'formatted (number->string operating-auto-picc-polling))))
        (cons 'operating-auto-ats-generation (list (cons 'raw operating-auto-ats-generation) (cons 'formatted (number->string operating-auto-ats-generation))))
        (cons 'operating-polling-interval (list (cons 'raw operating-polling-interval) (cons 'formatted (number->string operating-polling-interval))))
        (cons 'operating-felica-424k (list (cons 'raw operating-felica-424k) (cons 'formatted (number->string operating-felica-424k))))
        (cons 'operating-felica-212k (list (cons 'raw operating-felica-212k) (cons 'formatted (number->string operating-felica-212k))))
        (cons 'operating-topaz (list (cons 'raw operating-topaz) (cons 'formatted (number->string operating-topaz))))
        (cons 'operating-iso-14443-type-b (list (cons 'raw operating-iso-14443-type-b) (cons 'formatted (number->string operating-iso-14443-type-b))))
        (cons 'operating-iso-14443-type-a (list (cons 'raw operating-iso-14443-type-a) (cons 'formatted (number->string operating-iso-14443-type-a))))
        )))

    (catch (e)
      (err (str "ACR122 parse error: " e)))))

;; dissect-acr122: parse ACR122 from bytevector
;; Returns (ok fields-alist) or (err message)