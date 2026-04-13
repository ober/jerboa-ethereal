;; packet-eapol.c
;; Routines for EAPOL and EAPOL-Key IEEE 802.1X-2010 PDU dissection
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/eapol.ss
;; Auto-generated from wireshark/epan/dissectors/packet-eapol.c

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
(def (dissect-eapol buffer)
  "802.1X Authentication"
  (try
    (let* (
           (keydes-replay-counter (unwrap (read-u64be buffer 2)))
           (keydes-key-iv (unwrap (slice buffer 10 16)))
           (keydes-key-index (unwrap (read-u8 buffer 26)))
           (keydes-key-index-type (unwrap (read-u8 buffer 26)))
           (keydes-key-index-number (unwrap (read-u8 buffer 26)))
           (keydes-key-signature (unwrap (slice buffer 27 16)))
           (keydes-key (unwrap (slice buffer 43 1)))
           (keydes-key-generated-locally (unwrap (read-u8 buffer 43)))
           (keydes-key-len (unwrap (read-u16be buffer 44)))
           )

      (ok (list
        (cons 'keydes-replay-counter (list (cons 'raw keydes-replay-counter) (cons 'formatted (number->string keydes-replay-counter))))
        (cons 'keydes-key-iv (list (cons 'raw keydes-key-iv) (cons 'formatted (fmt-bytes keydes-key-iv))))
        (cons 'keydes-key-index (list (cons 'raw keydes-key-index) (cons 'formatted (fmt-hex keydes-key-index))))
        (cons 'keydes-key-index-type (list (cons 'raw keydes-key-index-type) (cons 'formatted (if (= keydes-key-index-type 0) "Broadcast" "Unicast"))))
        (cons 'keydes-key-index-number (list (cons 'raw keydes-key-index-number) (cons 'formatted (number->string keydes-key-index-number))))
        (cons 'keydes-key-signature (list (cons 'raw keydes-key-signature) (cons 'formatted (fmt-bytes keydes-key-signature))))
        (cons 'keydes-key (list (cons 'raw keydes-key) (cons 'formatted (fmt-bytes keydes-key))))
        (cons 'keydes-key-generated-locally (list (cons 'raw keydes-key-generated-locally) (cons 'formatted (number->string keydes-key-generated-locally))))
        (cons 'keydes-key-len (list (cons 'raw keydes-key-len) (cons 'formatted (number->string keydes-key-len))))
        )))

    (catch (e)
      (err (str "EAPOL parse error: " e)))))

;; dissect-eapol: parse EAPOL from bytevector
;; Returns (ok fields-alist) or (err message)