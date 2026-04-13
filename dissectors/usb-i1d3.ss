;; packet-usb-i1d3.c
;; Dissects the X-Rite i1 Display Pro (and derivatives) USB protocol
;; Copyright 2016, Etienne Dechamps <etienne@edechamps.fr>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/usb-i1d3.ss
;; Auto-generated from wireshark/epan/dissectors/packet-usb_i1d3.c

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
(def (dissect-usb-i1d3 buffer)
  "X-Rite i1 Display Pro (and derivatives) USB protocol"
  (try
    (let* (
           (i1d3-response-code (unwrap (read-u8 buffer 0)))
           (i1d3-echoed-command-code (unwrap (read-u8 buffer 1)))
           (i1d3-unlock-result (unwrap (read-u8 buffer 2)))
           (i1d3-challenge-encode-key (unwrap (read-u8 buffer 2)))
           (i1d3-locked (unwrap (read-u16be buffer 2)))
           (i1d3-firmdate (unwrap (slice buffer 2 1)))
           (i1d3-firmver (unwrap (slice buffer 2 1)))
           (i1d3-prodname (unwrap (slice buffer 2 1)))
           (i1d3-status (unwrap (read-u24be buffer 2)))
           (i1d3-information (unwrap (slice buffer 2 1)))
           (i1d3-led-offtime (unwrap (read-u8 buffer 2)))
           (i1d3-challenge-decode-key (unwrap (read-u8 buffer 3)))
           (i1d3-prodtype (unwrap (read-u16be buffer 3)))
           (i1d3-led-ontime (unwrap (read-u8 buffer 3)))
           (i1d3-readintee-data (unwrap (slice buffer 4 1)))
           (i1d3-readextee-data (unwrap (slice buffer 5 1)))
           (i1d3-challenge-response (unwrap (slice buffer 24 16)))
           (i1d3-challenge-data (unwrap (slice buffer 35 8)))
           )

      (ok (list
        (cons 'i1d3-response-code (list (cons 'raw i1d3-response-code) (cons 'formatted (fmt-hex i1d3-response-code))))
        (cons 'i1d3-echoed-command-code (list (cons 'raw i1d3-echoed-command-code) (cons 'formatted (fmt-hex i1d3-echoed-command-code))))
        (cons 'i1d3-unlock-result (list (cons 'raw i1d3-unlock-result) (cons 'formatted (fmt-hex i1d3-unlock-result))))
        (cons 'i1d3-challenge-encode-key (list (cons 'raw i1d3-challenge-encode-key) (cons 'formatted (fmt-hex i1d3-challenge-encode-key))))
        (cons 'i1d3-locked (list (cons 'raw i1d3-locked) (cons 'formatted (fmt-hex i1d3-locked))))
        (cons 'i1d3-firmdate (list (cons 'raw i1d3-firmdate) (cons 'formatted (utf8->string i1d3-firmdate))))
        (cons 'i1d3-firmver (list (cons 'raw i1d3-firmver) (cons 'formatted (utf8->string i1d3-firmver))))
        (cons 'i1d3-prodname (list (cons 'raw i1d3-prodname) (cons 'formatted (utf8->string i1d3-prodname))))
        (cons 'i1d3-status (list (cons 'raw i1d3-status) (cons 'formatted (fmt-hex i1d3-status))))
        (cons 'i1d3-information (list (cons 'raw i1d3-information) (cons 'formatted (utf8->string i1d3-information))))
        (cons 'i1d3-led-offtime (list (cons 'raw i1d3-led-offtime) (cons 'formatted (number->string i1d3-led-offtime))))
        (cons 'i1d3-challenge-decode-key (list (cons 'raw i1d3-challenge-decode-key) (cons 'formatted (fmt-hex i1d3-challenge-decode-key))))
        (cons 'i1d3-prodtype (list (cons 'raw i1d3-prodtype) (cons 'formatted (fmt-hex i1d3-prodtype))))
        (cons 'i1d3-led-ontime (list (cons 'raw i1d3-led-ontime) (cons 'formatted (number->string i1d3-led-ontime))))
        (cons 'i1d3-readintee-data (list (cons 'raw i1d3-readintee-data) (cons 'formatted (fmt-bytes i1d3-readintee-data))))
        (cons 'i1d3-readextee-data (list (cons 'raw i1d3-readextee-data) (cons 'formatted (fmt-bytes i1d3-readextee-data))))
        (cons 'i1d3-challenge-response (list (cons 'raw i1d3-challenge-response) (cons 'formatted (fmt-bytes i1d3-challenge-response))))
        (cons 'i1d3-challenge-data (list (cons 'raw i1d3-challenge-data) (cons 'formatted (fmt-bytes i1d3-challenge-data))))
        )))

    (catch (e)
      (err (str "USB-I1D3 parse error: " e)))))

;; dissect-usb-i1d3: parse USB-I1D3 from bytevector
;; Returns (ok fields-alist) or (err message)