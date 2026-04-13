;; packet-h265.c
;; Routines for H.265 dissection
;; Copyright 2018, Asaf Kave <kave.asaf[at]gmail.com>
;; Based on the H.264 dissector, thanks!
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; References:
;; https://tools.ietf.org/html/rfc7798
;; http://www.itu.int/rec/T-REC-H.265/en
;;

;; jerboa-ethereal/dissectors/h265.ss
;; Auto-generated from wireshark/epan/dissectors/packet-h265.c

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
(def (dissect-h265 buffer)
  "H.265"
  (try
    (let* (
           (vps-sub-layer-ordering-info-present-flag (unwrap (read-u8 buffer 0)))
           (sps-video-parameter-set-id (unwrap (read-u8 buffer 0)))
           (sps-max-sub-layers-minus1 (unwrap (read-u8 buffer 0)))
           (sps-temporal-id-nesting-flag (unwrap (read-u8 buffer 0)))
           (sdp-parameter-sprop-vps (unwrap (slice buffer 0 1)))
           (sdp-parameter-sprop-sps (unwrap (slice buffer 0 1)))
           (sdp-parameter-sprop-pps (unwrap (slice buffer 0 1)))
           (nal-f-bit (unwrap (read-u8 buffer 0)))
           (nuh-layer-id (unwrap (read-u16be buffer 0)))
           (nuh-temporal-id-plus1 (unwrap (read-u16be buffer 0)))
           (start-bit (unwrap (read-u8 buffer 0)))
           (end-bit (unwrap (read-u8 buffer 0)))
           (general-profile-space (unwrap (read-u8 buffer 3)))
           (general-tier-flag (unwrap (read-u8 buffer 3)))
           (general-profile-compatibility-flags (unwrap (read-u32be buffer 3)))
           )

      (ok (list
        (cons 'vps-sub-layer-ordering-info-present-flag (list (cons 'raw vps-sub-layer-ordering-info-present-flag) (cons 'formatted (number->string vps-sub-layer-ordering-info-present-flag))))
        (cons 'sps-video-parameter-set-id (list (cons 'raw sps-video-parameter-set-id) (cons 'formatted (number->string sps-video-parameter-set-id))))
        (cons 'sps-max-sub-layers-minus1 (list (cons 'raw sps-max-sub-layers-minus1) (cons 'formatted (number->string sps-max-sub-layers-minus1))))
        (cons 'sps-temporal-id-nesting-flag (list (cons 'raw sps-temporal-id-nesting-flag) (cons 'formatted (number->string sps-temporal-id-nesting-flag))))
        (cons 'sdp-parameter-sprop-vps (list (cons 'raw sdp-parameter-sprop-vps) (cons 'formatted (fmt-bytes sdp-parameter-sprop-vps))))
        (cons 'sdp-parameter-sprop-sps (list (cons 'raw sdp-parameter-sprop-sps) (cons 'formatted (fmt-bytes sdp-parameter-sprop-sps))))
        (cons 'sdp-parameter-sprop-pps (list (cons 'raw sdp-parameter-sprop-pps) (cons 'formatted (fmt-bytes sdp-parameter-sprop-pps))))
        (cons 'nal-f-bit (list (cons 'raw nal-f-bit) (cons 'formatted (if (= nal-f-bit 0) "No bit errors or other syntax violations" "Bit errors or other syntax violations"))))
        (cons 'nuh-layer-id (list (cons 'raw nuh-layer-id) (cons 'formatted (number->string nuh-layer-id))))
        (cons 'nuh-temporal-id-plus1 (list (cons 'raw nuh-temporal-id-plus1) (cons 'formatted (number->string nuh-temporal-id-plus1))))
        (cons 'start-bit (list (cons 'raw start-bit) (cons 'formatted (if (= start-bit 0) "Not the first packet of FU-A picture" "the first packet of FU-A picture"))))
        (cons 'end-bit (list (cons 'raw end-bit) (cons 'formatted (if (= end-bit 0) "Not the last packet of FU-A picture" "the last packet of FU-A picture"))))
        (cons 'general-profile-space (list (cons 'raw general-profile-space) (cons 'formatted (number->string general-profile-space))))
        (cons 'general-tier-flag (list (cons 'raw general-tier-flag) (cons 'formatted (number->string general-tier-flag))))
        (cons 'general-profile-compatibility-flags (list (cons 'raw general-profile-compatibility-flags) (cons 'formatted (fmt-hex general-profile-compatibility-flags))))
        )))

    (catch (e)
      (err (str "H265 parse error: " e)))))

;; dissect-h265: parse H265 from bytevector
;; Returns (ok fields-alist) or (err message)