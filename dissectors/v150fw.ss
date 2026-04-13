;; packet-v150fw.c
;;
;; v150fw = v.150.1 SSE messages, contained in RTP packets
;;
;; Written by Jamison Adcock <jamison.adcock@cobham.com>
;; for Sparta Inc., dba Cobham Analytic Solutions
;; This code is largely based on the RTP parsing code
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/v150fw.ss
;; Auto-generated from wireshark/epan/dissectors/packet-v150fw.c
;; RFC 2833

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
(def (dissect-v150fw buffer)
  "V.150.1 State Signaling Event"
  (try
    (let* (
           (force-response-bit (unwrap (read-u8 buffer 0)))
           (extension-bit (unwrap (read-u8 buffer 0)))
           (ric-info-mod-avail (unwrap (read-u16be buffer 0)))
           (cm-jm-mod-avail-pcm-mode (unwrap (read-u8 buffer 0)))
           (cm-jm-mod-avail-v34-duplex (unwrap (read-u8 buffer 0)))
           (cm-jm-mod-avail-v34-half-duplex (unwrap (read-u8 buffer 0)))
           (cm-jm-mod-avail-v32-v32bis (unwrap (read-u8 buffer 0)))
           (cm-jm-mod-avail-v22-v22bis (unwrap (read-u8 buffer 0)))
           (cm-jm-mod-avail-v17 (unwrap (read-u8 buffer 0)))
           (cm-jm-mod-avail-v29-half-duplex (unwrap (read-u8 buffer 0)))
           (cm-jm-mod-avail-v27ter (unwrap (read-u8 buffer 0)))
           (cm-jm-mod-avail-v26ter (unwrap (read-u8 buffer 0)))
           (cm-jm-mod-avail-v26bis (unwrap (read-u8 buffer 0)))
           (cm-jm-mod-avail-v23-duplex (unwrap (read-u8 buffer 0)))
           (cm-jm-mod-avail-v23-half-duplex (unwrap (read-u8 buffer 0)))
           (cm-jm-mod-avail-v21 (unwrap (read-u8 buffer 0)))
           (cm-jm-mod-avail-v90-or-v92-analog (unwrap (read-u8 buffer 0)))
           (cm-jm-mod-avail-v90-or-v92-digital (unwrap (read-u8 buffer 0)))
           (cm-jm-mod-avail-v91 (unwrap (read-u8 buffer 0)))
           (ric-info-timeout-vendor (unwrap (read-u16be buffer 0)))
           (ric-info-cleardown-reserved (unwrap (read-u16be buffer 0)))
           (reason-id-code-info (unwrap (read-u16be buffer 0)))
           (reserved (unwrap (read-u16be buffer 2)))
           (extension-len (unwrap (read-u16be buffer 2)))
           (ric-info-cleardown-vendor-tag (unwrap (read-u8 buffer 4)))
           (ric-info-cleardown-vendor-info (unwrap (read-u8 buffer 4)))
           )

      (ok (list
        (cons 'force-response-bit (list (cons 'raw force-response-bit) (cons 'formatted (if (= force-response-bit 0) "False" "True"))))
        (cons 'extension-bit (list (cons 'raw extension-bit) (cons 'formatted (if (= extension-bit 0) "False" "True"))))
        (cons 'ric-info-mod-avail (list (cons 'raw ric-info-mod-avail) (cons 'formatted (fmt-hex ric-info-mod-avail))))
        (cons 'cm-jm-mod-avail-pcm-mode (list (cons 'raw cm-jm-mod-avail-pcm-mode) (cons 'formatted (if (= cm-jm-mod-avail-pcm-mode 0) "False" "True"))))
        (cons 'cm-jm-mod-avail-v34-duplex (list (cons 'raw cm-jm-mod-avail-v34-duplex) (cons 'formatted (if (= cm-jm-mod-avail-v34-duplex 0) "False" "True"))))
        (cons 'cm-jm-mod-avail-v34-half-duplex (list (cons 'raw cm-jm-mod-avail-v34-half-duplex) (cons 'formatted (if (= cm-jm-mod-avail-v34-half-duplex 0) "False" "True"))))
        (cons 'cm-jm-mod-avail-v32-v32bis (list (cons 'raw cm-jm-mod-avail-v32-v32bis) (cons 'formatted (if (= cm-jm-mod-avail-v32-v32bis 0) "False" "True"))))
        (cons 'cm-jm-mod-avail-v22-v22bis (list (cons 'raw cm-jm-mod-avail-v22-v22bis) (cons 'formatted (if (= cm-jm-mod-avail-v22-v22bis 0) "False" "True"))))
        (cons 'cm-jm-mod-avail-v17 (list (cons 'raw cm-jm-mod-avail-v17) (cons 'formatted (if (= cm-jm-mod-avail-v17 0) "False" "True"))))
        (cons 'cm-jm-mod-avail-v29-half-duplex (list (cons 'raw cm-jm-mod-avail-v29-half-duplex) (cons 'formatted (if (= cm-jm-mod-avail-v29-half-duplex 0) "False" "True"))))
        (cons 'cm-jm-mod-avail-v27ter (list (cons 'raw cm-jm-mod-avail-v27ter) (cons 'formatted (if (= cm-jm-mod-avail-v27ter 0) "False" "True"))))
        (cons 'cm-jm-mod-avail-v26ter (list (cons 'raw cm-jm-mod-avail-v26ter) (cons 'formatted (if (= cm-jm-mod-avail-v26ter 0) "False" "True"))))
        (cons 'cm-jm-mod-avail-v26bis (list (cons 'raw cm-jm-mod-avail-v26bis) (cons 'formatted (if (= cm-jm-mod-avail-v26bis 0) "False" "True"))))
        (cons 'cm-jm-mod-avail-v23-duplex (list (cons 'raw cm-jm-mod-avail-v23-duplex) (cons 'formatted (if (= cm-jm-mod-avail-v23-duplex 0) "False" "True"))))
        (cons 'cm-jm-mod-avail-v23-half-duplex (list (cons 'raw cm-jm-mod-avail-v23-half-duplex) (cons 'formatted (if (= cm-jm-mod-avail-v23-half-duplex 0) "False" "True"))))
        (cons 'cm-jm-mod-avail-v21 (list (cons 'raw cm-jm-mod-avail-v21) (cons 'formatted (if (= cm-jm-mod-avail-v21 0) "False" "True"))))
        (cons 'cm-jm-mod-avail-v90-or-v92-analog (list (cons 'raw cm-jm-mod-avail-v90-or-v92-analog) (cons 'formatted (if (= cm-jm-mod-avail-v90-or-v92-analog 0) "False" "True"))))
        (cons 'cm-jm-mod-avail-v90-or-v92-digital (list (cons 'raw cm-jm-mod-avail-v90-or-v92-digital) (cons 'formatted (if (= cm-jm-mod-avail-v90-or-v92-digital 0) "False" "True"))))
        (cons 'cm-jm-mod-avail-v91 (list (cons 'raw cm-jm-mod-avail-v91) (cons 'formatted (if (= cm-jm-mod-avail-v91 0) "False" "True"))))
        (cons 'ric-info-timeout-vendor (list (cons 'raw ric-info-timeout-vendor) (cons 'formatted (fmt-hex ric-info-timeout-vendor))))
        (cons 'ric-info-cleardown-reserved (list (cons 'raw ric-info-cleardown-reserved) (cons 'formatted (fmt-hex ric-info-cleardown-reserved))))
        (cons 'reason-id-code-info (list (cons 'raw reason-id-code-info) (cons 'formatted (fmt-hex reason-id-code-info))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-hex reserved))))
        (cons 'extension-len (list (cons 'raw extension-len) (cons 'formatted (number->string extension-len))))
        (cons 'ric-info-cleardown-vendor-tag (list (cons 'raw ric-info-cleardown-vendor-tag) (cons 'formatted (fmt-hex ric-info-cleardown-vendor-tag))))
        (cons 'ric-info-cleardown-vendor-info (list (cons 'raw ric-info-cleardown-vendor-info) (cons 'formatted (fmt-hex ric-info-cleardown-vendor-info))))
        )))

    (catch (e)
      (err (str "V150FW parse error: " e)))))

;; dissect-v150fw: parse V150FW from bytevector
;; Returns (ok fields-alist) or (err message)