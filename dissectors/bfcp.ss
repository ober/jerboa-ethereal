;; packet-bfcp.c
;; Routines for Binary Floor Control Protocol(BFCP) dissection
;; Copyright 2012, Nitinkumar Yemul <nitinkumaryemul@gmail.com>
;;
;; Updated with attribute dissection
;; Copyright 2012, Anders Broman <anders.broman@ericsson.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; BFCP Message structure is defined in RFC 8855
;;

;; jerboa-ethereal/dissectors/bfcp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bfcp.c
;; RFC 8855

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
(def (dissect-bfcp buffer)
  "Binary Floor Control Protocol"
  (try
    (let* (
           (setup-method (unwrap (slice buffer 0 1)))
           (setup-frame (unwrap (read-u32be buffer 0)))
           (setup (unwrap (slice buffer 0 1)))
           (attribute-types-m-bit (unwrap (read-u8 buffer 0)))
           (attribute-length (unwrap (read-u8 buffer 0)))
           (version (unwrap (read-u8 buffer 0)))
           (hdr-r-bit (unwrap (read-u8 buffer 0)))
           (hdr-f-bit (unwrap (read-u8 buffer 0)))
           (payload-length (unwrap (read-u16be buffer 0)))
           (conference-id (unwrap (read-u32be buffer 2)))
           (priority (unwrap (read-u16be buffer 6)))
           (transaction-id (unwrap (read-u16be buffer 6)))
           (queue-pos (unwrap (read-u8 buffer 8)))
           (error-specific-details (unwrap (slice buffer 8 1)))
           (error-info-text (unwrap (slice buffer 8 1)))
           (part-prov-info-text (unwrap (slice buffer 8 1)))
           (status-info-text (unwrap (slice buffer 8 1)))
           (user-id (unwrap (read-u16be buffer 8)))
           (padding (unwrap (slice buffer 10 1)))
           (user-disp-name (unwrap (slice buffer 10 1)))
           (user-uri (unwrap (slice buffer 10 1)))
           (beneficiary-id (unwrap (read-u16be buffer 10)))
           (fragment-offset (unwrap (read-u16be buffer 10)))
           (fragment-length (unwrap (read-u16be buffer 12)))
           (req-by-id (unwrap (read-u16be buffer 14)))
           (floor-id (unwrap (read-u16be buffer 16)))
           (floor-request-id (unwrap (read-u16be buffer 18)))
           (payload (unwrap (slice buffer 20 1)))
           )

      (ok (list
        (cons 'setup-method (list (cons 'raw setup-method) (cons 'formatted (utf8->string setup-method))))
        (cons 'setup-frame (list (cons 'raw setup-frame) (cons 'formatted (number->string setup-frame))))
        (cons 'setup (list (cons 'raw setup) (cons 'formatted (utf8->string setup))))
        (cons 'attribute-types-m-bit (list (cons 'raw attribute-types-m-bit) (cons 'formatted (number->string attribute-types-m-bit))))
        (cons 'attribute-length (list (cons 'raw attribute-length) (cons 'formatted (number->string attribute-length))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'hdr-r-bit (list (cons 'raw hdr-r-bit) (cons 'formatted (if (= hdr-r-bit 0) "False" "True"))))
        (cons 'hdr-f-bit (list (cons 'raw hdr-f-bit) (cons 'formatted (if (= hdr-f-bit 0) "False" "True"))))
        (cons 'payload-length (list (cons 'raw payload-length) (cons 'formatted (number->string payload-length))))
        (cons 'conference-id (list (cons 'raw conference-id) (cons 'formatted (number->string conference-id))))
        (cons 'priority (list (cons 'raw priority) (cons 'formatted (number->string priority))))
        (cons 'transaction-id (list (cons 'raw transaction-id) (cons 'formatted (number->string transaction-id))))
        (cons 'queue-pos (list (cons 'raw queue-pos) (cons 'formatted (number->string queue-pos))))
        (cons 'error-specific-details (list (cons 'raw error-specific-details) (cons 'formatted (fmt-bytes error-specific-details))))
        (cons 'error-info-text (list (cons 'raw error-info-text) (cons 'formatted (utf8->string error-info-text))))
        (cons 'part-prov-info-text (list (cons 'raw part-prov-info-text) (cons 'formatted (utf8->string part-prov-info-text))))
        (cons 'status-info-text (list (cons 'raw status-info-text) (cons 'formatted (utf8->string status-info-text))))
        (cons 'user-id (list (cons 'raw user-id) (cons 'formatted (number->string user-id))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        (cons 'user-disp-name (list (cons 'raw user-disp-name) (cons 'formatted (utf8->string user-disp-name))))
        (cons 'user-uri (list (cons 'raw user-uri) (cons 'formatted (utf8->string user-uri))))
        (cons 'beneficiary-id (list (cons 'raw beneficiary-id) (cons 'formatted (number->string beneficiary-id))))
        (cons 'fragment-offset (list (cons 'raw fragment-offset) (cons 'formatted (number->string fragment-offset))))
        (cons 'fragment-length (list (cons 'raw fragment-length) (cons 'formatted (number->string fragment-length))))
        (cons 'req-by-id (list (cons 'raw req-by-id) (cons 'formatted (number->string req-by-id))))
        (cons 'floor-id (list (cons 'raw floor-id) (cons 'formatted (number->string floor-id))))
        (cons 'floor-request-id (list (cons 'raw floor-request-id) (cons 'formatted (number->string floor-request-id))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-bytes payload))))
        )))

    (catch (e)
      (err (str "BFCP parse error: " e)))))

;; dissect-bfcp: parse BFCP from bytevector
;; Returns (ok fields-alist) or (err message)