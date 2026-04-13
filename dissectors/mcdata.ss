;; packet-mcdata.c
;; Routines for MCData dissection.
;; 3GPP TS 24.282 V18.8.0 MCData
;;
;; TODO:
;; Add support for OFF-NETWORK message and notification
;; Add support for DEFERRED LIST ACCESS messages
;; Add support for FD NETWORK NOTIFICATION message
;; Add support for GROUP EMERGENCY ALERT messages
;; Add support for COMMUNICATION RELEASE message
;;
;; Copyright 2026, Stefan Wenk
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;;

;; jerboa-ethereal/dissectors/mcdata.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mcdata.c

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
(def (dissect-mcdata buffer)
  "Mission critical data"
  (try
    (let* (
           (message-auth (unwrap (read-u8 buffer 0)))
           (message-protected (unwrap (read-u8 buffer 0)))
           (num-payloads (unwrap (read-u8 buffer 1)))
           (payload-val-text (unwrap (slice buffer 3 1)))
           (status-val (unwrap (read-u16be buffer 3)))
           (payload-val-bytes (unwrap (slice buffer 3 1)))
           (conv-id (unwrap (slice buffer 9 16)))
           (message-id (unwrap (slice buffer 9 16)))
           (sds-disposition-req-iei (unwrap (read-u8 buffer 10)))
           (fd-disposition-req-iei (unwrap (read-u8 buffer 11)))
           (mandatory-download-iei (unwrap (read-u8 buffer 12)))
           (ext-response-type-iei (unwrap (read-u8 buffer 13)))
           (release-response-type-iei (unwrap (read-u8 buffer 14)))
           (in-reply-to-message-id (unwrap (slice buffer 16 16)))
           (payload-len (unwrap (read-u16be buffer 17)))
           (user-ID (unwrap (slice buffer 17 1)))
           (deffered-fd-sig-payload (unwrap (slice buffer 17 1)))
           (app-metadata-container (unwrap (slice buffer 17 1)))
           (metadata (unwrap (slice buffer 17 1)))
           (group-id (unwrap (slice buffer 17 1)))
           (ext-app-id-data (unwrap (slice buffer 17 1)))
           (user-location (unwrap (slice buffer 17 1)))
           (org-name (unwrap (slice buffer 17 1)))
           )

      (ok (list
        (cons 'message-auth (list (cons 'raw message-auth) (cons 'formatted (number->string message-auth))))
        (cons 'message-protected (list (cons 'raw message-protected) (cons 'formatted (number->string message-protected))))
        (cons 'num-payloads (list (cons 'raw num-payloads) (cons 'formatted (number->string num-payloads))))
        (cons 'payload-val-text (list (cons 'raw payload-val-text) (cons 'formatted (utf8->string payload-val-text))))
        (cons 'status-val (list (cons 'raw status-val) (cons 'formatted (number->string status-val))))
        (cons 'payload-val-bytes (list (cons 'raw payload-val-bytes) (cons 'formatted (fmt-bytes payload-val-bytes))))
        (cons 'conv-id (list (cons 'raw conv-id) (cons 'formatted (fmt-bytes conv-id))))
        (cons 'message-id (list (cons 'raw message-id) (cons 'formatted (fmt-bytes message-id))))
        (cons 'sds-disposition-req-iei (list (cons 'raw sds-disposition-req-iei) (cons 'formatted (fmt-hex sds-disposition-req-iei))))
        (cons 'fd-disposition-req-iei (list (cons 'raw fd-disposition-req-iei) (cons 'formatted (fmt-hex fd-disposition-req-iei))))
        (cons 'mandatory-download-iei (list (cons 'raw mandatory-download-iei) (cons 'formatted (fmt-hex mandatory-download-iei))))
        (cons 'ext-response-type-iei (list (cons 'raw ext-response-type-iei) (cons 'formatted (fmt-hex ext-response-type-iei))))
        (cons 'release-response-type-iei (list (cons 'raw release-response-type-iei) (cons 'formatted (fmt-hex release-response-type-iei))))
        (cons 'in-reply-to-message-id (list (cons 'raw in-reply-to-message-id) (cons 'formatted (fmt-bytes in-reply-to-message-id))))
        (cons 'payload-len (list (cons 'raw payload-len) (cons 'formatted (number->string payload-len))))
        (cons 'user-ID (list (cons 'raw user-ID) (cons 'formatted (utf8->string user-ID))))
        (cons 'deffered-fd-sig-payload (list (cons 'raw deffered-fd-sig-payload) (cons 'formatted (fmt-bytes deffered-fd-sig-payload))))
        (cons 'app-metadata-container (list (cons 'raw app-metadata-container) (cons 'formatted (utf8->string app-metadata-container))))
        (cons 'metadata (list (cons 'raw metadata) (cons 'formatted (utf8->string metadata))))
        (cons 'group-id (list (cons 'raw group-id) (cons 'formatted (fmt-bytes group-id))))
        (cons 'ext-app-id-data (list (cons 'raw ext-app-id-data) (cons 'formatted (utf8->string ext-app-id-data))))
        (cons 'user-location (list (cons 'raw user-location) (cons 'formatted (fmt-bytes user-location))))
        (cons 'org-name (list (cons 'raw org-name) (cons 'formatted (utf8->string org-name))))
        )))

    (catch (e)
      (err (str "MCDATA parse error: " e)))))

;; dissect-mcdata: parse MCDATA from bytevector
;; Returns (ok fields-alist) or (err message)