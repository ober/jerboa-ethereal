;; packet-mmse.c
;; Routines for MMS Message Encapsulation dissection
;; Copyright 2001, Tom Uijldert <tom.uijldert@cmg.nl>
;; Copyright 2004, Olivier Biot
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;; ----------
;;
;; Dissector of an encoded Multimedia message PDU, as defined by the WAPForum
;; (http://www.wapforum.org) in "WAP-209-MMSEncapsulation-20020105-a".
;; Subsequent releases of MMS are in control of the Open Mobile Alliance (OMA):
;; Dissection of MMS 1.1 as in OMA-MMS-ENC-v1.1.
;; Dissection of MMS 1.2 as in OMA-MMS-ENC-v1.2 (not finished yet).
;;

;; jerboa-ethereal/dissectors/mmse.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mmse.c

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
(def (dissect-mmse buffer)
  "MMS Message Encapsulation"
  (try
    (let* (
           (transaction-id (unwrap (slice buffer 2 1)))
           (mms-version (unwrap (slice buffer 2 2)))
           (bcc (unwrap (slice buffer 2 1)))
           (cc (unwrap (slice buffer 2 1)))
           (content-location (unwrap (slice buffer 2 1)))
           (from (unwrap (slice buffer 2 1)))
           (message-class-str (unwrap (slice buffer 2 1)))
           (message-id (unwrap (slice buffer 2 1)))
           (message-size (unwrap (read-u32be buffer 2)))
           (response-text (unwrap (slice buffer 2 1)))
           (subject (unwrap (slice buffer 2 1)))
           (to (unwrap (slice buffer 2 1)))
           (retrieve-text (unwrap (slice buffer 2 1)))
           (reply-charging-id (unwrap (slice buffer 2 1)))
           (reply-charging-size (unwrap (read-u32be buffer 2)))
           (prev-sent-by (unwrap (slice buffer 2 1)))
           (prev-sent-by-fwd-count (unwrap (read-u32be buffer 2)))
           (prev-sent-date (unwrap (slice buffer 2 1)))
           (prev-sent-date-fwd-count (unwrap (read-u32be buffer 2)))
           (header-uint (unwrap (read-u8 buffer 2)))
           (header-string (unwrap (slice buffer 2 1)))
           (header-bytes (unwrap (slice buffer 2 1)))
           (ffheader (unwrap (slice buffer 2 1)))
           )

      (ok (list
        (cons 'transaction-id (list (cons 'raw transaction-id) (cons 'formatted (utf8->string transaction-id))))
        (cons 'mms-version (list (cons 'raw mms-version) (cons 'formatted (utf8->string mms-version))))
        (cons 'bcc (list (cons 'raw bcc) (cons 'formatted (utf8->string bcc))))
        (cons 'cc (list (cons 'raw cc) (cons 'formatted (utf8->string cc))))
        (cons 'content-location (list (cons 'raw content-location) (cons 'formatted (utf8->string content-location))))
        (cons 'from (list (cons 'raw from) (cons 'formatted (utf8->string from))))
        (cons 'message-class-str (list (cons 'raw message-class-str) (cons 'formatted (utf8->string message-class-str))))
        (cons 'message-id (list (cons 'raw message-id) (cons 'formatted (utf8->string message-id))))
        (cons 'message-size (list (cons 'raw message-size) (cons 'formatted (number->string message-size))))
        (cons 'response-text (list (cons 'raw response-text) (cons 'formatted (utf8->string response-text))))
        (cons 'subject (list (cons 'raw subject) (cons 'formatted (utf8->string subject))))
        (cons 'to (list (cons 'raw to) (cons 'formatted (utf8->string to))))
        (cons 'retrieve-text (list (cons 'raw retrieve-text) (cons 'formatted (utf8->string retrieve-text))))
        (cons 'reply-charging-id (list (cons 'raw reply-charging-id) (cons 'formatted (utf8->string reply-charging-id))))
        (cons 'reply-charging-size (list (cons 'raw reply-charging-size) (cons 'formatted (number->string reply-charging-size))))
        (cons 'prev-sent-by (list (cons 'raw prev-sent-by) (cons 'formatted (utf8->string prev-sent-by))))
        (cons 'prev-sent-by-fwd-count (list (cons 'raw prev-sent-by-fwd-count) (cons 'formatted (number->string prev-sent-by-fwd-count))))
        (cons 'prev-sent-date (list (cons 'raw prev-sent-date) (cons 'formatted (utf8->string prev-sent-date))))
        (cons 'prev-sent-date-fwd-count (list (cons 'raw prev-sent-date-fwd-count) (cons 'formatted (number->string prev-sent-date-fwd-count))))
        (cons 'header-uint (list (cons 'raw header-uint) (cons 'formatted (number->string header-uint))))
        (cons 'header-string (list (cons 'raw header-string) (cons 'formatted (utf8->string header-string))))
        (cons 'header-bytes (list (cons 'raw header-bytes) (cons 'formatted (fmt-bytes header-bytes))))
        (cons 'ffheader (list (cons 'raw ffheader) (cons 'formatted (utf8->string ffheader))))
        )))

    (catch (e)
      (err (str "MMSE parse error: " e)))))

;; dissect-mmse: parse MMSE from bytevector
;; Returns (ok fields-alist) or (err message)