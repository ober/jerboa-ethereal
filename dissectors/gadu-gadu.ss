;; packet-gadu-gadu.c
;; Routines for Gadu-Gadu dissection
;; Copyright 2011,2012, Jakub Zawadzki <darkjames-ws@darkjames.pl>
;;
;; Protocol documentation available at http://toxygen.net/libgadu/protocol/
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gadu-gadu.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gadu_gadu.c

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
(def (dissect-gadu-gadu buffer)
  "Gadu-Gadu Protocol"
  (try
    (let* (
           (gadu-login-protocol (unwrap (read-u32be buffer 4)))
           (gadu-login-version (unwrap (slice buffer 4 4)))
           (gadu-header-length (unwrap (read-u32be buffer 4)))
           (gadu-data (unwrap (slice buffer 8 1)))
           (gadu-login-hash (unwrap (slice buffer 27 4)))
           (gadu-login-local-ip (unwrap (read-u32be buffer 100)))
           (gadu-login-local-port (unwrap (read-u16be buffer 104)))
           (gadu-login-uin (unwrap (read-u32be buffer 106)))
           (gadu-login80-lang (unwrap (slice buffer 110 2)))
           (gadu-login-status (unwrap (read-u32be buffer 112)))
           (gadu-userdata-uin (unwrap (read-u32be buffer 132)))
           (gadu-userdata-attr-name (unwrap (slice buffer 144 4)))
           (gadu-userdata-attr-type (unwrap (read-u32be buffer 144)))
           (gadu-userdata-attr-value (unwrap (slice buffer 152 4)))
           (gadu-typing-notify-uin (unwrap (read-u32be buffer 154)))
           (gadu-msg-sender (unwrap (read-u32be buffer 186)))
           (gadu-msg-uin (unwrap (read-u32be buffer 210)))
           (gadu-msg-recipient (unwrap (read-u32be buffer 210)))
           (gadu-msg-seq (unwrap (read-u32be buffer 214)))
           (gadu-msg-class (unwrap (read-u32be buffer 218)))
           (gadu-msg80-offset-plain (unwrap (read-u32be buffer 222)))
           (gadu-msg80-offset-attr (unwrap (read-u32be buffer 226)))
           (gadu-msg-ack-recipient (unwrap (read-u32be buffer 234)))
           (gadu-msg-ack-seq (unwrap (read-u32be buffer 242)))
           (gadu-status-version (unwrap (read-u8 buffer 271)))
           (gadu-status-uin (unwrap (read-u32be buffer 278)))
           (gadu-status-status (unwrap (read-u32be buffer 282)))
           (gadu-status-ip (unwrap (read-u32be buffer 290)))
           (gadu-status-port (unwrap (read-u16be buffer 294)))
           (gadu-status-img-size (unwrap (read-u8 buffer 296)))
           (gadu-new-status-status (unwrap (read-u32be buffer 302)))
           (gadu-contact-uin-str (unwrap (slice buffer 321 1)))
           (gadu-contact-uin (unwrap (read-u32be buffer 327)))
           (gadu-contact-type (unwrap (read-u8 buffer 331)))
           (gadu-welcome-seed (unwrap (read-u32be buffer 332)))
           (gadu-userlist (unwrap (slice buffer 336 1)))
           (gadu-userlist-version (unwrap (read-u32be buffer 352)))
           (filename (unwrap (slice buffer 392 255)))
           (id (unwrap (slice buffer 647 8)))
           (uin-from (unwrap (read-u32be buffer 655)))
           (uin-to (unwrap (read-u32be buffer 659)))
           (gadu-pubdir-request-seq (unwrap (read-u32be buffer 664)))
           (gadu-pubdir-reply-seq (unwrap (read-u32be buffer 669)))
           )

      (ok (list
        (cons 'gadu-login-protocol (list (cons 'raw gadu-login-protocol) (cons 'formatted (fmt-hex gadu-login-protocol))))
        (cons 'gadu-login-version (list (cons 'raw gadu-login-version) (cons 'formatted (utf8->string gadu-login-version))))
        (cons 'gadu-header-length (list (cons 'raw gadu-header-length) (cons 'formatted (number->string gadu-header-length))))
        (cons 'gadu-data (list (cons 'raw gadu-data) (cons 'formatted (fmt-bytes gadu-data))))
        (cons 'gadu-login-hash (list (cons 'raw gadu-login-hash) (cons 'formatted (fmt-bytes gadu-login-hash))))
        (cons 'gadu-login-local-ip (list (cons 'raw gadu-login-local-ip) (cons 'formatted (fmt-ipv4 gadu-login-local-ip))))
        (cons 'gadu-login-local-port (list (cons 'raw gadu-login-local-port) (cons 'formatted (number->string gadu-login-local-port))))
        (cons 'gadu-login-uin (list (cons 'raw gadu-login-uin) (cons 'formatted (number->string gadu-login-uin))))
        (cons 'gadu-login80-lang (list (cons 'raw gadu-login80-lang) (cons 'formatted (utf8->string gadu-login80-lang))))
        (cons 'gadu-login-status (list (cons 'raw gadu-login-status) (cons 'formatted (fmt-hex gadu-login-status))))
        (cons 'gadu-userdata-uin (list (cons 'raw gadu-userdata-uin) (cons 'formatted (number->string gadu-userdata-uin))))
        (cons 'gadu-userdata-attr-name (list (cons 'raw gadu-userdata-attr-name) (cons 'formatted (utf8->string gadu-userdata-attr-name))))
        (cons 'gadu-userdata-attr-type (list (cons 'raw gadu-userdata-attr-type) (cons 'formatted (fmt-hex gadu-userdata-attr-type))))
        (cons 'gadu-userdata-attr-value (list (cons 'raw gadu-userdata-attr-value) (cons 'formatted (utf8->string gadu-userdata-attr-value))))
        (cons 'gadu-typing-notify-uin (list (cons 'raw gadu-typing-notify-uin) (cons 'formatted (number->string gadu-typing-notify-uin))))
        (cons 'gadu-msg-sender (list (cons 'raw gadu-msg-sender) (cons 'formatted (number->string gadu-msg-sender))))
        (cons 'gadu-msg-uin (list (cons 'raw gadu-msg-uin) (cons 'formatted (number->string gadu-msg-uin))))
        (cons 'gadu-msg-recipient (list (cons 'raw gadu-msg-recipient) (cons 'formatted (number->string gadu-msg-recipient))))
        (cons 'gadu-msg-seq (list (cons 'raw gadu-msg-seq) (cons 'formatted (number->string gadu-msg-seq))))
        (cons 'gadu-msg-class (list (cons 'raw gadu-msg-class) (cons 'formatted (fmt-hex gadu-msg-class))))
        (cons 'gadu-msg80-offset-plain (list (cons 'raw gadu-msg80-offset-plain) (cons 'formatted (number->string gadu-msg80-offset-plain))))
        (cons 'gadu-msg80-offset-attr (list (cons 'raw gadu-msg80-offset-attr) (cons 'formatted (number->string gadu-msg80-offset-attr))))
        (cons 'gadu-msg-ack-recipient (list (cons 'raw gadu-msg-ack-recipient) (cons 'formatted (number->string gadu-msg-ack-recipient))))
        (cons 'gadu-msg-ack-seq (list (cons 'raw gadu-msg-ack-seq) (cons 'formatted (number->string gadu-msg-ack-seq))))
        (cons 'gadu-status-version (list (cons 'raw gadu-status-version) (cons 'formatted (fmt-hex gadu-status-version))))
        (cons 'gadu-status-uin (list (cons 'raw gadu-status-uin) (cons 'formatted (number->string gadu-status-uin))))
        (cons 'gadu-status-status (list (cons 'raw gadu-status-status) (cons 'formatted (fmt-hex gadu-status-status))))
        (cons 'gadu-status-ip (list (cons 'raw gadu-status-ip) (cons 'formatted (fmt-ipv4 gadu-status-ip))))
        (cons 'gadu-status-port (list (cons 'raw gadu-status-port) (cons 'formatted (number->string gadu-status-port))))
        (cons 'gadu-status-img-size (list (cons 'raw gadu-status-img-size) (cons 'formatted (number->string gadu-status-img-size))))
        (cons 'gadu-new-status-status (list (cons 'raw gadu-new-status-status) (cons 'formatted (fmt-hex gadu-new-status-status))))
        (cons 'gadu-contact-uin-str (list (cons 'raw gadu-contact-uin-str) (cons 'formatted (utf8->string gadu-contact-uin-str))))
        (cons 'gadu-contact-uin (list (cons 'raw gadu-contact-uin) (cons 'formatted (number->string gadu-contact-uin))))
        (cons 'gadu-contact-type (list (cons 'raw gadu-contact-type) (cons 'formatted (fmt-hex gadu-contact-type))))
        (cons 'gadu-welcome-seed (list (cons 'raw gadu-welcome-seed) (cons 'formatted (fmt-hex gadu-welcome-seed))))
        (cons 'gadu-userlist (list (cons 'raw gadu-userlist) (cons 'formatted (fmt-bytes gadu-userlist))))
        (cons 'gadu-userlist-version (list (cons 'raw gadu-userlist-version) (cons 'formatted (number->string gadu-userlist-version))))
        (cons 'filename (list (cons 'raw filename) (cons 'formatted (utf8->string filename))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (fmt-bytes id))))
        (cons 'uin-from (list (cons 'raw uin-from) (cons 'formatted (number->string uin-from))))
        (cons 'uin-to (list (cons 'raw uin-to) (cons 'formatted (number->string uin-to))))
        (cons 'gadu-pubdir-request-seq (list (cons 'raw gadu-pubdir-request-seq) (cons 'formatted (fmt-hex gadu-pubdir-request-seq))))
        (cons 'gadu-pubdir-reply-seq (list (cons 'raw gadu-pubdir-reply-seq) (cons 'formatted (fmt-hex gadu-pubdir-reply-seq))))
        )))

    (catch (e)
      (err (str "GADU-GADU parse error: " e)))))

;; dissect-gadu-gadu: parse GADU-GADU from bytevector
;; Returns (ok fields-alist) or (err message)