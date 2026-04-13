;; packet-sftp.c
;; Routines for ssh packet dissection
;;
;; Jérôme Hamm
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-ssh.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;;
;; Note:  support for SFTP.
;;
;;

;; jerboa-ethereal/dissectors/sftp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-sftp.c

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
(def (dissect-sftp buffer)
  "SSH File Transfer Protocol"
  (try
    (let* (
           (sftp-version (unwrap (read-u32be buffer 9)))
           (sftp-pflags (unwrap (read-u32be buffer 21)))
           (sftp-length (unwrap (read-u32be buffer 49)))
           (sftp-offset (unwrap (read-u64be buffer 61)))
           (sftp-path-len (unwrap (read-u32be buffer 145)))
           (sftp-path (unwrap (slice buffer 149 1)))
           (sftp-status (unwrap (read-u32be buffer 153)))
           (sftp-error-message-len (unwrap (read-u32be buffer 157)))
           (sftp-error-message (unwrap (slice buffer 161 1)))
           (lang-tag-length (unwrap (read-u32be buffer 161)))
           (lang-tag (unwrap (slice buffer 165 1)))
           (sftp-handle-len (unwrap (read-u32be buffer 169)))
           (sftp-handle (unwrap (slice buffer 173 1)))
           (sftp-data-len (unwrap (read-u32be buffer 177)))
           (sftp-data (unwrap (slice buffer 181 1)))
           (sftp-name-count (unwrap (read-u32be buffer 185)))
           (sftp-name-fn-len (unwrap (read-u32be buffer 189)))
           (sftp-name-fn (unwrap (slice buffer 193 1)))
           (sftp-name-ln-len (unwrap (read-u32be buffer 193)))
           (sftp-name-ln (unwrap (slice buffer 197 1)))
           (sftp-id (unwrap (read-u32be buffer 197)))
           (sftp-len (unwrap (read-u32be buffer 201)))
           )

      (ok (list
        (cons 'sftp-version (list (cons 'raw sftp-version) (cons 'formatted (number->string sftp-version))))
        (cons 'sftp-pflags (list (cons 'raw sftp-pflags) (cons 'formatted (fmt-hex sftp-pflags))))
        (cons 'sftp-length (list (cons 'raw sftp-length) (cons 'formatted (number->string sftp-length))))
        (cons 'sftp-offset (list (cons 'raw sftp-offset) (cons 'formatted (number->string sftp-offset))))
        (cons 'sftp-path-len (list (cons 'raw sftp-path-len) (cons 'formatted (number->string sftp-path-len))))
        (cons 'sftp-path (list (cons 'raw sftp-path) (cons 'formatted (utf8->string sftp-path))))
        (cons 'sftp-status (list (cons 'raw sftp-status) (cons 'formatted (number->string sftp-status))))
        (cons 'sftp-error-message-len (list (cons 'raw sftp-error-message-len) (cons 'formatted (number->string sftp-error-message-len))))
        (cons 'sftp-error-message (list (cons 'raw sftp-error-message) (cons 'formatted (utf8->string sftp-error-message))))
        (cons 'lang-tag-length (list (cons 'raw lang-tag-length) (cons 'formatted (number->string lang-tag-length))))
        (cons 'lang-tag (list (cons 'raw lang-tag) (cons 'formatted (utf8->string lang-tag))))
        (cons 'sftp-handle-len (list (cons 'raw sftp-handle-len) (cons 'formatted (number->string sftp-handle-len))))
        (cons 'sftp-handle (list (cons 'raw sftp-handle) (cons 'formatted (fmt-bytes sftp-handle))))
        (cons 'sftp-data-len (list (cons 'raw sftp-data-len) (cons 'formatted (number->string sftp-data-len))))
        (cons 'sftp-data (list (cons 'raw sftp-data) (cons 'formatted (fmt-bytes sftp-data))))
        (cons 'sftp-name-count (list (cons 'raw sftp-name-count) (cons 'formatted (number->string sftp-name-count))))
        (cons 'sftp-name-fn-len (list (cons 'raw sftp-name-fn-len) (cons 'formatted (number->string sftp-name-fn-len))))
        (cons 'sftp-name-fn (list (cons 'raw sftp-name-fn) (cons 'formatted (utf8->string sftp-name-fn))))
        (cons 'sftp-name-ln-len (list (cons 'raw sftp-name-ln-len) (cons 'formatted (number->string sftp-name-ln-len))))
        (cons 'sftp-name-ln (list (cons 'raw sftp-name-ln) (cons 'formatted (utf8->string sftp-name-ln))))
        (cons 'sftp-id (list (cons 'raw sftp-id) (cons 'formatted (number->string sftp-id))))
        (cons 'sftp-len (list (cons 'raw sftp-len) (cons 'formatted (number->string sftp-len))))
        )))

    (catch (e)
      (err (str "SFTP parse error: " e)))))

;; dissect-sftp: parse SFTP from bytevector
;; Returns (ok fields-alist) or (err message)