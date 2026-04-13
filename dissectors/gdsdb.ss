;; packet-gdsdb.c
;; Routines for Firebird/Interbase dissection
;; Copyright 2007, Moshe van der Sterre <moshevds@gmail.com>
;;
;; Firebird home: http://www.firebirdsql.org
;; Source: http://sourceforge.net/projects/firebird/
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gdsdb.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gdsdb.c

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
(def (dissect-gdsdb buffer)
  "Firebird SQL Database Remote Protocol"
  (try
    (let* (
           (connect-version (unwrap (read-u32be buffer 8)))
           (connect-count (unwrap (read-u32be buffer 16)))
           (connect-pref-version (unwrap (read-u32be buffer 20)))
           (connect-pref-mintype (unwrap (read-u32be buffer 28)))
           (connect-pref-maxtype (unwrap (read-u32be buffer 32)))
           (connect-pref-weight (unwrap (read-u32be buffer 36)))
           (accept-version (unwrap (read-u32be buffer 40)))
           (accept-proto-min-type (unwrap (read-u32be buffer 48)))
           (request-type (unwrap (read-u32be buffer 52)))
           (request-object (unwrap (read-u32be buffer 56)))
           (request-partner (unwrap (read-u64be buffer 60)))
           (attach-database-object-id (unwrap (read-u32be buffer 68)))
           (compile-database (unwrap (read-u32be buffer 72)))
           (receive-request (unwrap (read-u32be buffer 76)))
           (receive-incarnation (unwrap (read-u32be buffer 80)))
           (receive-transaction (unwrap (read-u32be buffer 84)))
           (receive-msgnr (unwrap (read-u32be buffer 88)))
           (receive-messages (unwrap (read-u32be buffer 92)))
           (receive-direction (unwrap (read-u32be buffer 96)))
           (receive-offset (unwrap (read-u64be buffer 100)))
           (send-request (unwrap (read-u32be buffer 108)))
           (send-incarnation (unwrap (read-u32be buffer 112)))
           (send-transaction (unwrap (read-u32be buffer 116)))
           (send-msgnr (unwrap (read-u32be buffer 120)))
           (send-messages (unwrap (read-u32be buffer 124)))
           (status-vector-error-code (unwrap (read-u32be buffer 132)))
           (status-vector-number (unwrap (read-u32be buffer 136)))
           (response-object (unwrap (read-u32be buffer 140)))
           (response-blobid (unwrap (read-u64be buffer 144)))
           (response-datasize (unwrap (read-u32be buffer 152)))
           (response-data (unwrap (slice buffer 156 1)))
           (transact-database (unwrap (read-u32be buffer 156)))
           (transact-transaction (unwrap (read-u32be buffer 160)))
           (transactresponse-messages (unwrap (read-u32be buffer 164)))
           (openblob-transaction (unwrap (read-u32be buffer 180)))
           (openblob-id (unwrap (read-u64be buffer 184)))
           (reconnect-handle (unwrap (read-u32be buffer 192)))
           (info-object (unwrap (read-u32be buffer 196)))
           (info-incarnation (unwrap (read-u32be buffer 200)))
           (info-buffer-length (unwrap (read-u32be buffer 204)))
           (release-object (unwrap (read-u32be buffer 208)))
           (execute-statement (unwrap (read-u32be buffer 212)))
           (execute-transaction (unwrap (read-u32be buffer 216)))
           (execute-message-number (unwrap (read-u32be buffer 220)))
           (execute-messages (unwrap (read-u32be buffer 224)))
           (prepare-transaction (unwrap (read-u32be buffer 228)))
           (prepare-statement (unwrap (read-u32be buffer 232)))
           (prepare-dialect (unwrap (read-u32be buffer 236)))
           (prepare-bufferlength (unwrap (read-u32be buffer 240)))
           (free-statement (unwrap (read-u32be buffer 244)))
           (free-option (unwrap (read-u32be buffer 248)))
           )

      (ok (list
        (cons 'connect-version (list (cons 'raw connect-version) (cons 'formatted (number->string connect-version))))
        (cons 'connect-count (list (cons 'raw connect-count) (cons 'formatted (number->string connect-count))))
        (cons 'connect-pref-version (list (cons 'raw connect-pref-version) (cons 'formatted (number->string connect-pref-version))))
        (cons 'connect-pref-mintype (list (cons 'raw connect-pref-mintype) (cons 'formatted (number->string connect-pref-mintype))))
        (cons 'connect-pref-maxtype (list (cons 'raw connect-pref-maxtype) (cons 'formatted (number->string connect-pref-maxtype))))
        (cons 'connect-pref-weight (list (cons 'raw connect-pref-weight) (cons 'formatted (number->string connect-pref-weight))))
        (cons 'accept-version (list (cons 'raw accept-version) (cons 'formatted (number->string accept-version))))
        (cons 'accept-proto-min-type (list (cons 'raw accept-proto-min-type) (cons 'formatted (number->string accept-proto-min-type))))
        (cons 'request-type (list (cons 'raw request-type) (cons 'formatted (number->string request-type))))
        (cons 'request-object (list (cons 'raw request-object) (cons 'formatted (number->string request-object))))
        (cons 'request-partner (list (cons 'raw request-partner) (cons 'formatted (number->string request-partner))))
        (cons 'attach-database-object-id (list (cons 'raw attach-database-object-id) (cons 'formatted (number->string attach-database-object-id))))
        (cons 'compile-database (list (cons 'raw compile-database) (cons 'formatted (number->string compile-database))))
        (cons 'receive-request (list (cons 'raw receive-request) (cons 'formatted (number->string receive-request))))
        (cons 'receive-incarnation (list (cons 'raw receive-incarnation) (cons 'formatted (number->string receive-incarnation))))
        (cons 'receive-transaction (list (cons 'raw receive-transaction) (cons 'formatted (number->string receive-transaction))))
        (cons 'receive-msgnr (list (cons 'raw receive-msgnr) (cons 'formatted (number->string receive-msgnr))))
        (cons 'receive-messages (list (cons 'raw receive-messages) (cons 'formatted (number->string receive-messages))))
        (cons 'receive-direction (list (cons 'raw receive-direction) (cons 'formatted (number->string receive-direction))))
        (cons 'receive-offset (list (cons 'raw receive-offset) (cons 'formatted (number->string receive-offset))))
        (cons 'send-request (list (cons 'raw send-request) (cons 'formatted (number->string send-request))))
        (cons 'send-incarnation (list (cons 'raw send-incarnation) (cons 'formatted (number->string send-incarnation))))
        (cons 'send-transaction (list (cons 'raw send-transaction) (cons 'formatted (number->string send-transaction))))
        (cons 'send-msgnr (list (cons 'raw send-msgnr) (cons 'formatted (number->string send-msgnr))))
        (cons 'send-messages (list (cons 'raw send-messages) (cons 'formatted (number->string send-messages))))
        (cons 'status-vector-error-code (list (cons 'raw status-vector-error-code) (cons 'formatted (number->string status-vector-error-code))))
        (cons 'status-vector-number (list (cons 'raw status-vector-number) (cons 'formatted (number->string status-vector-number))))
        (cons 'response-object (list (cons 'raw response-object) (cons 'formatted (fmt-hex response-object))))
        (cons 'response-blobid (list (cons 'raw response-blobid) (cons 'formatted (fmt-hex response-blobid))))
        (cons 'response-datasize (list (cons 'raw response-datasize) (cons 'formatted (number->string response-datasize))))
        (cons 'response-data (list (cons 'raw response-data) (cons 'formatted (fmt-bytes response-data))))
        (cons 'transact-database (list (cons 'raw transact-database) (cons 'formatted (number->string transact-database))))
        (cons 'transact-transaction (list (cons 'raw transact-transaction) (cons 'formatted (number->string transact-transaction))))
        (cons 'transactresponse-messages (list (cons 'raw transactresponse-messages) (cons 'formatted (number->string transactresponse-messages))))
        (cons 'openblob-transaction (list (cons 'raw openblob-transaction) (cons 'formatted (number->string openblob-transaction))))
        (cons 'openblob-id (list (cons 'raw openblob-id) (cons 'formatted (fmt-hex openblob-id))))
        (cons 'reconnect-handle (list (cons 'raw reconnect-handle) (cons 'formatted (number->string reconnect-handle))))
        (cons 'info-object (list (cons 'raw info-object) (cons 'formatted (number->string info-object))))
        (cons 'info-incarnation (list (cons 'raw info-incarnation) (cons 'formatted (number->string info-incarnation))))
        (cons 'info-buffer-length (list (cons 'raw info-buffer-length) (cons 'formatted (number->string info-buffer-length))))
        (cons 'release-object (list (cons 'raw release-object) (cons 'formatted (number->string release-object))))
        (cons 'execute-statement (list (cons 'raw execute-statement) (cons 'formatted (number->string execute-statement))))
        (cons 'execute-transaction (list (cons 'raw execute-transaction) (cons 'formatted (number->string execute-transaction))))
        (cons 'execute-message-number (list (cons 'raw execute-message-number) (cons 'formatted (number->string execute-message-number))))
        (cons 'execute-messages (list (cons 'raw execute-messages) (cons 'formatted (number->string execute-messages))))
        (cons 'prepare-transaction (list (cons 'raw prepare-transaction) (cons 'formatted (number->string prepare-transaction))))
        (cons 'prepare-statement (list (cons 'raw prepare-statement) (cons 'formatted (number->string prepare-statement))))
        (cons 'prepare-dialect (list (cons 'raw prepare-dialect) (cons 'formatted (number->string prepare-dialect))))
        (cons 'prepare-bufferlength (list (cons 'raw prepare-bufferlength) (cons 'formatted (number->string prepare-bufferlength))))
        (cons 'free-statement (list (cons 'raw free-statement) (cons 'formatted (number->string free-statement))))
        (cons 'free-option (list (cons 'raw free-option) (cons 'formatted (number->string free-option))))
        )))

    (catch (e)
      (err (str "GDSDB parse error: " e)))))

;; dissect-gdsdb: parse GDSDB from bytevector
;; Returns (ok fields-alist) or (err message)