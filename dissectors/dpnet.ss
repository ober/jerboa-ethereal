;; packet-dpnet.c
;; This is a dissector for the DirectPlay 8 protocol.
;;
;; Copyright 2017 - Alistair Leslie-Hughes
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;;

;; jerboa-ethereal/dissectors/dpnet.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dpnet.c

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
(def (dissect-dpnet buffer)
  "DirectPlay 8 protocol"
  (try
    (let* (
           (lead (unwrap (read-u8 buffer 0)))
           (data-command (unwrap (read-u8 buffer 0)))
           (command-data (extract-bits data-command 0x0 0))
           (command-reliable (extract-bits data-command 0x0 0))
           (command-seq (extract-bits data-command 0x0 0))
           (command-poll (extract-bits data-command 0x0 0))
           (command-new-msg (extract-bits data-command 0x0 0))
           (command-end-msg (extract-bits data-command 0x0 0))
           (command-user1 (extract-bits data-command 0x0 0))
           (command-user2 (extract-bits data-command 0x0 0))
           (payload (unwrap (read-u16be buffer 2)))
           (data (unwrap (slice buffer 21 1)))
           (reply-offset (unwrap (read-u32be buffer 21)))
           (response-size (unwrap (read-u32be buffer 25)))
           (desc-size (unwrap (read-u32be buffer 29)))
           (desc-flags (unwrap (read-u16le buffer 33)))
           (desc-client-server (extract-bits desc-flags 0x0 0))
           (desc-migrate-host (extract-bits desc-flags 0x0 0))
           (desc-nodpnsvr (extract-bits desc-flags 0x0 0))
           (desc-req-password (extract-bits desc-flags 0x0 0))
           (desc-no-enums (extract-bits desc-flags 0x0 0))
           (desc-fast-signed (extract-bits desc-flags 0x0 0))
           (desc-full-signed (extract-bits desc-flags 0x0 0))
           (data-cframe-send-secret (unwrap (read-u64be buffer 34)))
           (max-players (unwrap (read-u32be buffer 37)))
           (current-players (unwrap (read-u32be buffer 41)))
           (data-cframe-recv-secret (unwrap (read-u64be buffer 42)))
           (session-offset (unwrap (read-u32be buffer 45)))
           (session-size (unwrap (read-u32be buffer 49)))
           (password-offset (unwrap (read-u32be buffer 53)))
           (data-cframe-echo-time (unwrap (read-u32be buffer 54)))
           (data-cframe-msgid (unwrap (read-u8 buffer 54)))
           (data-cframe-rspid (unwrap (read-u8 buffer 55)))
           (password-size (unwrap (read-u32be buffer 57)))
           (data-cframe-session (unwrap (read-u32be buffer 60)))
           (reserved-offset (unwrap (read-u32be buffer 61)))
           (reserved-size (unwrap (read-u32be buffer 65)))
           (data-cframe-signature (unwrap (read-u64be buffer 68)))
           (application-offset (unwrap (read-u32be buffer 69)))
           (data-cframe-retry (unwrap (read-u8 buffer 69)))
           (data-cframe-nseq (unwrap (read-u8 buffer 70)))
           (data-cframe-nrcv (unwrap (read-u8 buffer 71)))
           (data-cframe-padding (unwrap (read-u16be buffer 72)))
           (application-size (unwrap (read-u32be buffer 73)))
           (data-cframe-timestamp (unwrap (read-u32be buffer 74)))
           (instance (unwrap (slice buffer 77 16)))
           (data-cframe-sack-mask1 (unwrap (read-u32be buffer 78)))
           (data-cframe-sack-mask2 (unwrap (read-u32be buffer 82)))
           (data-cframe-send-mask1 (unwrap (read-u32be buffer 86)))
           (data-cframe-send-mask2 (unwrap (read-u32be buffer 90)))
           (application (unwrap (slice buffer 93 16)))
           )

      (ok (list
        (cons 'lead (list (cons 'raw lead) (cons 'formatted (number->string lead))))
        (cons 'data-command (list (cons 'raw data-command) (cons 'formatted (fmt-hex data-command))))
        (cons 'command-data (list (cons 'raw command-data) (cons 'formatted (if (= command-data 0) "Not set" "Set"))))
        (cons 'command-reliable (list (cons 'raw command-reliable) (cons 'formatted (if (= command-reliable 0) "Not set" "Set"))))
        (cons 'command-seq (list (cons 'raw command-seq) (cons 'formatted (if (= command-seq 0) "Not set" "Set"))))
        (cons 'command-poll (list (cons 'raw command-poll) (cons 'formatted (if (= command-poll 0) "Not set" "Set"))))
        (cons 'command-new-msg (list (cons 'raw command-new-msg) (cons 'formatted (if (= command-new-msg 0) "Not set" "Set"))))
        (cons 'command-end-msg (list (cons 'raw command-end-msg) (cons 'formatted (if (= command-end-msg 0) "Not set" "Set"))))
        (cons 'command-user1 (list (cons 'raw command-user1) (cons 'formatted (if (= command-user1 0) "Not set" "Set"))))
        (cons 'command-user2 (list (cons 'raw command-user2) (cons 'formatted (if (= command-user2 0) "Not set" "Set"))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-hex payload))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'reply-offset (list (cons 'raw reply-offset) (cons 'formatted (number->string reply-offset))))
        (cons 'response-size (list (cons 'raw response-size) (cons 'formatted (number->string response-size))))
        (cons 'desc-size (list (cons 'raw desc-size) (cons 'formatted (number->string desc-size))))
        (cons 'desc-flags (list (cons 'raw desc-flags) (cons 'formatted (fmt-hex desc-flags))))
        (cons 'desc-client-server (list (cons 'raw desc-client-server) (cons 'formatted (if (= desc-client-server 0) "Peer session" "Client/Server session"))))
        (cons 'desc-migrate-host (list (cons 'raw desc-migrate-host) (cons 'formatted (if (= desc-migrate-host 0) "Host Migrating NOT allowed" "Host Migrating allowed"))))
        (cons 'desc-nodpnsvr (list (cons 'raw desc-nodpnsvr) (cons 'formatted (if (= desc-nodpnsvr 0) "Using dpnsvr.exe" "NOT using dpnsvr.exe"))))
        (cons 'desc-req-password (list (cons 'raw desc-req-password) (cons 'formatted (if (= desc-req-password 0) "NO password required" "Password required"))))
        (cons 'desc-no-enums (list (cons 'raw desc-no-enums) (cons 'formatted (if (= desc-no-enums 0) "Enumeration allowed" "Enumeration NOT allowed"))))
        (cons 'desc-fast-signed (list (cons 'raw desc-fast-signed) (cons 'formatted (if (= desc-fast-signed 0) "NOT using Fast signing" "Using Fast signing"))))
        (cons 'desc-full-signed (list (cons 'raw desc-full-signed) (cons 'formatted (if (= desc-full-signed 0) "NOT using Full signing" "Using Full signing"))))
        (cons 'data-cframe-send-secret (list (cons 'raw data-cframe-send-secret) (cons 'formatted (fmt-hex data-cframe-send-secret))))
        (cons 'max-players (list (cons 'raw max-players) (cons 'formatted (number->string max-players))))
        (cons 'current-players (list (cons 'raw current-players) (cons 'formatted (number->string current-players))))
        (cons 'data-cframe-recv-secret (list (cons 'raw data-cframe-recv-secret) (cons 'formatted (fmt-hex data-cframe-recv-secret))))
        (cons 'session-offset (list (cons 'raw session-offset) (cons 'formatted (number->string session-offset))))
        (cons 'session-size (list (cons 'raw session-size) (cons 'formatted (number->string session-size))))
        (cons 'password-offset (list (cons 'raw password-offset) (cons 'formatted (number->string password-offset))))
        (cons 'data-cframe-echo-time (list (cons 'raw data-cframe-echo-time) (cons 'formatted (fmt-hex data-cframe-echo-time))))
        (cons 'data-cframe-msgid (list (cons 'raw data-cframe-msgid) (cons 'formatted (fmt-hex data-cframe-msgid))))
        (cons 'data-cframe-rspid (list (cons 'raw data-cframe-rspid) (cons 'formatted (fmt-hex data-cframe-rspid))))
        (cons 'password-size (list (cons 'raw password-size) (cons 'formatted (number->string password-size))))
        (cons 'data-cframe-session (list (cons 'raw data-cframe-session) (cons 'formatted (fmt-hex data-cframe-session))))
        (cons 'reserved-offset (list (cons 'raw reserved-offset) (cons 'formatted (number->string reserved-offset))))
        (cons 'reserved-size (list (cons 'raw reserved-size) (cons 'formatted (number->string reserved-size))))
        (cons 'data-cframe-signature (list (cons 'raw data-cframe-signature) (cons 'formatted (fmt-hex data-cframe-signature))))
        (cons 'application-offset (list (cons 'raw application-offset) (cons 'formatted (number->string application-offset))))
        (cons 'data-cframe-retry (list (cons 'raw data-cframe-retry) (cons 'formatted (fmt-hex data-cframe-retry))))
        (cons 'data-cframe-nseq (list (cons 'raw data-cframe-nseq) (cons 'formatted (fmt-hex data-cframe-nseq))))
        (cons 'data-cframe-nrcv (list (cons 'raw data-cframe-nrcv) (cons 'formatted (fmt-hex data-cframe-nrcv))))
        (cons 'data-cframe-padding (list (cons 'raw data-cframe-padding) (cons 'formatted (number->string data-cframe-padding))))
        (cons 'application-size (list (cons 'raw application-size) (cons 'formatted (number->string application-size))))
        (cons 'data-cframe-timestamp (list (cons 'raw data-cframe-timestamp) (cons 'formatted (number->string data-cframe-timestamp))))
        (cons 'instance (list (cons 'raw instance) (cons 'formatted (fmt-bytes instance))))
        (cons 'data-cframe-sack-mask1 (list (cons 'raw data-cframe-sack-mask1) (cons 'formatted (fmt-hex data-cframe-sack-mask1))))
        (cons 'data-cframe-sack-mask2 (list (cons 'raw data-cframe-sack-mask2) (cons 'formatted (fmt-hex data-cframe-sack-mask2))))
        (cons 'data-cframe-send-mask1 (list (cons 'raw data-cframe-send-mask1) (cons 'formatted (fmt-hex data-cframe-send-mask1))))
        (cons 'data-cframe-send-mask2 (list (cons 'raw data-cframe-send-mask2) (cons 'formatted (fmt-hex data-cframe-send-mask2))))
        (cons 'application (list (cons 'raw application) (cons 'formatted (fmt-bytes application))))
        )))

    (catch (e)
      (err (str "DPNET parse error: " e)))))

;; dissect-dpnet: parse DPNET from bytevector
;; Returns (ok fields-alist) or (err message)