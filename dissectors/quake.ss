;; packet-quake.c
;; Routines for Quake packet dissection
;;
;; Uwe Girlich <uwe@planetquake.com>
;; http://www.idsoftware.com/q1source/q1source.zip
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-tftp.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/quake.ss
;; Auto-generated from wireshark/epan/dissectors/packet-quake.c

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
(def (dissect-quake buffer)
  "Quake Network Protocol"
  (try
    (let* (
           (header-flags-control (unwrap (read-u8 buffer 0)))
           (header-flags-unreliable (unwrap (read-u8 buffer 0)))
           (header-flags-endmsg (unwrap (read-u8 buffer 0)))
           (header-flags-no-ack (unwrap (read-u8 buffer 0)))
           (header-flags-ack (unwrap (read-u8 buffer 0)))
           (header-flags-data (unwrap (read-u8 buffer 0)))
           (header-flags (unwrap (read-u16be buffer 0)))
           (CCREP-REJECT-reason (unwrap (slice buffer 0 1)))
           (CCREP-ACCEPT-port (unwrap (read-u32be buffer 0)))
           (CCREQ-RULE-INFO-lastrule (unwrap (slice buffer 0 1)))
           (CCREQ-PLAYER-INFO-player (unwrap (read-u8 buffer 0)))
           (CCREQ-CONNECT-game (unwrap (slice buffer 0 1)))
           (CCREQ-CONNECT-version (unwrap (read-u8 buffer 0)))
           (CCREQ-SERVER-INFO-game (unwrap (slice buffer 0 1)))
           (CCREP-SERVER-INFO-address (unwrap (slice buffer 0 1)))
           (CCREP-SERVER-INFO-server (unwrap (slice buffer 0 1)))
           (CCREP-SERVER-INFO-map (unwrap (slice buffer 0 1)))
           (CCREP-SERVER-INFO-num-player (unwrap (read-u8 buffer 0)))
           (CCREP-RULE-INFO-rule (unwrap (slice buffer 0 1)))
           (CCREP-RULE-INFO-value (unwrap (slice buffer 0 1)))
           (CCREP-SERVER-INFO-max-player (unwrap (read-u8 buffer 1)))
           (CCREP-PLAYER-INFO-name (unwrap (slice buffer 1 1)))
           (CCREP-PLAYER-INFO-colors (unwrap (read-u32be buffer 1)))
           (header-length (unwrap (read-u16be buffer 2)))
           (CCREQ-SERVER-INFO-version (unwrap (read-u8 buffer 2)))
           (header-sequence (unwrap (read-u32be buffer 4)))
           (CCREP-PLAYER-INFO-frags (unwrap (read-u32be buffer 5)))
           (CCREP-PLAYER-INFO-connect-time (unwrap (read-u32be buffer 9)))
           (CCREP-PLAYER-INFO-address (unwrap (slice buffer 13 1)))
           )

      (ok (list
        (cons 'header-flags-control (list (cons 'raw header-flags-control) (cons 'formatted (if (= header-flags-control 0) "False" "True"))))
        (cons 'header-flags-unreliable (list (cons 'raw header-flags-unreliable) (cons 'formatted (if (= header-flags-unreliable 0) "False" "True"))))
        (cons 'header-flags-endmsg (list (cons 'raw header-flags-endmsg) (cons 'formatted (if (= header-flags-endmsg 0) "False" "True"))))
        (cons 'header-flags-no-ack (list (cons 'raw header-flags-no-ack) (cons 'formatted (if (= header-flags-no-ack 0) "False" "True"))))
        (cons 'header-flags-ack (list (cons 'raw header-flags-ack) (cons 'formatted (if (= header-flags-ack 0) "False" "True"))))
        (cons 'header-flags-data (list (cons 'raw header-flags-data) (cons 'formatted (if (= header-flags-data 0) "False" "True"))))
        (cons 'header-flags (list (cons 'raw header-flags) (cons 'formatted (fmt-hex header-flags))))
        (cons 'CCREP-REJECT-reason (list (cons 'raw CCREP-REJECT-reason) (cons 'formatted (utf8->string CCREP-REJECT-reason))))
        (cons 'CCREP-ACCEPT-port (list (cons 'raw CCREP-ACCEPT-port) (cons 'formatted (number->string CCREP-ACCEPT-port))))
        (cons 'CCREQ-RULE-INFO-lastrule (list (cons 'raw CCREQ-RULE-INFO-lastrule) (cons 'formatted (utf8->string CCREQ-RULE-INFO-lastrule))))
        (cons 'CCREQ-PLAYER-INFO-player (list (cons 'raw CCREQ-PLAYER-INFO-player) (cons 'formatted (number->string CCREQ-PLAYER-INFO-player))))
        (cons 'CCREQ-CONNECT-game (list (cons 'raw CCREQ-CONNECT-game) (cons 'formatted (utf8->string CCREQ-CONNECT-game))))
        (cons 'CCREQ-CONNECT-version (list (cons 'raw CCREQ-CONNECT-version) (cons 'formatted (number->string CCREQ-CONNECT-version))))
        (cons 'CCREQ-SERVER-INFO-game (list (cons 'raw CCREQ-SERVER-INFO-game) (cons 'formatted (utf8->string CCREQ-SERVER-INFO-game))))
        (cons 'CCREP-SERVER-INFO-address (list (cons 'raw CCREP-SERVER-INFO-address) (cons 'formatted (utf8->string CCREP-SERVER-INFO-address))))
        (cons 'CCREP-SERVER-INFO-server (list (cons 'raw CCREP-SERVER-INFO-server) (cons 'formatted (utf8->string CCREP-SERVER-INFO-server))))
        (cons 'CCREP-SERVER-INFO-map (list (cons 'raw CCREP-SERVER-INFO-map) (cons 'formatted (utf8->string CCREP-SERVER-INFO-map))))
        (cons 'CCREP-SERVER-INFO-num-player (list (cons 'raw CCREP-SERVER-INFO-num-player) (cons 'formatted (number->string CCREP-SERVER-INFO-num-player))))
        (cons 'CCREP-RULE-INFO-rule (list (cons 'raw CCREP-RULE-INFO-rule) (cons 'formatted (utf8->string CCREP-RULE-INFO-rule))))
        (cons 'CCREP-RULE-INFO-value (list (cons 'raw CCREP-RULE-INFO-value) (cons 'formatted (utf8->string CCREP-RULE-INFO-value))))
        (cons 'CCREP-SERVER-INFO-max-player (list (cons 'raw CCREP-SERVER-INFO-max-player) (cons 'formatted (number->string CCREP-SERVER-INFO-max-player))))
        (cons 'CCREP-PLAYER-INFO-name (list (cons 'raw CCREP-PLAYER-INFO-name) (cons 'formatted (utf8->string CCREP-PLAYER-INFO-name))))
        (cons 'CCREP-PLAYER-INFO-colors (list (cons 'raw CCREP-PLAYER-INFO-colors) (cons 'formatted (fmt-hex CCREP-PLAYER-INFO-colors))))
        (cons 'header-length (list (cons 'raw header-length) (cons 'formatted (number->string header-length))))
        (cons 'CCREQ-SERVER-INFO-version (list (cons 'raw CCREQ-SERVER-INFO-version) (cons 'formatted (number->string CCREQ-SERVER-INFO-version))))
        (cons 'header-sequence (list (cons 'raw header-sequence) (cons 'formatted (fmt-hex header-sequence))))
        (cons 'CCREP-PLAYER-INFO-frags (list (cons 'raw CCREP-PLAYER-INFO-frags) (cons 'formatted (number->string CCREP-PLAYER-INFO-frags))))
        (cons 'CCREP-PLAYER-INFO-connect-time (list (cons 'raw CCREP-PLAYER-INFO-connect-time) (cons 'formatted (number->string CCREP-PLAYER-INFO-connect-time))))
        (cons 'CCREP-PLAYER-INFO-address (list (cons 'raw CCREP-PLAYER-INFO-address) (cons 'formatted (utf8->string CCREP-PLAYER-INFO-address))))
        )))

    (catch (e)
      (err (str "QUAKE parse error: " e)))))

;; dissect-quake: parse QUAKE from bytevector
;; Returns (ok fields-alist) or (err message)