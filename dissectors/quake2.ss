;; packet-quake2.c
;; Routines for Quake II packet dissection
;;
;; Uwe Girlich <uwe@planetquake.com>
;; http://www.idsoftware.com/q1source/q1source.zip
;; http://www.planetquake.com/demospecs/dm2
;; http://www.dgs.monash.edu.au/~timf/bottim/
;; http://www.opt-sci.Arizona.EDU/Pandora/default.asp
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-quakeworld.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/quake2.ss
;; Auto-generated from wireshark/epan/dissectors/packet-quake2.c

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
(def (dissect-quake2 buffer)
  "Quake II Network Protocol"
  (try
    (let* (
           (game (unwrap (read-u32be buffer 0)))
           (connectionless (unwrap (read-u32be buffer 0)))
           (command (unwrap (slice buffer 0 1)))
           (userinfo (unwrap (slice buffer 0 1)))
           (connectionless-marker (unwrap (read-u32be buffer 0)))
           (game-client-command (unwrap (read-u8 buffer 0)))
           (game-server-command (unwrap (read-u8 buffer 0)))
           (game-seq1 (unwrap (read-u32be buffer 0)))
           (game-rel1 (unwrap (read-u8 buffer 0)))
           (game-client-command-move-lframe (unwrap (read-u32be buffer 1)))
           (connectionless-text (unwrap (slice buffer 4 1)))
           (game-seq2 (unwrap (read-u32be buffer 4)))
           (game-rel2 (unwrap (read-u8 buffer 4)))
           (game-qport (unwrap (read-u32be buffer 8)))
           )

      (ok (list
        (cons 'game (list (cons 'raw game) (cons 'formatted (number->string game))))
        (cons 'connectionless (list (cons 'raw connectionless) (cons 'formatted (number->string connectionless))))
        (cons 'command (list (cons 'raw command) (cons 'formatted (utf8->string command))))
        (cons 'userinfo (list (cons 'raw userinfo) (cons 'formatted (utf8->string userinfo))))
        (cons 'connectionless-marker (list (cons 'raw connectionless-marker) (cons 'formatted (fmt-hex connectionless-marker))))
        (cons 'game-client-command (list (cons 'raw game-client-command) (cons 'formatted (number->string game-client-command))))
        (cons 'game-server-command (list (cons 'raw game-server-command) (cons 'formatted (number->string game-server-command))))
        (cons 'game-seq1 (list (cons 'raw game-seq1) (cons 'formatted (number->string game-seq1))))
        (cons 'game-rel1 (list (cons 'raw game-rel1) (cons 'formatted (number->string game-rel1))))
        (cons 'game-client-command-move-lframe (list (cons 'raw game-client-command-move-lframe) (cons 'formatted (number->string game-client-command-move-lframe))))
        (cons 'connectionless-text (list (cons 'raw connectionless-text) (cons 'formatted (utf8->string connectionless-text))))
        (cons 'game-seq2 (list (cons 'raw game-seq2) (cons 'formatted (number->string game-seq2))))
        (cons 'game-rel2 (list (cons 'raw game-rel2) (cons 'formatted (number->string game-rel2))))
        (cons 'game-qport (list (cons 'raw game-qport) (cons 'formatted (number->string game-qport))))
        )))

    (catch (e)
      (err (str "QUAKE2 parse error: " e)))))

;; dissect-quake2: parse QUAKE2 from bytevector
;; Returns (ok fields-alist) or (err message)