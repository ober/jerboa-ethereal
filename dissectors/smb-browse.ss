;; packet-smb-browse.c
;; Routines for SMB Browser packet dissection
;; Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-pop.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/smb-browse.ss
;; Auto-generated from wireshark/epan/dissectors/packet-smb_browse.c

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
(def (dissect-smb-browse buffer)
  "Microsoft Windows Browser Protocol"
  (try
    (let* (
           (os (unwrap (read-u8 buffer 0)))
           (desire (unwrap (read-u8 buffer 0)))
           (reset-demote (extract-bits desire 0x1 0))
           (reset-flush (extract-bits desire 0x2 1))
           (reset-stop (extract-bits desire 0x4 2))
           (criteria (unwrap (read-u32be buffer 0)))
           (hf-periodicity (unwrap (read-u32be buffer 4)))
           (field (unwrap (read-u32be buffer 8)))
           (major (unwrap (read-u8 buffer 12)))
           (minor (unwrap (read-u8 buffer 13)))
           (const (unwrap (read-u16be buffer 14)))
           (flags (unwrap (read-u8 buffer 16)))
           (computer-name (unwrap (slice buffer 17 1)))
           (version (unwrap (read-u8 buffer 17)))
           (uptime (unwrap (read-u32be buffer 22)))
           (name (unwrap (slice buffer 30 1)))
           (count (unwrap (read-u8 buffer 31)))
           (token (unwrap (read-u32be buffer 32)))
           (server (unwrap (slice buffer 36 1)))
           (server-name (unwrap (slice buffer 36 1)))
           (to-promote (unwrap (slice buffer 36 1)))
           )

      (ok (list
        (cons 'os (list (cons 'raw os) (cons 'formatted (fmt-hex os))))
        (cons 'desire (list (cons 'raw desire) (cons 'formatted (fmt-hex desire))))
        (cons 'reset-demote (list (cons 'raw reset-demote) (cons 'formatted (if (= reset-demote 0) "Not set" "Set"))))
        (cons 'reset-flush (list (cons 'raw reset-flush) (cons 'formatted (if (= reset-flush 0) "Not set" "Set"))))
        (cons 'reset-stop (list (cons 'raw reset-stop) (cons 'formatted (if (= reset-stop 0) "Not set" "Set"))))
        (cons 'criteria (list (cons 'raw criteria) (cons 'formatted (fmt-hex criteria))))
        (cons 'hf-periodicity (list (cons 'raw hf-periodicity) (cons 'formatted (number->string hf-periodicity))))
        (cons 'field (list (cons 'raw field) (cons 'formatted (fmt-hex field))))
        (cons 'major (list (cons 'raw major) (cons 'formatted (number->string major))))
        (cons 'minor (list (cons 'raw minor) (cons 'formatted (number->string minor))))
        (cons 'const (list (cons 'raw const) (cons 'formatted (fmt-hex const))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'computer-name (list (cons 'raw computer-name) (cons 'formatted (utf8->string computer-name))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'uptime (list (cons 'raw uptime) (cons 'formatted (number->string uptime))))
        (cons 'name (list (cons 'raw name) (cons 'formatted (utf8->string name))))
        (cons 'count (list (cons 'raw count) (cons 'formatted (number->string count))))
        (cons 'token (list (cons 'raw token) (cons 'formatted (number->string token))))
        (cons 'server (list (cons 'raw server) (cons 'formatted (utf8->string server))))
        (cons 'server-name (list (cons 'raw server-name) (cons 'formatted (utf8->string server-name))))
        (cons 'to-promote (list (cons 'raw to-promote) (cons 'formatted (utf8->string to-promote))))
        )))

    (catch (e)
      (err (str "SMB-BROWSE parse error: " e)))))

;; dissect-smb-browse: parse SMB-BROWSE from bytevector
;; Returns (ok fields-alist) or (err message)