;; packet-nt-tpcp.c
;; Routines for Transparent Proxy Cache Protocol packet disassembly
;; (c) Copyright Giles Scott <giles.scott1 [AT] btinternet.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nt-tpcp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nt_tpcp.c

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
(def (dissect-nt-tpcp buffer)
  "Alteon - Transparent Proxy Cache Protocol"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (flags (unwrap (read-u16be buffer 2)))
           (flags-tcp (extract-bits flags 0x0 0))
           (flags-redir (extract-bits flags 0x0 0))
           (flags-xon (extract-bits flags 0x0 0))
           (flags-xoff (extract-bits flags 0x0 0))
           (id (unwrap (read-u16be buffer 4)))
           (cport (unwrap (read-u16be buffer 6)))
           (caddr (unwrap (read-u32be buffer 8)))
           (saddr (unwrap (read-u32be buffer 12)))
           (vaddr (unwrap (read-u32be buffer 16)))
           (rasaddr (unwrap (read-u32be buffer 20)))
           (signature (unwrap (read-u32be buffer 24)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flags-tcp (list (cons 'raw flags-tcp) (cons 'formatted (if (= flags-tcp 0) "Not set" "Set"))))
        (cons 'flags-redir (list (cons 'raw flags-redir) (cons 'formatted (if (= flags-redir 0) "Not set" "Set"))))
        (cons 'flags-xon (list (cons 'raw flags-xon) (cons 'formatted (if (= flags-xon 0) "Not set" "Set"))))
        (cons 'flags-xoff (list (cons 'raw flags-xoff) (cons 'formatted (if (= flags-xoff 0) "Not set" "Set"))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'cport (list (cons 'raw cport) (cons 'formatted (number->string cport))))
        (cons 'caddr (list (cons 'raw caddr) (cons 'formatted (fmt-ipv4 caddr))))
        (cons 'saddr (list (cons 'raw saddr) (cons 'formatted (fmt-ipv4 saddr))))
        (cons 'vaddr (list (cons 'raw vaddr) (cons 'formatted (fmt-ipv4 vaddr))))
        (cons 'rasaddr (list (cons 'raw rasaddr) (cons 'formatted (fmt-ipv4 rasaddr))))
        (cons 'signature (list (cons 'raw signature) (cons 'formatted (number->string signature))))
        )))

    (catch (e)
      (err (str "NT-TPCP parse error: " e)))))

;; dissect-nt-tpcp: parse NT-TPCP from bytevector
;; Returns (ok fields-alist) or (err message)