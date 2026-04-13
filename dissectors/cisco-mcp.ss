;; packet-cisco-mcp.c
;; Routines for the disassembly of Cisco's MCP (MisCabling Protocol)
;;
;; Copyright 2019 Joerg Mayer (see AUTHORS file)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/cisco-mcp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cisco_mcp.c

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
(def (dissect-cisco-mcp buffer)
  "Miscabling Protocol"
  (try
    (let* (
           (tlv-length (unwrap (read-u16be buffer 1)))
           (fabric-id (unwrap (read-u32be buffer 2)))
           (node-id (unwrap (read-u32be buffer 2)))
           (vpc-domain (unwrap (read-u32be buffer 2)))
           (vpc-id (unwrap (read-u32be buffer 2)))
           (vpc-vtep (unwrap (read-u32be buffer 2)))
           (port-id (unwrap (read-u32be buffer 2)))
           (strictmode (unwrap (read-u32be buffer 2)))
           (digest (unwrap (slice buffer 2 1)))
           (unknown (unwrap (slice buffer 2 1)))
           )

      (ok (list
        (cons 'tlv-length (list (cons 'raw tlv-length) (cons 'formatted (number->string tlv-length))))
        (cons 'fabric-id (list (cons 'raw fabric-id) (cons 'formatted (number->string fabric-id))))
        (cons 'node-id (list (cons 'raw node-id) (cons 'formatted (number->string node-id))))
        (cons 'vpc-domain (list (cons 'raw vpc-domain) (cons 'formatted (number->string vpc-domain))))
        (cons 'vpc-id (list (cons 'raw vpc-id) (cons 'formatted (number->string vpc-id))))
        (cons 'vpc-vtep (list (cons 'raw vpc-vtep) (cons 'formatted (fmt-ipv4 vpc-vtep))))
        (cons 'port-id (list (cons 'raw port-id) (cons 'formatted (fmt-hex port-id))))
        (cons 'strictmode (list (cons 'raw strictmode) (cons 'formatted (number->string strictmode))))
        (cons 'digest (list (cons 'raw digest) (cons 'formatted (fmt-bytes digest))))
        (cons 'unknown (list (cons 'raw unknown) (cons 'formatted (fmt-bytes unknown))))
        )))

    (catch (e)
      (err (str "CISCO-MCP parse error: " e)))))

;; dissect-cisco-mcp: parse CISCO-MCP from bytevector
;; Returns (ok fields-alist) or (err message)