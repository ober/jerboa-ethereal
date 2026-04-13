;; packet-agentx.c
;; Routines for Agent Extensibility (AgentX) Protocol disassembly
;; RFC 2257
;;
;; Copyright (c) 2005 by Oleg Terletsky <oleg.terletsky@comverse.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/agentx.ss
;; Auto-generated from wireshark/epan/dissectors/packet-agentx.c
;; RFC 2257

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
(def (dissect-agentx buffer)
  "AgentX"
  (try
    (let* (
           (hf-version (unwrap (read-u8 buffer 0)))
           (hf-ostring (unwrap (slice buffer 0 1)))
           (sub (unwrap (read-u8 buffer 0)))
           (prefix (unwrap (read-u8 buffer 0)))
           (include (unwrap (read-u8 buffer 0)))
           (hf-val64 (unwrap (read-u64be buffer 0)))
           (hf-val32 (unwrap (read-u32be buffer 0)))
           (uptime (unwrap (read-u32be buffer 0)))
           (index (unwrap (read-u16be buffer 0)))
           (hf-flags (unwrap (read-u8 buffer 2)))
           (register (extract-bits hf-flags 0x0 0))
           (newindex (extract-bits hf-flags 0x0 0))
           (anyindex (extract-bits hf-flags 0x0 0))
           (context (extract-bits hf-flags 0x0 0))
           (byteorder (extract-bits hf-flags 0x0 0))
           (nrepeat (unwrap (read-u16be buffer 8)))
           (mrepeat (unwrap (read-u16be buffer 8)))
           (id (unwrap (read-u32be buffer 12)))
           (len (unwrap (read-u32be buffer 16)))
           (timeout (unwrap (read-u8 buffer 28)))
           (prio (unwrap (read-u8 buffer 28)))
           (rsid (unwrap (read-u8 buffer 28)))
           (ubound (unwrap (read-u32be buffer 32)))
           )

      (ok (list
        (cons 'hf-version (list (cons 'raw hf-version) (cons 'formatted (number->string hf-version))))
        (cons 'hf-ostring (list (cons 'raw hf-ostring) (cons 'formatted (utf8->string hf-ostring))))
        (cons 'sub (list (cons 'raw sub) (cons 'formatted (number->string sub))))
        (cons 'prefix (list (cons 'raw prefix) (cons 'formatted (number->string prefix))))
        (cons 'include (list (cons 'raw include) (cons 'formatted (if (= include 0) "False" "True"))))
        (cons 'hf-val64 (list (cons 'raw hf-val64) (cons 'formatted (number->string hf-val64))))
        (cons 'hf-val32 (list (cons 'raw hf-val32) (cons 'formatted (number->string hf-val32))))
        (cons 'uptime (list (cons 'raw uptime) (cons 'formatted (number->string uptime))))
        (cons 'index (list (cons 'raw index) (cons 'formatted (number->string index))))
        (cons 'hf-flags (list (cons 'raw hf-flags) (cons 'formatted (number->string hf-flags))))
        (cons 'register (list (cons 'raw register) (cons 'formatted (if (= register 0) "Not set" "Set"))))
        (cons 'newindex (list (cons 'raw newindex) (cons 'formatted (if (= newindex 0) "Not set" "Set"))))
        (cons 'anyindex (list (cons 'raw anyindex) (cons 'formatted (if (= anyindex 0) "Not set" "Set"))))
        (cons 'context (list (cons 'raw context) (cons 'formatted (if (= context 0) "None" "Provided"))))
        (cons 'byteorder (list (cons 'raw byteorder) (cons 'formatted (if (= byteorder 0) "LSB" "MSB (network order)"))))
        (cons 'nrepeat (list (cons 'raw nrepeat) (cons 'formatted (number->string nrepeat))))
        (cons 'mrepeat (list (cons 'raw mrepeat) (cons 'formatted (number->string mrepeat))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'timeout (list (cons 'raw timeout) (cons 'formatted (number->string timeout))))
        (cons 'prio (list (cons 'raw prio) (cons 'formatted (number->string prio))))
        (cons 'rsid (list (cons 'raw rsid) (cons 'formatted (number->string rsid))))
        (cons 'ubound (list (cons 'raw ubound) (cons 'formatted (number->string ubound))))
        )))

    (catch (e)
      (err (str "AGENTX parse error: " e)))))

;; dissect-agentx: parse AGENTX from bytevector
;; Returns (ok fields-alist) or (err message)