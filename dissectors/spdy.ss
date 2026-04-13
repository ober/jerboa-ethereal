;; packet-spdy.c
;; Routines for SPDY packet disassembly
;; For now, the protocol spec can be found at
;; http://dev.chromium.org/spdy/spdy-protocol
;;
;; Copyright 2010, Google Inc.
;; Hasan Khalil <hkhalil@google.com>
;; Chris Bentzel <cbentzel@google.com>
;; Eric Shienbrood <ers@google.com>
;;
;; Copyright 2013-2014
;; Alexis La Goutte <alexis.lagoutte@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Originally based on packet-http.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/spdy.ss
;; Auto-generated from wireshark/epan/dissectors/packet-spdy.c

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
(def (dissect-spdy buffer)
  "SPDY"
  (try
    (let* (
           (flags-fin (unwrap (read-u8 buffer 0)))
           (flags-unidirectional (unwrap (read-u8 buffer 0)))
           (flags-clear-settings (unwrap (read-u8 buffer 0)))
           (data (unwrap (slice buffer 0 1)))
           (control-bit (unwrap (read-u8 buffer 0)))
           (version (unwrap (read-u16be buffer 0)))
           (streamid (unwrap (read-u32be buffer 4)))
           (priority (unwrap (read-u16be buffer 8)))
           (unused (unwrap (read-u16be buffer 8)))
           (slot (unwrap (read-u16be buffer 8)))
           (length (unwrap (read-u24be buffer 9)))
           (header-block (unwrap (slice buffer 10 1)))
           (num-settings (unwrap (read-u32be buffer 14)))
           (flags (unwrap (read-u8 buffer 18)))
           (flags-persist-value (unwrap (read-u8 buffer 18)))
           (flags-persisted (unwrap (read-u8 buffer 18)))
           (setting-value (unwrap (read-u32be buffer 22)))
           (ping-id (unwrap (read-u32be buffer 26)))
           (window-update-delta (unwrap (read-u32be buffer 34)))
           )

      (ok (list
        (cons 'flags-fin (list (cons 'raw flags-fin) (cons 'formatted (if (= flags-fin 0) "False" "True"))))
        (cons 'flags-unidirectional (list (cons 'raw flags-unidirectional) (cons 'formatted (if (= flags-unidirectional 0) "False" "True"))))
        (cons 'flags-clear-settings (list (cons 'raw flags-clear-settings) (cons 'formatted (if (= flags-clear-settings 0) "False" "True"))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'control-bit (list (cons 'raw control-bit) (cons 'formatted (if (= control-bit 0) "False" "True"))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'streamid (list (cons 'raw streamid) (cons 'formatted (number->string streamid))))
        (cons 'priority (list (cons 'raw priority) (cons 'formatted (number->string priority))))
        (cons 'unused (list (cons 'raw unused) (cons 'formatted (fmt-hex unused))))
        (cons 'slot (list (cons 'raw slot) (cons 'formatted (number->string slot))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'header-block (list (cons 'raw header-block) (cons 'formatted (fmt-bytes header-block))))
        (cons 'num-settings (list (cons 'raw num-settings) (cons 'formatted (number->string num-settings))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flags-persist-value (list (cons 'raw flags-persist-value) (cons 'formatted (if (= flags-persist-value 0) "False" "True"))))
        (cons 'flags-persisted (list (cons 'raw flags-persisted) (cons 'formatted (if (= flags-persisted 0) "False" "True"))))
        (cons 'setting-value (list (cons 'raw setting-value) (cons 'formatted (number->string setting-value))))
        (cons 'ping-id (list (cons 'raw ping-id) (cons 'formatted (number->string ping-id))))
        (cons 'window-update-delta (list (cons 'raw window-update-delta) (cons 'formatted (number->string window-update-delta))))
        )))

    (catch (e)
      (err (str "SPDY parse error: " e)))))

;; dissect-spdy: parse SPDY from bytevector
;; Returns (ok fields-alist) or (err message)