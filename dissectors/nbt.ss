;; packet-nbt.c
;; Routines for NetBIOS-over-TCP packet disassembly
;; Guy Harris <guy@alum.mit.edu>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nbt.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nbt.c

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
(def (dissect-nbt buffer)
  "NetBIOS Name Service"
  (try
    (let* (
           (continuation-data (unwrap (slice buffer 0 1)))
           (name (unwrap (slice buffer 0 1)))
           (transaction-id (unwrap (read-u16be buffer 0)))
           (count-questions (unwrap (read-u16be buffer 0)))
           (count-answers (unwrap (read-u16be buffer 0)))
           (count-auth-rr (unwrap (read-u16be buffer 0)))
           (count-add-rr (unwrap (read-u16be buffer 0)))
           (datagram-id (unwrap (read-u16be buffer 0)))
           (src-ip (unwrap (read-u32be buffer 0)))
           (src-port (unwrap (read-u16be buffer 0)))
           (cifs-length (unwrap (read-u24be buffer 1)))
           (ttl (unwrap (read-u32be buffer 4)))
           (flags-e (extract-bits flags 0x0 0))
           (length (unwrap (read-u24be buffer 4)))
           (retarget-ip-address (unwrap (read-u32be buffer 7)))
           (data-length (unwrap (read-u16be buffer 8)))
           (retarget-port (unwrap (read-u16be buffer 11)))
           (flags (unwrap (read-u16be buffer 14)))
           (flags-response (extract-bits flags 0x0 0))
           (flags-authoritative (extract-bits flags 0x0 0))
           (flags-truncated (extract-bits flags 0x0 0))
           (flags-recdesired (extract-bits flags 0x0 0))
           (flags-recavail (extract-bits flags 0x0 0))
           (flags-broadcast (extract-bits flags 0x0 0))
           (nb-flags (unwrap (read-u16be buffer 14)))
           (name-flags (unwrap (read-u16be buffer 14)))
           (fragment (extract-bits name-flags 0x1 0))
           (first (extract-bits name-flags 0x2 1))
           )

      (ok (list
        (cons 'continuation-data (list (cons 'raw continuation-data) (cons 'formatted (fmt-bytes continuation-data))))
        (cons 'name (list (cons 'raw name) (cons 'formatted (utf8->string name))))
        (cons 'transaction-id (list (cons 'raw transaction-id) (cons 'formatted (fmt-hex transaction-id))))
        (cons 'count-questions (list (cons 'raw count-questions) (cons 'formatted (number->string count-questions))))
        (cons 'count-answers (list (cons 'raw count-answers) (cons 'formatted (number->string count-answers))))
        (cons 'count-auth-rr (list (cons 'raw count-auth-rr) (cons 'formatted (number->string count-auth-rr))))
        (cons 'count-add-rr (list (cons 'raw count-add-rr) (cons 'formatted (number->string count-add-rr))))
        (cons 'datagram-id (list (cons 'raw datagram-id) (cons 'formatted (fmt-hex datagram-id))))
        (cons 'src-ip (list (cons 'raw src-ip) (cons 'formatted (fmt-ipv4 src-ip))))
        (cons 'src-port (list (cons 'raw src-port) (cons 'formatted (number->string src-port))))
        (cons 'cifs-length (list (cons 'raw cifs-length) (cons 'formatted (number->string cifs-length))))
        (cons 'ttl (list (cons 'raw ttl) (cons 'formatted (number->string ttl))))
        (cons 'flags-e (list (cons 'raw flags-e) (cons 'formatted (if (= flags-e 0) "Add 0 to length" "Add 65536 to length"))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'retarget-ip-address (list (cons 'raw retarget-ip-address) (cons 'formatted (fmt-ipv4 retarget-ip-address))))
        (cons 'data-length (list (cons 'raw data-length) (cons 'formatted (number->string data-length))))
        (cons 'retarget-port (list (cons 'raw retarget-port) (cons 'formatted (number->string retarget-port))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flags-response (list (cons 'raw flags-response) (cons 'formatted (if (= flags-response 0) "Message is a query" "Message is a response"))))
        (cons 'flags-authoritative (list (cons 'raw flags-authoritative) (cons 'formatted (if (= flags-authoritative 0) "Server is not an authority for domain" "Server is an authority for domain"))))
        (cons 'flags-truncated (list (cons 'raw flags-truncated) (cons 'formatted (if (= flags-truncated 0) "Message is not truncated" "Message is truncated"))))
        (cons 'flags-recdesired (list (cons 'raw flags-recdesired) (cons 'formatted (if (= flags-recdesired 0) "Don't do query recursively" "Do query recursively"))))
        (cons 'flags-recavail (list (cons 'raw flags-recavail) (cons 'formatted (if (= flags-recavail 0) "Server can't do recursive queries" "Server can do recursive queries"))))
        (cons 'flags-broadcast (list (cons 'raw flags-broadcast) (cons 'formatted (if (= flags-broadcast 0) "Not a broadcast packet" "Broadcast packet"))))
        (cons 'nb-flags (list (cons 'raw nb-flags) (cons 'formatted (fmt-hex nb-flags))))
        (cons 'name-flags (list (cons 'raw name-flags) (cons 'formatted (fmt-hex name-flags))))
        (cons 'fragment (list (cons 'raw fragment) (cons 'formatted (if (= fragment 0) "Not set" "Set"))))
        (cons 'first (list (cons 'raw first) (cons 'formatted (if (= first 0) "Not set" "Set"))))
        )))

    (catch (e)
      (err (str "NBT parse error: " e)))))

;; dissect-nbt: parse NBT from bytevector
;; Returns (ok fields-alist) or (err message)