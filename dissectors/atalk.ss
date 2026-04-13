;; packet-atalk.c
;; Routines for AppleTalk packet disassembly: LLAP, DDP, NBP, ATP, ASP,
;; RTMP, PAP.
;;
;; Simon Wilkinson <sxw@dcs.ed.ac.uk>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/atalk.ss
;; Auto-generated from wireshark/epan/dissectors/packet-atalk.c

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
(def (dissect-atalk buffer)
  "LocalTalk Link Access Protocol"
  (try
    (let* (
           (hopcount (unwrap (read-u16be buffer 0)))
           (len (unwrap (read-u16be buffer 0)))
           (net (unwrap (read-u16be buffer 0)))
           (node-len (unwrap (read-u8 buffer 0)))
           (node (unwrap (read-u8 buffer 0)))
           (info (unwrap (read-u8 buffer 0)))
           (ctrlinfo (unwrap (read-u8 buffer 0)))
           (xo (unwrap (read-u8 buffer 0)))
           (eom (unwrap (read-u8 buffer 0)))
           (sts (unwrap (read-u8 buffer 0)))
           (bitmap (unwrap (read-u8 buffer 0)))
           (tid (unwrap (read-u16be buffer 0)))
           (user-bytes (unwrap (read-u32be buffer 0)))
           (connid (unwrap (read-u8 buffer 0)))
           (waittime (unwrap (read-u16be buffer 0)))
           (start-index (unwrap (read-u16be buffer 0)))
           (last-flag (unwrap (read-u8 buffer 0)))
           (count (unwrap (read-u16be buffer 0)))
           (dst-socket (unwrap (read-u8 buffer 2)))
           (node-net (unwrap (read-u16be buffer 2)))
           (quantum (unwrap (read-u8 buffer 2)))
           (result (unwrap (read-u16be buffer 2)))
           (src-socket (unwrap (read-u8 buffer 3)))
           (dst-net (unwrap (read-u16be buffer 4)))
           (src (unwrap (slice buffer 4 3)))
           (node-node (unwrap (read-u8 buffer 4)))
           (node-port (unwrap (read-u8 buffer 4)))
           (node-enum (unwrap (read-u8 buffer 4)))
           (src-net (unwrap (read-u16be buffer 6)))
           (dst (unwrap (slice buffer 6 3)))
           (tuple-range-start (unwrap (read-u16be buffer 6)))
           (tuple-range-end (unwrap (read-u16be buffer 6)))
           (version (unwrap (read-u8 buffer 6)))
           (eof (unwrap (read-u8 buffer 6)))
           (attn-code (unwrap (read-u16be buffer 6)))
           (network-count (unwrap (read-u8 buffer 6)))
           (network (unwrap (read-u16be buffer 6)))
           (dst-node (unwrap (read-u8 buffer 8)))
           (src-node (unwrap (read-u8 buffer 9)))
           (seq (unwrap (read-u16be buffer 10)))
           (tuple-net (unwrap (read-u16be buffer 12)))
           (tuple-dist (unwrap (read-u16be buffer 12)))
           (size (unwrap (read-u16be buffer 12)))
           (flags (unwrap (read-u8 buffer 12)))
           (flags-zone-invalid (extract-bits flags 0x80 7))
           (flags-use-broadcast (extract-bits flags 0x40 6))
           (flags-only-one-zone (extract-bits flags 0x20 5))
           (network-start (unwrap (read-u16be buffer 12)))
           (network-end (unwrap (read-u16be buffer 14)))
           (multicast-length (unwrap (read-u8 buffer 16)))
           (multicast-address (unwrap (slice buffer 16 1)))
           (socket (unwrap (read-u8 buffer 17)))
           (session-id (unwrap (read-u8 buffer 17)))
           (init-error (unwrap (read-u16be buffer 17)))
           (zero-value (unwrap (slice buffer 29 4)))
           )

      (ok (list
        (cons 'hopcount (list (cons 'raw hopcount) (cons 'formatted (number->string hopcount))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'net (list (cons 'raw net) (cons 'formatted (number->string net))))
        (cons 'node-len (list (cons 'raw node-len) (cons 'formatted (number->string node-len))))
        (cons 'node (list (cons 'raw node) (cons 'formatted (number->string node))))
        (cons 'info (list (cons 'raw info) (cons 'formatted (fmt-hex info))))
        (cons 'ctrlinfo (list (cons 'raw ctrlinfo) (cons 'formatted (fmt-hex ctrlinfo))))
        (cons 'xo (list (cons 'raw xo) (cons 'formatted (number->string xo))))
        (cons 'eom (list (cons 'raw eom) (cons 'formatted (number->string eom))))
        (cons 'sts (list (cons 'raw sts) (cons 'formatted (number->string sts))))
        (cons 'bitmap (list (cons 'raw bitmap) (cons 'formatted (fmt-hex bitmap))))
        (cons 'tid (list (cons 'raw tid) (cons 'formatted (number->string tid))))
        (cons 'user-bytes (list (cons 'raw user-bytes) (cons 'formatted (fmt-hex user-bytes))))
        (cons 'connid (list (cons 'raw connid) (cons 'formatted (number->string connid))))
        (cons 'waittime (list (cons 'raw waittime) (cons 'formatted (number->string waittime))))
        (cons 'start-index (list (cons 'raw start-index) (cons 'formatted (number->string start-index))))
        (cons 'last-flag (list (cons 'raw last-flag) (cons 'formatted (number->string last-flag))))
        (cons 'count (list (cons 'raw count) (cons 'formatted (number->string count))))
        (cons 'dst-socket (list (cons 'raw dst-socket) (cons 'formatted (number->string dst-socket))))
        (cons 'node-net (list (cons 'raw node-net) (cons 'formatted (number->string node-net))))
        (cons 'quantum (list (cons 'raw quantum) (cons 'formatted (number->string quantum))))
        (cons 'result (list (cons 'raw result) (cons 'formatted (number->string result))))
        (cons 'src-socket (list (cons 'raw src-socket) (cons 'formatted (number->string src-socket))))
        (cons 'dst-net (list (cons 'raw dst-net) (cons 'formatted (number->string dst-net))))
        (cons 'src (list (cons 'raw src) (cons 'formatted (utf8->string src))))
        (cons 'node-node (list (cons 'raw node-node) (cons 'formatted (number->string node-node))))
        (cons 'node-port (list (cons 'raw node-port) (cons 'formatted (number->string node-port))))
        (cons 'node-enum (list (cons 'raw node-enum) (cons 'formatted (number->string node-enum))))
        (cons 'src-net (list (cons 'raw src-net) (cons 'formatted (number->string src-net))))
        (cons 'dst (list (cons 'raw dst) (cons 'formatted (utf8->string dst))))
        (cons 'tuple-range-start (list (cons 'raw tuple-range-start) (cons 'formatted (number->string tuple-range-start))))
        (cons 'tuple-range-end (list (cons 'raw tuple-range-end) (cons 'formatted (number->string tuple-range-end))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (fmt-hex version))))
        (cons 'eof (list (cons 'raw eof) (cons 'formatted (number->string eof))))
        (cons 'attn-code (list (cons 'raw attn-code) (cons 'formatted (fmt-hex attn-code))))
        (cons 'network-count (list (cons 'raw network-count) (cons 'formatted (number->string network-count))))
        (cons 'network (list (cons 'raw network) (cons 'formatted (number->string network))))
        (cons 'dst-node (list (cons 'raw dst-node) (cons 'formatted (number->string dst-node))))
        (cons 'src-node (list (cons 'raw src-node) (cons 'formatted (number->string src-node))))
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (number->string seq))))
        (cons 'tuple-net (list (cons 'raw tuple-net) (cons 'formatted (number->string tuple-net))))
        (cons 'tuple-dist (list (cons 'raw tuple-dist) (cons 'formatted (number->string tuple-dist))))
        (cons 'size (list (cons 'raw size) (cons 'formatted (number->string size))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flags-zone-invalid (list (cons 'raw flags-zone-invalid) (cons 'formatted (if (= flags-zone-invalid 0) "Not set" "Set"))))
        (cons 'flags-use-broadcast (list (cons 'raw flags-use-broadcast) (cons 'formatted (if (= flags-use-broadcast 0) "Not set" "Set"))))
        (cons 'flags-only-one-zone (list (cons 'raw flags-only-one-zone) (cons 'formatted (if (= flags-only-one-zone 0) "Not set" "Set"))))
        (cons 'network-start (list (cons 'raw network-start) (cons 'formatted (number->string network-start))))
        (cons 'network-end (list (cons 'raw network-end) (cons 'formatted (number->string network-end))))
        (cons 'multicast-length (list (cons 'raw multicast-length) (cons 'formatted (number->string multicast-length))))
        (cons 'multicast-address (list (cons 'raw multicast-address) (cons 'formatted (fmt-bytes multicast-address))))
        (cons 'socket (list (cons 'raw socket) (cons 'formatted (number->string socket))))
        (cons 'session-id (list (cons 'raw session-id) (cons 'formatted (number->string session-id))))
        (cons 'init-error (list (cons 'raw init-error) (cons 'formatted (number->string init-error))))
        (cons 'zero-value (list (cons 'raw zero-value) (cons 'formatted (fmt-bytes zero-value))))
        )))

    (catch (e)
      (err (str "ATALK parse error: " e)))))

;; dissect-atalk: parse ATALK from bytevector
;; Returns (ok fields-alist) or (err message)