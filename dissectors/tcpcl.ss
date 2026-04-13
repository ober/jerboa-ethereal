;; packet-tcpcl.c
;; References:
;; RFC 7242: https://tools.ietf.org/html/rfc7242
;; RFC 9174: https://www.rfc-editor.org/rfc/rfc9174.html
;;
;; TCPCLv4 portions copyright 2019-2021, Brian Sipos <brian.sipos@gmail.com>
;; Copyright 2006-2007 The MITRE Corporation.
;; All Rights Reserved.
;; Approved for Public Release; Distribution Unlimited.
;; Tracking Number 07-0090.
;;
;; The US Government will not be charged any license fee and/or royalties
;; related to this software. Neither name of The MITRE Corporation; nor the
;; names of its contributors may be used to endorse or promote products
;; derived from this software without specific prior written permission.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/tcpcl.ss
;; Auto-generated from wireshark/epan/dissectors/packet-tcpcl.c
;; RFC 7242

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
(def (dissect-tcpcl buffer)
  "DTN TCP Convergence Layer Protocol"
  (try
    (let* (
           (negotiate-use-tls (unwrap (read-u8 buffer 0)))
           (related (unwrap (read-u32be buffer 0)))
           (sess-init-related (unwrap (read-u32be buffer 0)))
           (sess-term-related (unwrap (read-u32be buffer 0)))
           (xfer-refuse-related-seg (unwrap (read-u32be buffer 0)))
           (xfer-ack-related-start (unwrap (read-u32be buffer 0)))
           (xfer-segment-related-start (unwrap (read-u32be buffer 0)))
           (xfer-segment-related-ack (unwrap (read-u32be buffer 0)))
           (xfer-total-len (unwrap (read-u64be buffer 0)))
           (data-procflags (unwrap (read-u8 buffer 0)))
           (data-procflags-start (extract-bits data-procflags 0x0 0))
           (data-procflags-end (extract-bits data-procflags 0x0 0))
           (magic (unwrap (slice buffer 0 1)))
           (version (unwrap (read-u8 buffer 0)))
           (data-segment-length (unwrap (read-u64be buffer 1)))
           (data-segment-data (unwrap (slice buffer 1 1)))
           (chdr-flags-ack-req (extract-bits chdr-flags 0x0 0))
           (chdr-flags-frag-enable (extract-bits chdr-flags 0x0 0))
           (chdr-flags-nak (extract-bits chdr-flags 0x0 0))
           (ack-length (unwrap (read-u64be buffer 2)))
           (shutdown-flags (unwrap (read-u8 buffer 3)))
           (shutdown-flags-reason (unwrap (read-u8 buffer 3)))
           (shutdown-flags-delay (unwrap (read-u8 buffer 3)))
           (chdr-local-eid-length (unwrap (read-u64be buffer 3)))
           (chdr-local-eid (unwrap (slice buffer 3 1)))
           (chdr-flags (unwrap (read-u8 buffer 3)))
           (chdr-flags-cantls (extract-bits chdr-flags 0x0 0))
           (shutdown-reason (unwrap (read-u8 buffer 4)))
           (shutdown-delay (unwrap (read-u16be buffer 5)))
           (sess-init-nodeid-data (unwrap (slice buffer 21 1)))
           (sessext-tree (unwrap (slice buffer 25 1)))
           (sess-term-flags (unwrap (read-u8 buffer 25)))
           (sess-term-flags-reply (extract-bits sess-term-flags 0x0 0))
           (xferext-tree (unwrap (slice buffer 40 1)))
           (xfer-segment-data (unwrap (slice buffer 48 1)))
           (xfer-flags (unwrap (read-u8 buffer 48)))
           (xfer-flags-start (extract-bits xfer-flags 0x0 0))
           (xfer-flags-end (extract-bits xfer-flags 0x0 0))
           (xfer-id (unwrap (read-u64be buffer 66)))
           (msg-reject-head (unwrap (read-u8 buffer 75)))
           )

      (ok (list
        (cons 'negotiate-use-tls (list (cons 'raw negotiate-use-tls) (cons 'formatted (number->string negotiate-use-tls))))
        (cons 'related (list (cons 'raw related) (cons 'formatted (number->string related))))
        (cons 'sess-init-related (list (cons 'raw sess-init-related) (cons 'formatted (number->string sess-init-related))))
        (cons 'sess-term-related (list (cons 'raw sess-term-related) (cons 'formatted (number->string sess-term-related))))
        (cons 'xfer-refuse-related-seg (list (cons 'raw xfer-refuse-related-seg) (cons 'formatted (number->string xfer-refuse-related-seg))))
        (cons 'xfer-ack-related-start (list (cons 'raw xfer-ack-related-start) (cons 'formatted (number->string xfer-ack-related-start))))
        (cons 'xfer-segment-related-start (list (cons 'raw xfer-segment-related-start) (cons 'formatted (number->string xfer-segment-related-start))))
        (cons 'xfer-segment-related-ack (list (cons 'raw xfer-segment-related-ack) (cons 'formatted (number->string xfer-segment-related-ack))))
        (cons 'xfer-total-len (list (cons 'raw xfer-total-len) (cons 'formatted (number->string xfer-total-len))))
        (cons 'data-procflags (list (cons 'raw data-procflags) (cons 'formatted (fmt-hex data-procflags))))
        (cons 'data-procflags-start (list (cons 'raw data-procflags-start) (cons 'formatted (if (= data-procflags-start 0) "Not set" "Set"))))
        (cons 'data-procflags-end (list (cons 'raw data-procflags-end) (cons 'formatted (if (= data-procflags-end 0) "Not set" "Set"))))
        (cons 'magic (list (cons 'raw magic) (cons 'formatted (fmt-bytes magic))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'data-segment-length (list (cons 'raw data-segment-length) (cons 'formatted (number->string data-segment-length))))
        (cons 'data-segment-data (list (cons 'raw data-segment-data) (cons 'formatted (fmt-bytes data-segment-data))))
        (cons 'chdr-flags-ack-req (list (cons 'raw chdr-flags-ack-req) (cons 'formatted (if (= chdr-flags-ack-req 0) "Not set" "Set"))))
        (cons 'chdr-flags-frag-enable (list (cons 'raw chdr-flags-frag-enable) (cons 'formatted (if (= chdr-flags-frag-enable 0) "Not set" "Set"))))
        (cons 'chdr-flags-nak (list (cons 'raw chdr-flags-nak) (cons 'formatted (if (= chdr-flags-nak 0) "Not set" "Set"))))
        (cons 'ack-length (list (cons 'raw ack-length) (cons 'formatted (number->string ack-length))))
        (cons 'shutdown-flags (list (cons 'raw shutdown-flags) (cons 'formatted (fmt-hex shutdown-flags))))
        (cons 'shutdown-flags-reason (list (cons 'raw shutdown-flags-reason) (cons 'formatted (if (= shutdown-flags-reason 0) "False" "True"))))
        (cons 'shutdown-flags-delay (list (cons 'raw shutdown-flags-delay) (cons 'formatted (if (= shutdown-flags-delay 0) "False" "True"))))
        (cons 'chdr-local-eid-length (list (cons 'raw chdr-local-eid-length) (cons 'formatted (number->string chdr-local-eid-length))))
        (cons 'chdr-local-eid (list (cons 'raw chdr-local-eid) (cons 'formatted (utf8->string chdr-local-eid))))
        (cons 'chdr-flags (list (cons 'raw chdr-flags) (cons 'formatted (fmt-hex chdr-flags))))
        (cons 'chdr-flags-cantls (list (cons 'raw chdr-flags-cantls) (cons 'formatted (if (= chdr-flags-cantls 0) "Not set" "Set"))))
        (cons 'shutdown-reason (list (cons 'raw shutdown-reason) (cons 'formatted (number->string shutdown-reason))))
        (cons 'shutdown-delay (list (cons 'raw shutdown-delay) (cons 'formatted (number->string shutdown-delay))))
        (cons 'sess-init-nodeid-data (list (cons 'raw sess-init-nodeid-data) (cons 'formatted (utf8->string sess-init-nodeid-data))))
        (cons 'sessext-tree (list (cons 'raw sessext-tree) (cons 'formatted (fmt-bytes sessext-tree))))
        (cons 'sess-term-flags (list (cons 'raw sess-term-flags) (cons 'formatted (fmt-hex sess-term-flags))))
        (cons 'sess-term-flags-reply (list (cons 'raw sess-term-flags-reply) (cons 'formatted (if (= sess-term-flags-reply 0) "Not set" "Set"))))
        (cons 'xferext-tree (list (cons 'raw xferext-tree) (cons 'formatted (fmt-bytes xferext-tree))))
        (cons 'xfer-segment-data (list (cons 'raw xfer-segment-data) (cons 'formatted (fmt-bytes xfer-segment-data))))
        (cons 'xfer-flags (list (cons 'raw xfer-flags) (cons 'formatted (fmt-hex xfer-flags))))
        (cons 'xfer-flags-start (list (cons 'raw xfer-flags-start) (cons 'formatted (if (= xfer-flags-start 0) "Not set" "Set"))))
        (cons 'xfer-flags-end (list (cons 'raw xfer-flags-end) (cons 'formatted (if (= xfer-flags-end 0) "Not set" "Set"))))
        (cons 'xfer-id (list (cons 'raw xfer-id) (cons 'formatted (fmt-hex xfer-id))))
        (cons 'msg-reject-head (list (cons 'raw msg-reject-head) (cons 'formatted (fmt-hex msg-reject-head))))
        )))

    (catch (e)
      (err (str "TCPCL parse error: " e)))))

;; dissect-tcpcl: parse TCPCL from bytevector
;; Returns (ok fields-alist) or (err message)