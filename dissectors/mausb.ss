;; packet-mausb.c
;; Routines for Media Agnostic USB dissection
;; Copyright 2014, Intel Corporation
;; Author: Sean O. Stalley <sean.stalley@intel.com>
;;
;; Dedicated to Robert & Dorothy Stalley
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mausb.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mausb.c

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
(def (dissect-mausb buffer)
  "Media Agnostic USB"
  (try
    (let* (
           (token (unwrap (read-u16be buffer 0)))
           (mgmt-pad (unwrap (read-u16be buffer 1)))
           (cap-resp-num-dev (unwrap (read-u8 buffer 4)))
           (cap-resp-num-stream (unwrap (read-u8 buffer 5)))
           (cap-resp-desc-count (unwrap (read-u8 buffer 6)))
           (cap-resp-desc-len (unwrap (read-u24be buffer 7)))
           (cap-resp-transfer-req (unwrap (read-u16be buffer 10)))
           (cap-resp-mgmt-req (unwrap (read-u16be buffer 12)))
           (cap-resp-rsvd (unwrap (read-u16be buffer 12)))
           (ep-handle (unwrap (read-u16be buffer 14)))
           (ep-handle-d (unwrap (read-u8 buffer 14)))
           (ep-handle-ep-num (unwrap (read-u16be buffer 14)))
           (ep-handle-dev-addr (unwrap (read-u16be buffer 14)))
           (ep-handle-bus-num (unwrap (read-u16be buffer 14)))
           (present-time (unwrap (read-u32be buffer 14)))
           (uframe (unwrap (read-u32be buffer 14)))
           (frame (unwrap (read-u32be buffer 14)))
           (timestamp (unwrap (read-u32be buffer 14)))
           (delta (unwrap (read-u32be buffer 14)))
           (nom-interval (unwrap (read-u32be buffer 14)))
           (clear-transfers-start-req-id (unwrap (read-u8 buffer 16)))
           (clear-transfers-status (unwrap (read-u8 buffer 20)))
           (clear-transfers-partial (unwrap (read-u8 buffer 20)))
           (clear-transfers-resp-block-rsvd (unwrap (read-u32be buffer 20)))
           (clear-transfers-last-req-id (unwrap (read-u8 buffer 24)))
           (clear-transfers-req-num (unwrap (read-u8 buffer 32)))
           (clear-transfers-resp-num (unwrap (read-u32be buffer 36)))
           (mgmt-ep-des-num (unwrap (read-u8 buffer 40)))
           (mgmt-ep-handle-num (unwrap (read-u8 buffer 40)))
           (mgmt-ep-des-size (unwrap (read-u16be buffer 40)))
           (cancel-transfer-seq-num (unwrap (read-u24be buffer 75)))
           (cancel-transfer-byte-offset (unwrap (read-u32be buffer 79)))
           (flags (unwrap (read-u8 buffer 91)))
           (length (unwrap (read-u16be buffer 93)))
           (dev-handle (unwrap (read-u16be buffer 95)))
           (ma-dev-addr (unwrap (read-u8 buffer 97)))
           (ssid (unwrap (read-u8 buffer 98)))
           (eps-rsvd (unwrap (read-u8 buffer 100)))
           (tflags (unwrap (read-u8 buffer 100)))
           (tflag-arq (extract-bits tflags 0x0 0))
           (tflag-neg (extract-bits tflags 0x0 0))
           (tflag-eot (extract-bits tflags 0x0 0))
           (tflag-rsvd (extract-bits tflags 0x0 0))
           (num-iso-hdr (unwrap (read-u16be buffer 101)))
           (iflags (unwrap (read-u16le buffer 101)))
           (iflag-mtd (extract-bits iflags 0x0 0))
           (iflag-hdr-format (extract-bits iflags 0x0 0))
           (iflag-asap (extract-bits iflags 0x0 0))
           (stream-id (unwrap (read-u16be buffer 101)))
           (seq-num (unwrap (read-u24be buffer 103)))
           (req-id (unwrap (read-u8 buffer 106)))
           (num-segs (unwrap (read-u32be buffer 107)))
           (mtd (unwrap (read-u32be buffer 115)))
           (rem-size-credit (unwrap (read-u32be buffer 119)))
           (cap-resp-num-ep (unwrap (read-u16be buffer 123)))
           )

      (ok (list
        (cons 'token (list (cons 'raw token) (cons 'formatted (number->string token))))
        (cons 'mgmt-pad (list (cons 'raw mgmt-pad) (cons 'formatted (fmt-hex mgmt-pad))))
        (cons 'cap-resp-num-dev (list (cons 'raw cap-resp-num-dev) (cons 'formatted (number->string cap-resp-num-dev))))
        (cons 'cap-resp-num-stream (list (cons 'raw cap-resp-num-stream) (cons 'formatted (number->string cap-resp-num-stream))))
        (cons 'cap-resp-desc-count (list (cons 'raw cap-resp-desc-count) (cons 'formatted (number->string cap-resp-desc-count))))
        (cons 'cap-resp-desc-len (list (cons 'raw cap-resp-desc-len) (cons 'formatted (number->string cap-resp-desc-len))))
        (cons 'cap-resp-transfer-req (list (cons 'raw cap-resp-transfer-req) (cons 'formatted (number->string cap-resp-transfer-req))))
        (cons 'cap-resp-mgmt-req (list (cons 'raw cap-resp-mgmt-req) (cons 'formatted (number->string cap-resp-mgmt-req))))
        (cons 'cap-resp-rsvd (list (cons 'raw cap-resp-rsvd) (cons 'formatted (fmt-hex cap-resp-rsvd))))
        (cons 'ep-handle (list (cons 'raw ep-handle) (cons 'formatted (fmt-hex ep-handle))))
        (cons 'ep-handle-d (list (cons 'raw ep-handle-d) (cons 'formatted (if (= ep-handle-d 0) "False" "True"))))
        (cons 'ep-handle-ep-num (list (cons 'raw ep-handle-ep-num) (cons 'formatted (number->string ep-handle-ep-num))))
        (cons 'ep-handle-dev-addr (list (cons 'raw ep-handle-dev-addr) (cons 'formatted (number->string ep-handle-dev-addr))))
        (cons 'ep-handle-bus-num (list (cons 'raw ep-handle-bus-num) (cons 'formatted (number->string ep-handle-bus-num))))
        (cons 'present-time (list (cons 'raw present-time) (cons 'formatted (number->string present-time))))
        (cons 'uframe (list (cons 'raw uframe) (cons 'formatted (number->string uframe))))
        (cons 'frame (list (cons 'raw frame) (cons 'formatted (number->string frame))))
        (cons 'timestamp (list (cons 'raw timestamp) (cons 'formatted (number->string timestamp))))
        (cons 'delta (list (cons 'raw delta) (cons 'formatted (number->string delta))))
        (cons 'nom-interval (list (cons 'raw nom-interval) (cons 'formatted (number->string nom-interval))))
        (cons 'clear-transfers-start-req-id (list (cons 'raw clear-transfers-start-req-id) (cons 'formatted (number->string clear-transfers-start-req-id))))
        (cons 'clear-transfers-status (list (cons 'raw clear-transfers-status) (cons 'formatted (if (= clear-transfers-status 0) "False" "True"))))
        (cons 'clear-transfers-partial (list (cons 'raw clear-transfers-partial) (cons 'formatted (number->string clear-transfers-partial))))
        (cons 'clear-transfers-resp-block-rsvd (list (cons 'raw clear-transfers-resp-block-rsvd) (cons 'formatted (fmt-hex clear-transfers-resp-block-rsvd))))
        (cons 'clear-transfers-last-req-id (list (cons 'raw clear-transfers-last-req-id) (cons 'formatted (number->string clear-transfers-last-req-id))))
        (cons 'clear-transfers-req-num (list (cons 'raw clear-transfers-req-num) (cons 'formatted (number->string clear-transfers-req-num))))
        (cons 'clear-transfers-resp-num (list (cons 'raw clear-transfers-resp-num) (cons 'formatted (number->string clear-transfers-resp-num))))
        (cons 'mgmt-ep-des-num (list (cons 'raw mgmt-ep-des-num) (cons 'formatted (number->string mgmt-ep-des-num))))
        (cons 'mgmt-ep-handle-num (list (cons 'raw mgmt-ep-handle-num) (cons 'formatted (number->string mgmt-ep-handle-num))))
        (cons 'mgmt-ep-des-size (list (cons 'raw mgmt-ep-des-size) (cons 'formatted (number->string mgmt-ep-des-size))))
        (cons 'cancel-transfer-seq-num (list (cons 'raw cancel-transfer-seq-num) (cons 'formatted (number->string cancel-transfer-seq-num))))
        (cons 'cancel-transfer-byte-offset (list (cons 'raw cancel-transfer-byte-offset) (cons 'formatted (number->string cancel-transfer-byte-offset))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'dev-handle (list (cons 'raw dev-handle) (cons 'formatted (fmt-hex dev-handle))))
        (cons 'ma-dev-addr (list (cons 'raw ma-dev-addr) (cons 'formatted (fmt-hex ma-dev-addr))))
        (cons 'ssid (list (cons 'raw ssid) (cons 'formatted (fmt-hex ssid))))
        (cons 'eps-rsvd (list (cons 'raw eps-rsvd) (cons 'formatted (fmt-hex eps-rsvd))))
        (cons 'tflags (list (cons 'raw tflags) (cons 'formatted (fmt-hex tflags))))
        (cons 'tflag-arq (list (cons 'raw tflag-arq) (cons 'formatted (if (= tflag-arq 0) "Not set" "Set"))))
        (cons 'tflag-neg (list (cons 'raw tflag-neg) (cons 'formatted (if (= tflag-neg 0) "Not set" "Set"))))
        (cons 'tflag-eot (list (cons 'raw tflag-eot) (cons 'formatted (if (= tflag-eot 0) "Not set" "Set"))))
        (cons 'tflag-rsvd (list (cons 'raw tflag-rsvd) (cons 'formatted (if (= tflag-rsvd 0) "Not set" "Set"))))
        (cons 'num-iso-hdr (list (cons 'raw num-iso-hdr) (cons 'formatted (number->string num-iso-hdr))))
        (cons 'iflags (list (cons 'raw iflags) (cons 'formatted (fmt-hex iflags))))
        (cons 'iflag-mtd (list (cons 'raw iflag-mtd) (cons 'formatted (if (= iflag-mtd 0) "Not set" "Set"))))
        (cons 'iflag-hdr-format (list (cons 'raw iflag-hdr-format) (cons 'formatted (if (= iflag-hdr-format 0) "Not set" "Set"))))
        (cons 'iflag-asap (list (cons 'raw iflag-asap) (cons 'formatted (if (= iflag-asap 0) "Not set" "Set"))))
        (cons 'stream-id (list (cons 'raw stream-id) (cons 'formatted (number->string stream-id))))
        (cons 'seq-num (list (cons 'raw seq-num) (cons 'formatted (number->string seq-num))))
        (cons 'req-id (list (cons 'raw req-id) (cons 'formatted (number->string req-id))))
        (cons 'num-segs (list (cons 'raw num-segs) (cons 'formatted (number->string num-segs))))
        (cons 'mtd (list (cons 'raw mtd) (cons 'formatted (number->string mtd))))
        (cons 'rem-size-credit (list (cons 'raw rem-size-credit) (cons 'formatted (number->string rem-size-credit))))
        (cons 'cap-resp-num-ep (list (cons 'raw cap-resp-num-ep) (cons 'formatted (number->string cap-resp-num-ep))))
        )))

    (catch (e)
      (err (str "MAUSB parse error: " e)))))

;; dissect-mausb: parse MAUSB from bytevector
;; Returns (ok fields-alist) or (err message)