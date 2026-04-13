;; packet-sdp.c
;; Routines for SDP packet disassembly (RFC 2327)
;;
;; Jason Lango <jal@netapp.com>
;; Liberally copied from packet-http.c, by Guy Harris <guy@alum.mit.edu>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;; Ref https://www.ietf.org/rfc/rfc4566
;;

;; jerboa-ethereal/dissectors/sdp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-sdp.c
;; RFC 2327

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
(def (dissect-sdp buffer)
  "Session Description Protocol"
  (try
    (let* (
           (username (unwrap (slice buffer 0 1)))
           (sessionid (unwrap (slice buffer 0 1)))
           (network-type (unwrap (slice buffer 0 1)))
           (address-type (unwrap (slice buffer 0 1)))
           (address (unwrap (slice buffer 0 1)))
           (info-network-type (unwrap (slice buffer 0 1)))
           (info-address-type (unwrap (slice buffer 0 1)))
           (info-connection-address (unwrap (slice buffer 0 1)))
           (info-ttl (unwrap (slice buffer 0 1)))
           (info-num-addr (unwrap (slice buffer 0 1)))
           (modifier (unwrap (slice buffer 0 1)))
           (value (unwrap (slice buffer 0 1)))
           (start (unwrap (slice buffer 0 1)))
           (stop (unwrap (slice buffer 0 1)))
           (time-interval (unwrap (slice buffer 0 1)))
           (time-duration (unwrap (slice buffer 0 1)))
           (time-offset (unwrap (slice buffer 0 1)))
           (time (unwrap (slice buffer 0 1)))
           (offset (unwrap (slice buffer 0 1)))
           (key-type (unwrap (slice buffer 0 1)))
           (key-data (unwrap (slice buffer 0 1)))
           (mgmt-prtcl-id (unwrap (slice buffer 0 1)))
           (version (unwrap (slice buffer 0 1)))
           (type (unwrap (slice buffer 0 1)))
           (media (unwrap (slice buffer 0 1)))
           (port-string (unwrap (slice buffer 0 1)))
           (port (unwrap (read-u16be buffer 0)))
           (portcount (unwrap (slice buffer 0 1)))
           (proto (unwrap (slice buffer 0 1)))
           (nal-unit-1-string (unwrap (slice buffer 0 1)))
           (nal-unit-2-string (unwrap (slice buffer 0 1)))
           (candidate-foundation (unwrap (slice buffer 0 1)))
           (candidate-componentid (unwrap (slice buffer 0 1)))
           (candidate-transport (unwrap (slice buffer 0 1)))
           (candidate-priority (unwrap (slice buffer 0 1)))
           (candidate-address (unwrap (slice buffer 0 1)))
           (candidate-port (unwrap (slice buffer 0 1)))
           (attribute-field (unwrap (slice buffer 0 1)))
           (attribute-value (unwrap (slice buffer 0 1)))
           (hf-invalid (unwrap (slice buffer 0 1)))
           (data (unwrap (slice buffer 0 1)))
           (candidate-type (unwrap (slice buffer 4 1)))
           (format (unwrap (slice buffer 4 1)))
           (encoding-name (unwrap (slice buffer 4 1)))
           (sample-rate (unwrap (slice buffer 4 1)))
           (channels (unwrap (slice buffer 4 1)))
           (format-specific-parameter (unwrap (slice buffer 4 1)))
           (crypto-tag (unwrap (read-u32be buffer 4)))
           (crypto-crypto-suite (unwrap (slice buffer 4 1)))
           (key-and-salt (unwrap (slice buffer 4 1)))
           (crypto-lifetime (unwrap (slice buffer 4 1)))
           (crypto-mki (unwrap (slice buffer 4 1)))
           (crypto-mki-length (unwrap (slice buffer 4 1)))
           )

      (ok (list
        (cons 'username (list (cons 'raw username) (cons 'formatted (utf8->string username))))
        (cons 'sessionid (list (cons 'raw sessionid) (cons 'formatted (utf8->string sessionid))))
        (cons 'network-type (list (cons 'raw network-type) (cons 'formatted (utf8->string network-type))))
        (cons 'address-type (list (cons 'raw address-type) (cons 'formatted (utf8->string address-type))))
        (cons 'address (list (cons 'raw address) (cons 'formatted (utf8->string address))))
        (cons 'info-network-type (list (cons 'raw info-network-type) (cons 'formatted (utf8->string info-network-type))))
        (cons 'info-address-type (list (cons 'raw info-address-type) (cons 'formatted (utf8->string info-address-type))))
        (cons 'info-connection-address (list (cons 'raw info-connection-address) (cons 'formatted (utf8->string info-connection-address))))
        (cons 'info-ttl (list (cons 'raw info-ttl) (cons 'formatted (utf8->string info-ttl))))
        (cons 'info-num-addr (list (cons 'raw info-num-addr) (cons 'formatted (utf8->string info-num-addr))))
        (cons 'modifier (list (cons 'raw modifier) (cons 'formatted (utf8->string modifier))))
        (cons 'value (list (cons 'raw value) (cons 'formatted (utf8->string value))))
        (cons 'start (list (cons 'raw start) (cons 'formatted (utf8->string start))))
        (cons 'stop (list (cons 'raw stop) (cons 'formatted (utf8->string stop))))
        (cons 'time-interval (list (cons 'raw time-interval) (cons 'formatted (utf8->string time-interval))))
        (cons 'time-duration (list (cons 'raw time-duration) (cons 'formatted (utf8->string time-duration))))
        (cons 'time-offset (list (cons 'raw time-offset) (cons 'formatted (utf8->string time-offset))))
        (cons 'time (list (cons 'raw time) (cons 'formatted (utf8->string time))))
        (cons 'offset (list (cons 'raw offset) (cons 'formatted (utf8->string offset))))
        (cons 'key-type (list (cons 'raw key-type) (cons 'formatted (utf8->string key-type))))
        (cons 'key-data (list (cons 'raw key-data) (cons 'formatted (utf8->string key-data))))
        (cons 'mgmt-prtcl-id (list (cons 'raw mgmt-prtcl-id) (cons 'formatted (utf8->string mgmt-prtcl-id))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (utf8->string version))))
        (cons 'type (list (cons 'raw type) (cons 'formatted (utf8->string type))))
        (cons 'media (list (cons 'raw media) (cons 'formatted (utf8->string media))))
        (cons 'port-string (list (cons 'raw port-string) (cons 'formatted (utf8->string port-string))))
        (cons 'port (list (cons 'raw port) (cons 'formatted (fmt-port port))))
        (cons 'portcount (list (cons 'raw portcount) (cons 'formatted (utf8->string portcount))))
        (cons 'proto (list (cons 'raw proto) (cons 'formatted (utf8->string proto))))
        (cons 'nal-unit-1-string (list (cons 'raw nal-unit-1-string) (cons 'formatted (utf8->string nal-unit-1-string))))
        (cons 'nal-unit-2-string (list (cons 'raw nal-unit-2-string) (cons 'formatted (utf8->string nal-unit-2-string))))
        (cons 'candidate-foundation (list (cons 'raw candidate-foundation) (cons 'formatted (utf8->string candidate-foundation))))
        (cons 'candidate-componentid (list (cons 'raw candidate-componentid) (cons 'formatted (utf8->string candidate-componentid))))
        (cons 'candidate-transport (list (cons 'raw candidate-transport) (cons 'formatted (utf8->string candidate-transport))))
        (cons 'candidate-priority (list (cons 'raw candidate-priority) (cons 'formatted (utf8->string candidate-priority))))
        (cons 'candidate-address (list (cons 'raw candidate-address) (cons 'formatted (utf8->string candidate-address))))
        (cons 'candidate-port (list (cons 'raw candidate-port) (cons 'formatted (utf8->string candidate-port))))
        (cons 'attribute-field (list (cons 'raw attribute-field) (cons 'formatted (utf8->string attribute-field))))
        (cons 'attribute-value (list (cons 'raw attribute-value) (cons 'formatted (utf8->string attribute-value))))
        (cons 'hf-invalid (list (cons 'raw hf-invalid) (cons 'formatted (utf8->string hf-invalid))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'candidate-type (list (cons 'raw candidate-type) (cons 'formatted (utf8->string candidate-type))))
        (cons 'format (list (cons 'raw format) (cons 'formatted (utf8->string format))))
        (cons 'encoding-name (list (cons 'raw encoding-name) (cons 'formatted (utf8->string encoding-name))))
        (cons 'sample-rate (list (cons 'raw sample-rate) (cons 'formatted (utf8->string sample-rate))))
        (cons 'channels (list (cons 'raw channels) (cons 'formatted (utf8->string channels))))
        (cons 'format-specific-parameter (list (cons 'raw format-specific-parameter) (cons 'formatted (utf8->string format-specific-parameter))))
        (cons 'crypto-tag (list (cons 'raw crypto-tag) (cons 'formatted (number->string crypto-tag))))
        (cons 'crypto-crypto-suite (list (cons 'raw crypto-crypto-suite) (cons 'formatted (utf8->string crypto-crypto-suite))))
        (cons 'key-and-salt (list (cons 'raw key-and-salt) (cons 'formatted (fmt-bytes key-and-salt))))
        (cons 'crypto-lifetime (list (cons 'raw crypto-lifetime) (cons 'formatted (utf8->string crypto-lifetime))))
        (cons 'crypto-mki (list (cons 'raw crypto-mki) (cons 'formatted (utf8->string crypto-mki))))
        (cons 'crypto-mki-length (list (cons 'raw crypto-mki-length) (cons 'formatted (utf8->string crypto-mki-length))))
        )))

    (catch (e)
      (err (str "SDP parse error: " e)))))

;; dissect-sdp: parse SDP from bytevector
;; Returns (ok fields-alist) or (err message)