;; packet-cfdp.c
;; Routines for CCSDS File Delivery Protocol (CFDP) dissection
;; Copyright 2013, Juan Antonio Montesinos juan.mondl@gmail.com
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Slightly updated to allow more in-depth decoding when called
;; with the 'dissect_as_subtree' method and to leverage some
;; of the bitfield display operations: Keith Scott
;; <kscott@mitre.org>.
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/cfdp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cfdp.c

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
(def (dissect-cfdp buffer)
  "CFDP"
  (try
    (let* (
           (dstid (unwrap (read-u64be buffer 0)))
           (transeqnum (unwrap (read-u64be buffer 0)))
           (flags (unwrap (read-u8 buffer 0)))
           (version (extract-bits flags 0x0 0))
           (res1 (extract-bits flags 0x0 0))
           (first-file-name-len (unwrap (read-u32be buffer 6)))
           (first-file-name (unwrap (slice buffer 7 1)))
           (second-file-name-len (unwrap (read-u32be buffer 7)))
           (second-file-name (unwrap (slice buffer 8 1)))
           (filestore-message-len (unwrap (read-u32be buffer 8)))
           (filestore-message (unwrap (slice buffer 9 1)))
           (data-length (unwrap (read-u16be buffer 12)))
           (file-data-offset (unwrap (read-u32be buffer 16)))
           (proxy-fault-hdl-overr (unwrap (read-u8 buffer 20)))
           (user-data (unwrap (slice buffer 20 1)))
           (crc (unwrap (read-u16be buffer 20)))
           (proxy-trans-mode (unwrap (read-u8 buffer 21)))
           (proxy-segment-control-byte (unwrap (read-u8 buffer 22)))
           (spare-seven-2 (extract-bits proxy-segment-control-byte 0xFE 1))
           (file-data-pdu (unwrap (slice buffer 22 1)))
           (proxy-put-resp (unwrap (read-u8 buffer 23)))
           (spare-one (extract-bits proxy-put-resp 0x8 3))
           (directory-name (unwrap (slice buffer 29 1)))
           (directory-file-name (unwrap (slice buffer 30 1)))
           (report-file-name (unwrap (slice buffer 32 1)))
           (message-to-user (unwrap (slice buffer 35 1)))
           (tlv-len (unwrap (read-u8 buffer 36)))
           (flow-label (unwrap (slice buffer 38 1)))
           (spare-four (unwrap (read-u8 buffer 38)))
           (entity (unwrap (slice buffer 49 1)))
           (dir-subtype-ack (unwrap (read-u8 buffer 53)))
           (spare-two (unwrap (read-u8 buffer 54)))
           (file-size (unwrap (read-u32be buffer 56)))
           (src-file-name-len (unwrap (read-u32be buffer 60)))
           (src-file-name (unwrap (slice buffer 61 1)))
           (dst-file-name-len (unwrap (read-u32be buffer 61)))
           (dst-file-name (unwrap (slice buffer 62 1)))
           (nak-st-scope (unwrap (read-u32be buffer 63)))
           (nak-sp-scope (unwrap (read-u32be buffer 67)))
           (segment-requests (unwrap (slice buffer 71 1)))
           (spare-seven (unwrap (read-u8 buffer 71)))
           (progress (unwrap (read-u32be buffer 72)))
           (srcid (unwrap (read-u64be buffer 76)))
           )

      (ok (list
        (cons 'dstid (list (cons 'raw dstid) (cons 'formatted (number->string dstid))))
        (cons 'transeqnum (list (cons 'raw transeqnum) (cons 'formatted (number->string transeqnum))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (if (= version 0) "Not set" "Set"))))
        (cons 'res1 (list (cons 'raw res1) (cons 'formatted (if (= res1 0) "Not set" "Set"))))
        (cons 'first-file-name-len (list (cons 'raw first-file-name-len) (cons 'formatted (number->string first-file-name-len))))
        (cons 'first-file-name (list (cons 'raw first-file-name) (cons 'formatted (utf8->string first-file-name))))
        (cons 'second-file-name-len (list (cons 'raw second-file-name-len) (cons 'formatted (number->string second-file-name-len))))
        (cons 'second-file-name (list (cons 'raw second-file-name) (cons 'formatted (utf8->string second-file-name))))
        (cons 'filestore-message-len (list (cons 'raw filestore-message-len) (cons 'formatted (number->string filestore-message-len))))
        (cons 'filestore-message (list (cons 'raw filestore-message) (cons 'formatted (fmt-bytes filestore-message))))
        (cons 'data-length (list (cons 'raw data-length) (cons 'formatted (number->string data-length))))
        (cons 'file-data-offset (list (cons 'raw file-data-offset) (cons 'formatted (number->string file-data-offset))))
        (cons 'proxy-fault-hdl-overr (list (cons 'raw proxy-fault-hdl-overr) (cons 'formatted (fmt-hex proxy-fault-hdl-overr))))
        (cons 'user-data (list (cons 'raw user-data) (cons 'formatted (fmt-bytes user-data))))
        (cons 'crc (list (cons 'raw crc) (cons 'formatted (fmt-hex crc))))
        (cons 'proxy-trans-mode (list (cons 'raw proxy-trans-mode) (cons 'formatted (fmt-hex proxy-trans-mode))))
        (cons 'proxy-segment-control-byte (list (cons 'raw proxy-segment-control-byte) (cons 'formatted (fmt-hex proxy-segment-control-byte))))
        (cons 'spare-seven-2 (list (cons 'raw spare-seven-2) (cons 'formatted (if (= spare-seven-2 0) "Not set" "Set"))))
        (cons 'file-data-pdu (list (cons 'raw file-data-pdu) (cons 'formatted (utf8->string file-data-pdu))))
        (cons 'proxy-put-resp (list (cons 'raw proxy-put-resp) (cons 'formatted (fmt-hex proxy-put-resp))))
        (cons 'spare-one (list (cons 'raw spare-one) (cons 'formatted (if (= spare-one 0) "Not set" "Set"))))
        (cons 'directory-name (list (cons 'raw directory-name) (cons 'formatted (utf8->string directory-name))))
        (cons 'directory-file-name (list (cons 'raw directory-file-name) (cons 'formatted (utf8->string directory-file-name))))
        (cons 'report-file-name (list (cons 'raw report-file-name) (cons 'formatted (utf8->string report-file-name))))
        (cons 'message-to-user (list (cons 'raw message-to-user) (cons 'formatted (fmt-bytes message-to-user))))
        (cons 'tlv-len (list (cons 'raw tlv-len) (cons 'formatted (number->string tlv-len))))
        (cons 'flow-label (list (cons 'raw flow-label) (cons 'formatted (fmt-bytes flow-label))))
        (cons 'spare-four (list (cons 'raw spare-four) (cons 'formatted (number->string spare-four))))
        (cons 'entity (list (cons 'raw entity) (cons 'formatted (fmt-bytes entity))))
        (cons 'dir-subtype-ack (list (cons 'raw dir-subtype-ack) (cons 'formatted (number->string dir-subtype-ack))))
        (cons 'spare-two (list (cons 'raw spare-two) (cons 'formatted (number->string spare-two))))
        (cons 'file-size (list (cons 'raw file-size) (cons 'formatted (number->string file-size))))
        (cons 'src-file-name-len (list (cons 'raw src-file-name-len) (cons 'formatted (number->string src-file-name-len))))
        (cons 'src-file-name (list (cons 'raw src-file-name) (cons 'formatted (utf8->string src-file-name))))
        (cons 'dst-file-name-len (list (cons 'raw dst-file-name-len) (cons 'formatted (number->string dst-file-name-len))))
        (cons 'dst-file-name (list (cons 'raw dst-file-name) (cons 'formatted (utf8->string dst-file-name))))
        (cons 'nak-st-scope (list (cons 'raw nak-st-scope) (cons 'formatted (number->string nak-st-scope))))
        (cons 'nak-sp-scope (list (cons 'raw nak-sp-scope) (cons 'formatted (number->string nak-sp-scope))))
        (cons 'segment-requests (list (cons 'raw segment-requests) (cons 'formatted (fmt-bytes segment-requests))))
        (cons 'spare-seven (list (cons 'raw spare-seven) (cons 'formatted (number->string spare-seven))))
        (cons 'progress (list (cons 'raw progress) (cons 'formatted (number->string progress))))
        (cons 'srcid (list (cons 'raw srcid) (cons 'formatted (number->string srcid))))
        )))

    (catch (e)
      (err (str "CFDP parse error: " e)))))

;; dissect-cfdp: parse CFDP from bytevector
;; Returns (ok fields-alist) or (err message)