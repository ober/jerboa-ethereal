;; packet-omron-fins.c
;; Routines for OMRON FINS UDP dissection
;; Copyright Sourcefire, Inc. 2008-2009, Matthew Watchinski <mwatchinski@sourcefire.com>
;;
;; Omron FINS/TCP Support
;; Copyright 2019 Kevin Herron <kevinherron@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Reference:
;;
;; OMRON FINS Commands Reference Manual, W227-E1-2
;;
;; https://www.myomron.com/downloads/1.Manuals/Networks/W227E12_FINS_Commands_Reference_Manual.pdf
;;
;; Special thanks to the guys who wrote the README.developer: it's great.
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/omron-fins.ss
;; Auto-generated from wireshark/epan/dissectors/packet-omron_fins.c

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
(def (dissect-omron-fins buffer)
  "OMRON FINS Protocol"
  (try
    (let* (
           (icf (unwrap (read-u8 buffer 0)))
           (icf-rb0 (extract-bits icf 0x0 0))
           (icf-rb1 (extract-bits icf 0x0 0))
           (icf-rb2 (extract-bits icf 0x0 0))
           (icf-rb3 (extract-bits icf 0x0 0))
           (icf-rb4 (extract-bits icf 0x0 0))
           (rsv (unwrap (read-u8 buffer 0)))
           (gct (unwrap (read-u8 buffer 0)))
           (sid (unwrap (read-u8 buffer 0)))
           (response-code (unwrap (read-u16be buffer 0)))
           (response-code-relay-error (extract-bits response-code 0x8000 15))
           (response-code-main-code (extract-bits response-code 0x7F00 8))
           (response-code-pc-fatal-error (extract-bits response-code 0x80 7))
           (response-code-pc-non-fatal-error (extract-bits response-code 0x40 6))
           (response-code-sub-code (extract-bits response-code 0x3F 0))
           (response-data (unwrap (slice buffer 0 1)))
           (fixed (unwrap (read-u16be buffer 0)))
           (block-record-node-num-status (unwrap (read-u8 buffer 0)))
           (block-record-node-num-num-nodes (unwrap (read-u8 buffer 0)))
           (program-number (unwrap (read-u16be buffer 0)))
           (command-data (unwrap (slice buffer 0 1)))
           (unit-address (unwrap (read-u8 buffer 0)))
           (num-units (unwrap (read-u8 buffer 0)))
           (model-number (unwrap (slice buffer 0 20)))
           (netw-node-sts-low-3 (unwrap (read-u8 buffer 0)))
           (netw-node-sts-low-2 (unwrap (read-u8 buffer 0)))
           (netw-node-sts-low-1 (unwrap (read-u8 buffer 0)))
           (netw-node-sts-low-0 (unwrap (read-u8 buffer 0)))
           (netw-node-sts-high-3 (unwrap (read-u8 buffer 0)))
           (netw-node-sts-high-2 (unwrap (read-u8 buffer 0)))
           (netw-node-sts-high-1 (unwrap (read-u8 buffer 0)))
           (netw-node-sts-high-0 (unwrap (read-u8 buffer 0)))
           (com-cycle-time (unwrap (read-u16be buffer 0)))
           (node-error-count (unwrap (read-u8 buffer 0)))
           (fals (unwrap (read-u16be buffer 0)))
           (message (unwrap (read-u16be buffer 0)))
           (message-rv-1 (extract-bits message 0x40 6))
           (message-rv-2 (extract-bits message 0x20 5))
           (message-rv-3 (extract-bits message 0x10 4))
           (message-rv-4 (extract-bits message 0x8 3))
           (message-rv-5 (extract-bits message 0x4 2))
           (message-rv-6 (extract-bits message 0x2 1))
           (message-rv-7 (extract-bits message 0x1 0))
           (read-message (unwrap (slice buffer 0 32)))
           (beginning-record-no (unwrap (read-u16be buffer 0)))
           (disk-no (unwrap (read-u16be buffer 0)))
           (filename (unwrap (slice buffer 0 12)))
           (beginning-block-num (unwrap (read-u16be buffer 0)))
           (data-type (unwrap (read-u8 buffer 0)))
           (data-type-rv (extract-bits data-type 0x38 3))
           (data-type-protected (extract-bits data-type 0x40 6))
           (data-type-end (extract-bits data-type 0x80 7))
           (block-num (unwrap (read-u16be buffer 0)))
           (number-of-bits-flags (unwrap (read-u16be buffer 0)))
           (name-data (unwrap (slice buffer 0 1)))
           )

      (ok (list
        (cons 'icf (list (cons 'raw icf) (cons 'formatted (fmt-hex icf))))
        (cons 'icf-rb0 (list (cons 'raw icf-rb0) (cons 'formatted (if (= icf-rb0 0) "Not set" "Set"))))
        (cons 'icf-rb1 (list (cons 'raw icf-rb1) (cons 'formatted (if (= icf-rb1 0) "Not set" "Set"))))
        (cons 'icf-rb2 (list (cons 'raw icf-rb2) (cons 'formatted (if (= icf-rb2 0) "Not set" "Set"))))
        (cons 'icf-rb3 (list (cons 'raw icf-rb3) (cons 'formatted (if (= icf-rb3 0) "Not set" "Set"))))
        (cons 'icf-rb4 (list (cons 'raw icf-rb4) (cons 'formatted (if (= icf-rb4 0) "Not set" "Set"))))
        (cons 'rsv (list (cons 'raw rsv) (cons 'formatted (fmt-hex rsv))))
        (cons 'gct (list (cons 'raw gct) (cons 'formatted (fmt-hex gct))))
        (cons 'sid (list (cons 'raw sid) (cons 'formatted (fmt-hex sid))))
        (cons 'response-code (list (cons 'raw response-code) (cons 'formatted (fmt-hex response-code))))
        (cons 'response-code-relay-error (list (cons 'raw response-code-relay-error) (cons 'formatted (if (= response-code-relay-error 0) "Not set" "Set"))))
        (cons 'response-code-main-code (list (cons 'raw response-code-main-code) (cons 'formatted (if (= response-code-main-code 0) "Not set" "Set"))))
        (cons 'response-code-pc-fatal-error (list (cons 'raw response-code-pc-fatal-error) (cons 'formatted (if (= response-code-pc-fatal-error 0) "Not set" "Set"))))
        (cons 'response-code-pc-non-fatal-error (list (cons 'raw response-code-pc-non-fatal-error) (cons 'formatted (if (= response-code-pc-non-fatal-error 0) "Not set" "Set"))))
        (cons 'response-code-sub-code (list (cons 'raw response-code-sub-code) (cons 'formatted (if (= response-code-sub-code 0) "Not set" "Set"))))
        (cons 'response-data (list (cons 'raw response-data) (cons 'formatted (fmt-bytes response-data))))
        (cons 'fixed (list (cons 'raw fixed) (cons 'formatted (fmt-hex fixed))))
        (cons 'block-record-node-num-status (list (cons 'raw block-record-node-num-status) (cons 'formatted (if (= block-record-node-num-status 0) "Warning" "Normal"))))
        (cons 'block-record-node-num-num-nodes (list (cons 'raw block-record-node-num-num-nodes) (cons 'formatted (number->string block-record-node-num-num-nodes))))
        (cons 'program-number (list (cons 'raw program-number) (cons 'formatted (fmt-hex program-number))))
        (cons 'command-data (list (cons 'raw command-data) (cons 'formatted (fmt-bytes command-data))))
        (cons 'unit-address (list (cons 'raw unit-address) (cons 'formatted (fmt-hex unit-address))))
        (cons 'num-units (list (cons 'raw num-units) (cons 'formatted (number->string num-units))))
        (cons 'model-number (list (cons 'raw model-number) (cons 'formatted (utf8->string model-number))))
        (cons 'netw-node-sts-low-3 (list (cons 'raw netw-node-sts-low-3) (cons 'formatted (if (= netw-node-sts-low-3 0) "Unit responds to polling" "Unit does not respond to polling"))))
        (cons 'netw-node-sts-low-2 (list (cons 'raw netw-node-sts-low-2) (cons 'formatted (number->string netw-node-sts-low-2))))
        (cons 'netw-node-sts-low-1 (list (cons 'raw netw-node-sts-low-1) (cons 'formatted (if (= netw-node-sts-low-1 0) "Normal" "Error"))))
        (cons 'netw-node-sts-low-0 (list (cons 'raw netw-node-sts-low-0) (cons 'formatted (if (= netw-node-sts-low-0 0) "Not in network" "In network"))))
        (cons 'netw-node-sts-high-3 (list (cons 'raw netw-node-sts-high-3) (cons 'formatted (if (= netw-node-sts-high-3 0) "Unit responds to polling" "Unit does not respond to polling"))))
        (cons 'netw-node-sts-high-2 (list (cons 'raw netw-node-sts-high-2) (cons 'formatted (number->string netw-node-sts-high-2))))
        (cons 'netw-node-sts-high-1 (list (cons 'raw netw-node-sts-high-1) (cons 'formatted (if (= netw-node-sts-high-1 0) "Normal" "Error"))))
        (cons 'netw-node-sts-high-0 (list (cons 'raw netw-node-sts-high-0) (cons 'formatted (if (= netw-node-sts-high-0 0) "Not in network" "In network"))))
        (cons 'com-cycle-time (list (cons 'raw com-cycle-time) (cons 'formatted (number->string com-cycle-time))))
        (cons 'node-error-count (list (cons 'raw node-error-count) (cons 'formatted (number->string node-error-count))))
        (cons 'fals (list (cons 'raw fals) (cons 'formatted (fmt-hex fals))))
        (cons 'message (list (cons 'raw message) (cons 'formatted (fmt-hex message))))
        (cons 'message-rv-1 (list (cons 'raw message-rv-1) (cons 'formatted (if (= message-rv-1 0) "Not set" "Set"))))
        (cons 'message-rv-2 (list (cons 'raw message-rv-2) (cons 'formatted (if (= message-rv-2 0) "Not set" "Set"))))
        (cons 'message-rv-3 (list (cons 'raw message-rv-3) (cons 'formatted (if (= message-rv-3 0) "Not set" "Set"))))
        (cons 'message-rv-4 (list (cons 'raw message-rv-4) (cons 'formatted (if (= message-rv-4 0) "Not set" "Set"))))
        (cons 'message-rv-5 (list (cons 'raw message-rv-5) (cons 'formatted (if (= message-rv-5 0) "Not set" "Set"))))
        (cons 'message-rv-6 (list (cons 'raw message-rv-6) (cons 'formatted (if (= message-rv-6 0) "Not set" "Set"))))
        (cons 'message-rv-7 (list (cons 'raw message-rv-7) (cons 'formatted (if (= message-rv-7 0) "Not set" "Set"))))
        (cons 'read-message (list (cons 'raw read-message) (cons 'formatted (utf8->string read-message))))
        (cons 'beginning-record-no (list (cons 'raw beginning-record-no) (cons 'formatted (number->string beginning-record-no))))
        (cons 'disk-no (list (cons 'raw disk-no) (cons 'formatted (number->string disk-no))))
        (cons 'filename (list (cons 'raw filename) (cons 'formatted (utf8->string filename))))
        (cons 'beginning-block-num (list (cons 'raw beginning-block-num) (cons 'formatted (number->string beginning-block-num))))
        (cons 'data-type (list (cons 'raw data-type) (cons 'formatted (fmt-hex data-type))))
        (cons 'data-type-rv (list (cons 'raw data-type-rv) (cons 'formatted (if (= data-type-rv 0) "Not set" "Set"))))
        (cons 'data-type-protected (list (cons 'raw data-type-protected) (cons 'formatted (if (= data-type-protected 0) "Not Protected" "Protected"))))
        (cons 'data-type-end (list (cons 'raw data-type-end) (cons 'formatted (if (= data-type-end 0) "Not Last Block" "Last Block"))))
        (cons 'block-num (list (cons 'raw block-num) (cons 'formatted (number->string block-num))))
        (cons 'number-of-bits-flags (list (cons 'raw number-of-bits-flags) (cons 'formatted (number->string number-of-bits-flags))))
        (cons 'name-data (list (cons 'raw name-data) (cons 'formatted (utf8->string name-data))))
        )))

    (catch (e)
      (err (str "OMRON-FINS parse error: " e)))))

;; dissect-omron-fins: parse OMRON-FINS from bytevector
;; Returns (ok fields-alist) or (err message)