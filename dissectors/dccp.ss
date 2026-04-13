;; packet-dccp.c
;; Routines for Datagram Congestion Control Protocol, "DCCP" dissection:
;; it should conform to RFC 4340
;;
;; Copyright 2005 _FF_
;;
;; Francesco Fondelli <francesco dot fondelli, gmail dot com>
;;
;; Copyright 2020-2021 by Thomas Dreibholz <dreibh [AT] simula.no>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-udp.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dccp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dccp.c
;; RFC 4340

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
(def (dissect-dccp buffer)
  "Datagram Congestion Control Protocol"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (srcport (unwrap (read-u16be buffer 0)))
           (padding (unwrap (slice buffer 2 1)))
           (mandatory (unwrap (slice buffer 2 1)))
           (slow-receiver (unwrap (slice buffer 2 1)))
           (init-cookie (unwrap (slice buffer 2 1)))
           (ndp-count (unwrap (read-u64be buffer 2)))
           (ack-vector-nonce-0 (unwrap (slice buffer 2 1)))
           (ack-vector-nonce-1 (unwrap (slice buffer 2 1)))
           (data-dropped (unwrap (slice buffer 2 1)))
           (timestamp (unwrap (read-u32be buffer 2)))
           (timestamp-echo (unwrap (read-u32be buffer 2)))
           (elapsed-time (unwrap (read-u32be buffer 2)))
           (data-checksum (unwrap (read-u32be buffer 2)))
           (confirm (unwrap (read-u8 buffer 2)))
           (dstport (unwrap (read-u16be buffer 2)))
           (port (unwrap (read-u16be buffer 2)))
           (join (unwrap (read-u8 buffer 3)))
           (join-id (unwrap (read-u8 buffer 4)))
           (join-token (unwrap (read-u32be buffer 4)))
           (join-nonce (unwrap (read-u32be buffer 4)))
           (stream (unwrap (read-u32be buffer 4)))
           (data-offset (unwrap (read-u8 buffer 4)))
           (key-type (unwrap (read-u8 buffer 5)))
           (key-key (unwrap (slice buffer 5 1)))
           (ccval (unwrap (read-u8 buffer 5)))
           (cscov (unwrap (read-u8 buffer 5)))
           (hmac-sha (unwrap (slice buffer 7 20)))
           (hmac (unwrap (read-u8 buffer 7)))
           (rtt (unwrap (read-u8 buffer 7)))
           (rtt-type (unwrap (read-u8 buffer 8)))
           (rtt-value (unwrap (read-u32be buffer 8)))
           (rtt-age (unwrap (read-u32be buffer 8)))
           (addaddr (unwrap (read-u8 buffer 8)))
           (res1 (unwrap (read-u8 buffer 8)))
           (x (unwrap (read-u8 buffer 8)))
           (addr-dec (unwrap (read-u32be buffer 9)))
           (addrport (unwrap (read-u16be buffer 9)))
           (addr-hex (unwrap (slice buffer 9 16)))
           (res2 (unwrap (read-u8 buffer 9)))
           (addrid (unwrap (read-u8 buffer 10)))
           (removeaddr (unwrap (read-u16be buffer 10)))
           (prio (unwrap (read-u8 buffer 10)))
           (seq-abs (unwrap (read-u64be buffer 10)))
           (prio-value (unwrap (read-u8 buffer 11)))
           (close (unwrap (read-u8 buffer 11)))
           (close-key (unwrap (read-u64be buffer 12)))
           (option-data (unwrap (slice buffer 12 1)))
           (ccid3-loss-event-rate (unwrap (read-u32be buffer 12)))
           (ccid3-loss-intervals (unwrap (slice buffer 12 1)))
           (option-reserved (unwrap (slice buffer 12 1)))
           (ccid-option-data (unwrap (slice buffer 12 1)))
           (option-unknown (unwrap (slice buffer 12 1)))
           (seq (unwrap (read-u64be buffer 16)))
           (data1 (unwrap (read-u8 buffer 55)))
           (data2 (unwrap (read-u8 buffer 55)))
           (data3 (unwrap (read-u8 buffer 55)))
           (ack-res (unwrap (read-u16be buffer 59)))
           (ack (unwrap (read-u64be buffer 59)))
           (ack-abs (unwrap (read-u64be buffer 59)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'srcport (list (cons 'raw srcport) (cons 'formatted (fmt-port srcport))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        (cons 'mandatory (list (cons 'raw mandatory) (cons 'formatted (fmt-bytes mandatory))))
        (cons 'slow-receiver (list (cons 'raw slow-receiver) (cons 'formatted (fmt-bytes slow-receiver))))
        (cons 'init-cookie (list (cons 'raw init-cookie) (cons 'formatted (fmt-bytes init-cookie))))
        (cons 'ndp-count (list (cons 'raw ndp-count) (cons 'formatted (number->string ndp-count))))
        (cons 'ack-vector-nonce-0 (list (cons 'raw ack-vector-nonce-0) (cons 'formatted (fmt-bytes ack-vector-nonce-0))))
        (cons 'ack-vector-nonce-1 (list (cons 'raw ack-vector-nonce-1) (cons 'formatted (fmt-bytes ack-vector-nonce-1))))
        (cons 'data-dropped (list (cons 'raw data-dropped) (cons 'formatted (fmt-bytes data-dropped))))
        (cons 'timestamp (list (cons 'raw timestamp) (cons 'formatted (number->string timestamp))))
        (cons 'timestamp-echo (list (cons 'raw timestamp-echo) (cons 'formatted (number->string timestamp-echo))))
        (cons 'elapsed-time (list (cons 'raw elapsed-time) (cons 'formatted (number->string elapsed-time))))
        (cons 'data-checksum (list (cons 'raw data-checksum) (cons 'formatted (fmt-hex data-checksum))))
        (cons 'confirm (list (cons 'raw confirm) (cons 'formatted (number->string confirm))))
        (cons 'dstport (list (cons 'raw dstport) (cons 'formatted (fmt-port dstport))))
        (cons 'port (list (cons 'raw port) (cons 'formatted (fmt-port port))))
        (cons 'join (list (cons 'raw join) (cons 'formatted (number->string join))))
        (cons 'join-id (list (cons 'raw join-id) (cons 'formatted (number->string join-id))))
        (cons 'join-token (list (cons 'raw join-token) (cons 'formatted (fmt-hex join-token))))
        (cons 'join-nonce (list (cons 'raw join-nonce) (cons 'formatted (fmt-hex join-nonce))))
        (cons 'stream (list (cons 'raw stream) (cons 'formatted (number->string stream))))
        (cons 'data-offset (list (cons 'raw data-offset) (cons 'formatted (number->string data-offset))))
        (cons 'key-type (list (cons 'raw key-type) (cons 'formatted (number->string key-type))))
        (cons 'key-key (list (cons 'raw key-key) (cons 'formatted (fmt-bytes key-key))))
        (cons 'ccval (list (cons 'raw ccval) (cons 'formatted (number->string ccval))))
        (cons 'cscov (list (cons 'raw cscov) (cons 'formatted (number->string cscov))))
        (cons 'hmac-sha (list (cons 'raw hmac-sha) (cons 'formatted (fmt-bytes hmac-sha))))
        (cons 'hmac (list (cons 'raw hmac) (cons 'formatted (number->string hmac))))
        (cons 'rtt (list (cons 'raw rtt) (cons 'formatted (number->string rtt))))
        (cons 'rtt-type (list (cons 'raw rtt-type) (cons 'formatted (number->string rtt-type))))
        (cons 'rtt-value (list (cons 'raw rtt-value) (cons 'formatted (number->string rtt-value))))
        (cons 'rtt-age (list (cons 'raw rtt-age) (cons 'formatted (number->string rtt-age))))
        (cons 'addaddr (list (cons 'raw addaddr) (cons 'formatted (number->string addaddr))))
        (cons 'res1 (list (cons 'raw res1) (cons 'formatted (fmt-hex res1))))
        (cons 'x (list (cons 'raw x) (cons 'formatted (number->string x))))
        (cons 'addr-dec (list (cons 'raw addr-dec) (cons 'formatted (fmt-ipv4 addr-dec))))
        (cons 'addrport (list (cons 'raw addrport) (cons 'formatted (number->string addrport))))
        (cons 'addr-hex (list (cons 'raw addr-hex) (cons 'formatted (fmt-ipv6-address addr-hex))))
        (cons 'res2 (list (cons 'raw res2) (cons 'formatted (fmt-hex res2))))
        (cons 'addrid (list (cons 'raw addrid) (cons 'formatted (number->string addrid))))
        (cons 'removeaddr (list (cons 'raw removeaddr) (cons 'formatted (number->string removeaddr))))
        (cons 'prio (list (cons 'raw prio) (cons 'formatted (number->string prio))))
        (cons 'seq-abs (list (cons 'raw seq-abs) (cons 'formatted (number->string seq-abs))))
        (cons 'prio-value (list (cons 'raw prio-value) (cons 'formatted (number->string prio-value))))
        (cons 'close (list (cons 'raw close) (cons 'formatted (number->string close))))
        (cons 'close-key (list (cons 'raw close-key) (cons 'formatted (fmt-hex close-key))))
        (cons 'option-data (list (cons 'raw option-data) (cons 'formatted (fmt-bytes option-data))))
        (cons 'ccid3-loss-event-rate (list (cons 'raw ccid3-loss-event-rate) (cons 'formatted (number->string ccid3-loss-event-rate))))
        (cons 'ccid3-loss-intervals (list (cons 'raw ccid3-loss-intervals) (cons 'formatted (fmt-bytes ccid3-loss-intervals))))
        (cons 'option-reserved (list (cons 'raw option-reserved) (cons 'formatted (fmt-bytes option-reserved))))
        (cons 'ccid-option-data (list (cons 'raw ccid-option-data) (cons 'formatted (fmt-bytes ccid-option-data))))
        (cons 'option-unknown (list (cons 'raw option-unknown) (cons 'formatted (fmt-bytes option-unknown))))
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (number->string seq))))
        (cons 'data1 (list (cons 'raw data1) (cons 'formatted (number->string data1))))
        (cons 'data2 (list (cons 'raw data2) (cons 'formatted (number->string data2))))
        (cons 'data3 (list (cons 'raw data3) (cons 'formatted (number->string data3))))
        (cons 'ack-res (list (cons 'raw ack-res) (cons 'formatted (fmt-hex ack-res))))
        (cons 'ack (list (cons 'raw ack) (cons 'formatted (number->string ack))))
        (cons 'ack-abs (list (cons 'raw ack-abs) (cons 'formatted (number->string ack-abs))))
        )))

    (catch (e)
      (err (str "DCCP parse error: " e)))))

;; dissect-dccp: parse DCCP from bytevector
;; Returns (ok fields-alist) or (err message)