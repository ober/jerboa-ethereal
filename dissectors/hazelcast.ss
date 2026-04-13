;;
;; packet-hazelcast.c
;; dissector for hazelcast wire protocol
;; Paul Erkkila <paul.erkkila@level3.com>
;;
;; Website: http://www.hazelcast.com/
;;
;; reversed from this code:
;; http://code.google.com/p/hazelcast/source/browse/branches/1.9.4/hazelcast/src/main/java/com/hazelcast/nio/Packet.java
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;;

;; jerboa-ethereal/dissectors/hazelcast.ss
;; Auto-generated from wireshark/epan/dissectors/packet-hazelcast.c

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
(def (dissect-hazelcast buffer)
  "Hazelcast Wire Protocol"
  (try
    (let* (
           (headerKeyLength (unwrap (read-u32be buffer 4)))
           (headerValueLength (unwrap (read-u32be buffer 8)))
           (headerVersion (unwrap (read-u8 buffer 12)))
           (blockID (unwrap (read-u32be buffer 14)))
           (threadID (unwrap (read-u32be buffer 18)))
           (flags (unwrap (read-u8 buffer 22)))
           (flags-lockCount (unwrap (read-u8 buffer 22)))
           (flags-timeout (unwrap (read-u8 buffer 22)))
           (flags-ttl (unwrap (read-u8 buffer 22)))
           (flags-txn (unwrap (read-u8 buffer 22)))
           (flags-longValue (unwrap (read-u8 buffer 22)))
           (flags-version (unwrap (read-u8 buffer 22)))
           (flags-client (unwrap (read-u8 buffer 22)))
           (flags-lockAddrNull (unwrap (read-u8 buffer 22)))
           (lockCount (unwrap (read-u32be buffer 23)))
           (timeout (unwrap (read-u64be buffer 27)))
           (ttl (unwrap (read-u64be buffer 35)))
           (txnID (unwrap (read-u64be buffer 43)))
           (longValue (unwrap (read-u64be buffer 51)))
           (version (unwrap (read-u64be buffer 59)))
           (lockAddrIP (unwrap (read-u32be buffer 67)))
           (lockAddrPort (unwrap (read-u32be buffer 71)))
           (callID (unwrap (read-u64be buffer 75)))
           (nameLength (unwrap (read-u32be buffer 84)))
           (name (unwrap (slice buffer 88 1)))
           (indexCount (unwrap (read-u8 buffer 88)))
           (keyPartitionHash (unwrap (read-u32be buffer 89)))
           (valuePartitionHash (unwrap (read-u32be buffer 93)))
           (keys (unwrap (slice buffer 97 1)))
           (values (unwrap (slice buffer 97 1)))
           (headerLength (unwrap (read-u32be buffer 98)))
           )

      (ok (list
        (cons 'headerKeyLength (list (cons 'raw headerKeyLength) (cons 'formatted (number->string headerKeyLength))))
        (cons 'headerValueLength (list (cons 'raw headerValueLength) (cons 'formatted (number->string headerValueLength))))
        (cons 'headerVersion (list (cons 'raw headerVersion) (cons 'formatted (number->string headerVersion))))
        (cons 'blockID (list (cons 'raw blockID) (cons 'formatted (fmt-hex blockID))))
        (cons 'threadID (list (cons 'raw threadID) (cons 'formatted (number->string threadID))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flags-lockCount (list (cons 'raw flags-lockCount) (cons 'formatted (number->string flags-lockCount))))
        (cons 'flags-timeout (list (cons 'raw flags-timeout) (cons 'formatted (number->string flags-timeout))))
        (cons 'flags-ttl (list (cons 'raw flags-ttl) (cons 'formatted (number->string flags-ttl))))
        (cons 'flags-txn (list (cons 'raw flags-txn) (cons 'formatted (number->string flags-txn))))
        (cons 'flags-longValue (list (cons 'raw flags-longValue) (cons 'formatted (number->string flags-longValue))))
        (cons 'flags-version (list (cons 'raw flags-version) (cons 'formatted (number->string flags-version))))
        (cons 'flags-client (list (cons 'raw flags-client) (cons 'formatted (number->string flags-client))))
        (cons 'flags-lockAddrNull (list (cons 'raw flags-lockAddrNull) (cons 'formatted (number->string flags-lockAddrNull))))
        (cons 'lockCount (list (cons 'raw lockCount) (cons 'formatted (number->string lockCount))))
        (cons 'timeout (list (cons 'raw timeout) (cons 'formatted (number->string timeout))))
        (cons 'ttl (list (cons 'raw ttl) (cons 'formatted (number->string ttl))))
        (cons 'txnID (list (cons 'raw txnID) (cons 'formatted (number->string txnID))))
        (cons 'longValue (list (cons 'raw longValue) (cons 'formatted (number->string longValue))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'lockAddrIP (list (cons 'raw lockAddrIP) (cons 'formatted (fmt-ipv4 lockAddrIP))))
        (cons 'lockAddrPort (list (cons 'raw lockAddrPort) (cons 'formatted (number->string lockAddrPort))))
        (cons 'callID (list (cons 'raw callID) (cons 'formatted (number->string callID))))
        (cons 'nameLength (list (cons 'raw nameLength) (cons 'formatted (number->string nameLength))))
        (cons 'name (list (cons 'raw name) (cons 'formatted (utf8->string name))))
        (cons 'indexCount (list (cons 'raw indexCount) (cons 'formatted (number->string indexCount))))
        (cons 'keyPartitionHash (list (cons 'raw keyPartitionHash) (cons 'formatted (fmt-hex keyPartitionHash))))
        (cons 'valuePartitionHash (list (cons 'raw valuePartitionHash) (cons 'formatted (fmt-hex valuePartitionHash))))
        (cons 'keys (list (cons 'raw keys) (cons 'formatted (fmt-bytes keys))))
        (cons 'values (list (cons 'raw values) (cons 'formatted (fmt-bytes values))))
        (cons 'headerLength (list (cons 'raw headerLength) (cons 'formatted (number->string headerLength))))
        )))

    (catch (e)
      (err (str "HAZELCAST parse error: " e)))))

;; dissect-hazelcast: parse HAZELCAST from bytevector
;; Returns (ok fields-alist) or (err message)