;; packet-ctdb.c
;; Routines for CTDB (Cluster TDB) dissection
;; Copyright 2007, Ronnie Sahlberg
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ctdb.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ctdb.c

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
(def (dissect-ctdb buffer)
  "Cluster TDB"
  (try
    (let* (
           (keyhash (unwrap (read-u32be buffer 0)))
           (recmaster (unwrap (read-u32be buffer 0)))
           (num-nodes (unwrap (read-u32be buffer 0)))
           (length (unwrap (read-u32be buffer 0)))
           (vnn (unwrap (read-u32be buffer 4)))
           (magic (unwrap (read-u32be buffer 4)))
           (node-flags (unwrap (read-u32be buffer 8)))
           (version (unwrap (read-u32be buffer 8)))
           (node-ip (unwrap (read-u32be buffer 12)))
           (generation (unwrap (read-u32be buffer 12)))
           (dst (unwrap (read-u32be buffer 20)))
           (src (unwrap (read-u32be buffer 24)))
           (pid (unwrap (read-u32be buffer 28)))
           (id (unwrap (read-u32be buffer 28)))
           (process-exists (unwrap (read-u8 buffer 32)))
           (key (unwrap (slice buffer 32 1)))
           (rsn (unwrap (read-u64be buffer 64)))
           (dmaster (unwrap (read-u32be buffer 72)))
           (srvid (unwrap (read-u64be buffer 88)))
           (clientid (unwrap (read-u32be buffer 96)))
           (ctrl-flags (unwrap (read-u32be buffer 100)))
           (status (unwrap (read-u32be buffer 108)))
           (errorlen (unwrap (read-u32be buffer 116)))
           (error (unwrap (slice buffer 120 1)))
           (flags-immediate (unwrap (read-u8 buffer 120)))
           (callid (unwrap (read-u32be buffer 128)))
           (hopcount (unwrap (read-u32be buffer 132)))
           (keylen (unwrap (read-u32be buffer 136)))
           (datalen (unwrap (read-u32be buffer 140)))
           (data (unwrap (slice buffer 144 1)))
           )

      (ok (list
        (cons 'keyhash (list (cons 'raw keyhash) (cons 'formatted (fmt-hex keyhash))))
        (cons 'recmaster (list (cons 'raw recmaster) (cons 'formatted (number->string recmaster))))
        (cons 'num-nodes (list (cons 'raw num-nodes) (cons 'formatted (number->string num-nodes))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'vnn (list (cons 'raw vnn) (cons 'formatted (number->string vnn))))
        (cons 'magic (list (cons 'raw magic) (cons 'formatted (fmt-hex magic))))
        (cons 'node-flags (list (cons 'raw node-flags) (cons 'formatted (fmt-hex node-flags))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'node-ip (list (cons 'raw node-ip) (cons 'formatted (fmt-ipv4 node-ip))))
        (cons 'generation (list (cons 'raw generation) (cons 'formatted (number->string generation))))
        (cons 'dst (list (cons 'raw dst) (cons 'formatted (number->string dst))))
        (cons 'src (list (cons 'raw src) (cons 'formatted (number->string src))))
        (cons 'pid (list (cons 'raw pid) (cons 'formatted (number->string pid))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'process-exists (list (cons 'raw process-exists) (cons 'formatted (if (= process-exists 0) "Process Exists" "Process does NOT exist"))))
        (cons 'key (list (cons 'raw key) (cons 'formatted (fmt-bytes key))))
        (cons 'rsn (list (cons 'raw rsn) (cons 'formatted (fmt-hex rsn))))
        (cons 'dmaster (list (cons 'raw dmaster) (cons 'formatted (number->string dmaster))))
        (cons 'srvid (list (cons 'raw srvid) (cons 'formatted (fmt-hex srvid))))
        (cons 'clientid (list (cons 'raw clientid) (cons 'formatted (fmt-hex clientid))))
        (cons 'ctrl-flags (list (cons 'raw ctrl-flags) (cons 'formatted (fmt-hex ctrl-flags))))
        (cons 'status (list (cons 'raw status) (cons 'formatted (number->string status))))
        (cons 'errorlen (list (cons 'raw errorlen) (cons 'formatted (number->string errorlen))))
        (cons 'error (list (cons 'raw error) (cons 'formatted (fmt-bytes error))))
        (cons 'flags-immediate (list (cons 'raw flags-immediate) (cons 'formatted (if (= flags-immediate 0) "Dmaster migration is not required" "DMASTER for the record must IMMEDIATELY be migrated to the caller"))))
        (cons 'callid (list (cons 'raw callid) (cons 'formatted (number->string callid))))
        (cons 'hopcount (list (cons 'raw hopcount) (cons 'formatted (number->string hopcount))))
        (cons 'keylen (list (cons 'raw keylen) (cons 'formatted (number->string keylen))))
        (cons 'datalen (list (cons 'raw datalen) (cons 'formatted (number->string datalen))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        )))

    (catch (e)
      (err (str "CTDB parse error: " e)))))

;; dissect-ctdb: parse CTDB from bytevector
;; Returns (ok fields-alist) or (err message)