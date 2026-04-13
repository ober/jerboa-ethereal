;; packet-uavcan-dsdl.c
;; Routines for dissection of DSDL used in UAVCAN
;;
;; Copyright 2020-2021 NXP
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/uavcan-dsdl.ss
;; Auto-generated from wireshark/epan/dissectors/packet-uavcan_dsdl.c

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
(def (dissect-uavcan-dsdl buffer)
  "UAVCAN DSDL"
  (try
    (let* (
           (write-offset (unwrap (slice buffer 0 5)))
           (read-offset (unwrap (slice buffer 0 5)))
           (modify-overwrite-destination (unwrap (read-u8 buffer 0)))
           (modify-preserve-source (unwrap (read-u8 buffer 0)))
           (entry-index (unwrap (read-u32be buffer 0)))
           (time-synchronizedtimestamp (unwrap (slice buffer 0 7)))
           (id (unwrap (read-u16be buffer 0)))
           (uptime (unwrap (read-u32be buffer 0)))
           (getinfo-size (unwrap (slice buffer 2 5)))
           (status-code (unwrap (read-u8 buffer 6)))
           (getinfo-timestamp (unwrap (slice buffer 7 5)))
           (access-mutable (unwrap (read-u8 buffer 7)))
           (access-persistent (unwrap (read-u8 buffer 7)))
           (value-size (unwrap (read-u8 buffer 9)))
           (primitive-array-Integer64 (unwrap (read-u64be buffer 10)))
           (getinfo-is-writeable (unwrap (read-u8 buffer 13)))
           (getinfo-is-readable (unwrap (read-u8 buffer 13)))
           (getinfo-is-link (unwrap (read-u8 buffer 13)))
           (getinfo-is-file-not-directory (unwrap (read-u8 buffer 13)))
           (primitive-array-Integer32 (unwrap (read-u32be buffer 18)))
           (primitive-array-Integer16 (unwrap (read-u16be buffer 22)))
           (primitive-array-Integer8 (unwrap (read-u8 buffer 24)))
           (primitive-array-Natural64 (unwrap (read-u64be buffer 25)))
           (primitive-array-Natural32 (unwrap (read-u32be buffer 33)))
           (primitive-array-Natural16 (unwrap (read-u16be buffer 37)))
           (primitive-array-Natural8 (unwrap (read-u8 buffer 39)))
           (primitive-array-Real64 (unwrap (read-u64be buffer 40)))
           (primitive-array-Real32 (unwrap (read-u32be buffer 48)))
           )

      (ok (list
        (cons 'write-offset (list (cons 'raw write-offset) (cons 'formatted (number->string write-offset))))
        (cons 'read-offset (list (cons 'raw read-offset) (cons 'formatted (number->string read-offset))))
        (cons 'modify-overwrite-destination (list (cons 'raw modify-overwrite-destination) (cons 'formatted (number->string modify-overwrite-destination))))
        (cons 'modify-preserve-source (list (cons 'raw modify-preserve-source) (cons 'formatted (number->string modify-preserve-source))))
        (cons 'entry-index (list (cons 'raw entry-index) (cons 'formatted (number->string entry-index))))
        (cons 'time-synchronizedtimestamp (list (cons 'raw time-synchronizedtimestamp) (cons 'formatted (number->string time-synchronizedtimestamp))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'uptime (list (cons 'raw uptime) (cons 'formatted (number->string uptime))))
        (cons 'getinfo-size (list (cons 'raw getinfo-size) (cons 'formatted (number->string getinfo-size))))
        (cons 'status-code (list (cons 'raw status-code) (cons 'formatted (number->string status-code))))
        (cons 'getinfo-timestamp (list (cons 'raw getinfo-timestamp) (cons 'formatted (number->string getinfo-timestamp))))
        (cons 'access-mutable (list (cons 'raw access-mutable) (cons 'formatted (number->string access-mutable))))
        (cons 'access-persistent (list (cons 'raw access-persistent) (cons 'formatted (number->string access-persistent))))
        (cons 'value-size (list (cons 'raw value-size) (cons 'formatted (number->string value-size))))
        (cons 'primitive-array-Integer64 (list (cons 'raw primitive-array-Integer64) (cons 'formatted (number->string primitive-array-Integer64))))
        (cons 'getinfo-is-writeable (list (cons 'raw getinfo-is-writeable) (cons 'formatted (number->string getinfo-is-writeable))))
        (cons 'getinfo-is-readable (list (cons 'raw getinfo-is-readable) (cons 'formatted (number->string getinfo-is-readable))))
        (cons 'getinfo-is-link (list (cons 'raw getinfo-is-link) (cons 'formatted (number->string getinfo-is-link))))
        (cons 'getinfo-is-file-not-directory (list (cons 'raw getinfo-is-file-not-directory) (cons 'formatted (number->string getinfo-is-file-not-directory))))
        (cons 'primitive-array-Integer32 (list (cons 'raw primitive-array-Integer32) (cons 'formatted (number->string primitive-array-Integer32))))
        (cons 'primitive-array-Integer16 (list (cons 'raw primitive-array-Integer16) (cons 'formatted (number->string primitive-array-Integer16))))
        (cons 'primitive-array-Integer8 (list (cons 'raw primitive-array-Integer8) (cons 'formatted (number->string primitive-array-Integer8))))
        (cons 'primitive-array-Natural64 (list (cons 'raw primitive-array-Natural64) (cons 'formatted (number->string primitive-array-Natural64))))
        (cons 'primitive-array-Natural32 (list (cons 'raw primitive-array-Natural32) (cons 'formatted (number->string primitive-array-Natural32))))
        (cons 'primitive-array-Natural16 (list (cons 'raw primitive-array-Natural16) (cons 'formatted (number->string primitive-array-Natural16))))
        (cons 'primitive-array-Natural8 (list (cons 'raw primitive-array-Natural8) (cons 'formatted (number->string primitive-array-Natural8))))
        (cons 'primitive-array-Real64 (list (cons 'raw primitive-array-Real64) (cons 'formatted (number->string primitive-array-Real64))))
        (cons 'primitive-array-Real32 (list (cons 'raw primitive-array-Real32) (cons 'formatted (number->string primitive-array-Real32))))
        )))

    (catch (e)
      (err (str "UAVCAN-DSDL parse error: " e)))))

;; dissect-uavcan-dsdl: parse UAVCAN-DSDL from bytevector
;; Returns (ok fields-alist) or (err message)