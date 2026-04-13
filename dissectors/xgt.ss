;; packet-xgt.c
;; Routines for XGT (LS ELECTRIC PLC) protocol packet disassembly
;;
;; Copyright 2025, Gihyeon Ryu and the SLiMe team (BoB 14th)
;;
;; XGT is a proprietary protocol used by LS ELECTRIC (formerly LS Industrial Systems)
;; for communication with their XGT series PLCs over Ethernet.
;;
;; Protocol specifications based on:
;; "XGT FEnet I/F Module Protocol Specification" (2005.03.30)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/xgt.ss
;; Auto-generated from wireshark/epan/dissectors/packet-xgt.c

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
(def (dissect-xgt buffer)
  "XGT FEnet Protocol"
  (try
    (let* (
           (reserved1 (unwrap (read-u16be buffer 8)))
           (plc-info (unwrap (read-u16be buffer 10)))
           (plc-info-redundancy (unwrap (read-u8 buffer 10)))
           (plc-info-cpu-error (unwrap (read-u8 buffer 10)))
           (invoke-id (unwrap (read-u16be buffer 14)))
           (length (unwrap (read-u16be buffer 16)))
           (fenet-position (unwrap (read-u8 buffer 18)))
           (fenet-slot (unwrap (read-u8 buffer 18)))
           (fenet-base (unwrap (read-u8 buffer 18)))
           (reserved2 (unwrap (read-u8 buffer 19)))
           (variable-length (unwrap (read-u16be buffer 20)))
           (variable-name (unwrap (slice buffer 22 1)))
           (byte-count (unwrap (read-u16be buffer 24)))
           (data-value-uint64 (unwrap (read-u64be buffer 26)))
           (data-value-uint8 (unwrap (read-u8 buffer 26)))
           (data-value-uint16 (unwrap (read-u16be buffer 26)))
           (data-value-uint32 (unwrap (read-u32be buffer 26)))
           (data (unwrap (slice buffer 26 1)))
           (reserved-area (unwrap (read-u16be buffer 30)))
           (data-length (unwrap (read-u16be buffer 36)))
           (status-data (unwrap (slice buffer 38 24)))
           (slot-info (unwrap (read-u32be buffer 38)))
           (cpu-type (unwrap (read-u16be buffer 42)))
           (ver-num (unwrap (read-u16be buffer 44)))
           (sys-state (unwrap (read-u32be buffer 46)))
           (padt-cnf (unwrap (read-u16be buffer 50)))
           (cnf-er (unwrap (read-u32be buffer 52)))
           (cnf-war (unwrap (read-u32be buffer 56)))
           (variable-count (unwrap (read-u16be buffer 62)))
           (block-count (unwrap (read-u16be buffer 62)))
           (company-id (unwrap (slice buffer 64 8)))
           )

      (ok (list
        (cons 'reserved1 (list (cons 'raw reserved1) (cons 'formatted (fmt-hex reserved1))))
        (cons 'plc-info (list (cons 'raw plc-info) (cons 'formatted (fmt-hex plc-info))))
        (cons 'plc-info-redundancy (list (cons 'raw plc-info-redundancy) (cons 'formatted (if (= plc-info-redundancy 0) "Master" "Slave"))))
        (cons 'plc-info-cpu-error (list (cons 'raw plc-info-cpu-error) (cons 'formatted (if (= plc-info-cpu-error 0) "Normal" "Error"))))
        (cons 'invoke-id (list (cons 'raw invoke-id) (cons 'formatted (number->string invoke-id))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'fenet-position (list (cons 'raw fenet-position) (cons 'formatted (fmt-hex fenet-position))))
        (cons 'fenet-slot (list (cons 'raw fenet-slot) (cons 'formatted (number->string fenet-slot))))
        (cons 'fenet-base (list (cons 'raw fenet-base) (cons 'formatted (number->string fenet-base))))
        (cons 'reserved2 (list (cons 'raw reserved2) (cons 'formatted (fmt-hex reserved2))))
        (cons 'variable-length (list (cons 'raw variable-length) (cons 'formatted (number->string variable-length))))
        (cons 'variable-name (list (cons 'raw variable-name) (cons 'formatted (utf8->string variable-name))))
        (cons 'byte-count (list (cons 'raw byte-count) (cons 'formatted (number->string byte-count))))
        (cons 'data-value-uint64 (list (cons 'raw data-value-uint64) (cons 'formatted (number->string data-value-uint64))))
        (cons 'data-value-uint8 (list (cons 'raw data-value-uint8) (cons 'formatted (number->string data-value-uint8))))
        (cons 'data-value-uint16 (list (cons 'raw data-value-uint16) (cons 'formatted (number->string data-value-uint16))))
        (cons 'data-value-uint32 (list (cons 'raw data-value-uint32) (cons 'formatted (number->string data-value-uint32))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'reserved-area (list (cons 'raw reserved-area) (cons 'formatted (fmt-hex reserved-area))))
        (cons 'data-length (list (cons 'raw data-length) (cons 'formatted (number->string data-length))))
        (cons 'status-data (list (cons 'raw status-data) (cons 'formatted (fmt-bytes status-data))))
        (cons 'slot-info (list (cons 'raw slot-info) (cons 'formatted (fmt-hex slot-info))))
        (cons 'cpu-type (list (cons 'raw cpu-type) (cons 'formatted (fmt-hex cpu-type))))
        (cons 'ver-num (list (cons 'raw ver-num) (cons 'formatted (fmt-hex ver-num))))
        (cons 'sys-state (list (cons 'raw sys-state) (cons 'formatted (fmt-hex sys-state))))
        (cons 'padt-cnf (list (cons 'raw padt-cnf) (cons 'formatted (fmt-hex padt-cnf))))
        (cons 'cnf-er (list (cons 'raw cnf-er) (cons 'formatted (fmt-hex cnf-er))))
        (cons 'cnf-war (list (cons 'raw cnf-war) (cons 'formatted (fmt-hex cnf-war))))
        (cons 'variable-count (list (cons 'raw variable-count) (cons 'formatted (number->string variable-count))))
        (cons 'block-count (list (cons 'raw block-count) (cons 'formatted (number->string block-count))))
        (cons 'company-id (list (cons 'raw company-id) (cons 'formatted (utf8->string company-id))))
        )))

    (catch (e)
      (err (str "XGT parse error: " e)))))

;; dissect-xgt: parse XGT from bytevector
;; Returns (ok fields-alist) or (err message)