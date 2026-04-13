;; packet-catapult-dct2000.c
;; Routines for Catapult DCT2000 packet stub header disassembly
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/catapult-dct2000.ss
;; Auto-generated from wireshark/epan/dissectors/packet-catapult_dct2000.c

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
(def (dissect-catapult-dct2000 buffer)
  "Catapult DCT2000 packet"
  (try
    (let* (
           (dct2000-dissected-length (unwrap (read-u16be buffer 0)))
           (dct2000-rawtraffic-interface (unwrap (read-u8 buffer 0)))
           (dct2000-context (unwrap (slice buffer 0 1)))
           (dct2000-port-number (unwrap (read-u8 buffer 0)))
           (dct2000-timestamp (unwrap (read-u64be buffer 0)))
           (dct2000-protocol (unwrap (slice buffer 0 1)))
           (dct2000-variant (unwrap (slice buffer 0 1)))
           (dct2000-outhdr (unwrap (slice buffer 0 1)))
           (dct2000-ueid (unwrap (read-u16be buffer 24)))
           (dct2000-comment (unwrap (slice buffer 30 1)))
           (dct2000-sprint (unwrap (slice buffer 30 1)))
           (dct2000-unparsed-data (unwrap (slice buffer 30 1)))
           (dct2000-ccch-id (unwrap (read-u8 buffer 56)))
           (dct2000-buffer-occupancy (unwrap (read-u8 buffer 56)))
           (dct2000-pdu-size (unwrap (read-u16be buffer 56)))
           (dct2000-tx-priority (unwrap (read-u8 buffer 56)))
           (dct2000-last-in-seg-set (unwrap (read-u8 buffer 56)))
           (dct2000-rx-timing-deviation (unwrap (read-u32be buffer 56)))
           (dct2000-no-padding-bits (unwrap (read-u8 buffer 56)))
           (dct2000-srbid (unwrap (read-u8 buffer 58)))
           (dct2000-drbid (unwrap (read-u8 buffer 58)))
           (dct2000-carrier-id (unwrap (read-u8 buffer 64)))
           (dct2000-cell-group (unwrap (read-u8 buffer 68)))
           (dct2000-ciphering-key (unwrap (slice buffer 72 16)))
           (dct2000-integrity-key (unwrap (slice buffer 92 16)))
           (dct2000-lte-ccpri-status (unwrap (read-u8 buffer 112)))
           (dct2000-lte-ccpri-channel (unwrap (read-u8 buffer 112)))
           (dct2000-cellid (unwrap (read-u16be buffer 116)))
           (dct2000-rlc-mui (unwrap (read-u16be buffer 120)))
           (dct2000-rlc-cnf (unwrap (read-u8 buffer 122)))
           (dct2000-rlc-discard-req (unwrap (read-u8 buffer 122)))
           (dct2000-tty-line (unwrap (slice buffer 122 1)))
           )

      (ok (list
        (cons 'dct2000-dissected-length (list (cons 'raw dct2000-dissected-length) (cons 'formatted (number->string dct2000-dissected-length))))
        (cons 'dct2000-rawtraffic-interface (list (cons 'raw dct2000-rawtraffic-interface) (cons 'formatted (number->string dct2000-rawtraffic-interface))))
        (cons 'dct2000-context (list (cons 'raw dct2000-context) (cons 'formatted (utf8->string dct2000-context))))
        (cons 'dct2000-port-number (list (cons 'raw dct2000-port-number) (cons 'formatted (number->string dct2000-port-number))))
        (cons 'dct2000-timestamp (list (cons 'raw dct2000-timestamp) (cons 'formatted (number->string dct2000-timestamp))))
        (cons 'dct2000-protocol (list (cons 'raw dct2000-protocol) (cons 'formatted (utf8->string dct2000-protocol))))
        (cons 'dct2000-variant (list (cons 'raw dct2000-variant) (cons 'formatted (utf8->string dct2000-variant))))
        (cons 'dct2000-outhdr (list (cons 'raw dct2000-outhdr) (cons 'formatted (utf8->string dct2000-outhdr))))
        (cons 'dct2000-ueid (list (cons 'raw dct2000-ueid) (cons 'formatted (number->string dct2000-ueid))))
        (cons 'dct2000-comment (list (cons 'raw dct2000-comment) (cons 'formatted (utf8->string dct2000-comment))))
        (cons 'dct2000-sprint (list (cons 'raw dct2000-sprint) (cons 'formatted (utf8->string dct2000-sprint))))
        (cons 'dct2000-unparsed-data (list (cons 'raw dct2000-unparsed-data) (cons 'formatted (fmt-bytes dct2000-unparsed-data))))
        (cons 'dct2000-ccch-id (list (cons 'raw dct2000-ccch-id) (cons 'formatted (number->string dct2000-ccch-id))))
        (cons 'dct2000-buffer-occupancy (list (cons 'raw dct2000-buffer-occupancy) (cons 'formatted (number->string dct2000-buffer-occupancy))))
        (cons 'dct2000-pdu-size (list (cons 'raw dct2000-pdu-size) (cons 'formatted (number->string dct2000-pdu-size))))
        (cons 'dct2000-tx-priority (list (cons 'raw dct2000-tx-priority) (cons 'formatted (if (= dct2000-tx-priority 0) "False" "True"))))
        (cons 'dct2000-last-in-seg-set (list (cons 'raw dct2000-last-in-seg-set) (cons 'formatted (if (= dct2000-last-in-seg-set 0) "False" "True"))))
        (cons 'dct2000-rx-timing-deviation (list (cons 'raw dct2000-rx-timing-deviation) (cons 'formatted (number->string dct2000-rx-timing-deviation))))
        (cons 'dct2000-no-padding-bits (list (cons 'raw dct2000-no-padding-bits) (cons 'formatted (number->string dct2000-no-padding-bits))))
        (cons 'dct2000-srbid (list (cons 'raw dct2000-srbid) (cons 'formatted (number->string dct2000-srbid))))
        (cons 'dct2000-drbid (list (cons 'raw dct2000-drbid) (cons 'formatted (number->string dct2000-drbid))))
        (cons 'dct2000-carrier-id (list (cons 'raw dct2000-carrier-id) (cons 'formatted (number->string dct2000-carrier-id))))
        (cons 'dct2000-cell-group (list (cons 'raw dct2000-cell-group) (cons 'formatted (number->string dct2000-cell-group))))
        (cons 'dct2000-ciphering-key (list (cons 'raw dct2000-ciphering-key) (cons 'formatted (fmt-bytes dct2000-ciphering-key))))
        (cons 'dct2000-integrity-key (list (cons 'raw dct2000-integrity-key) (cons 'formatted (fmt-bytes dct2000-integrity-key))))
        (cons 'dct2000-lte-ccpri-status (list (cons 'raw dct2000-lte-ccpri-status) (cons 'formatted (if (= dct2000-lte-ccpri-status 0) "False" "True"))))
        (cons 'dct2000-lte-ccpri-channel (list (cons 'raw dct2000-lte-ccpri-channel) (cons 'formatted (number->string dct2000-lte-ccpri-channel))))
        (cons 'dct2000-cellid (list (cons 'raw dct2000-cellid) (cons 'formatted (number->string dct2000-cellid))))
        (cons 'dct2000-rlc-mui (list (cons 'raw dct2000-rlc-mui) (cons 'formatted (number->string dct2000-rlc-mui))))
        (cons 'dct2000-rlc-cnf (list (cons 'raw dct2000-rlc-cnf) (cons 'formatted (if (= dct2000-rlc-cnf 0) "False" "True"))))
        (cons 'dct2000-rlc-discard-req (list (cons 'raw dct2000-rlc-discard-req) (cons 'formatted (if (= dct2000-rlc-discard-req 0) "False" "True"))))
        (cons 'dct2000-tty-line (list (cons 'raw dct2000-tty-line) (cons 'formatted (utf8->string dct2000-tty-line))))
        )))

    (catch (e)
      (err (str "CATAPULT-DCT2000 parse error: " e)))))

;; dissect-catapult-dct2000: parse CATAPULT-DCT2000 from bytevector
;; Returns (ok fields-alist) or (err message)