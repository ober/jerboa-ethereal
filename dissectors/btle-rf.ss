;; packet-btle_rf.c
;; https://www.tcpdump.org/linktypes/LINKTYPE_BLUETOOTH_LE_LL_WITH_PHDR.html
;;
;; Copyright 2014, Christopher D. Kilgour, techie at whiterocker dot com
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/btle-rf.ss
;; Auto-generated from wireshark/epan/dissectors/packet-btle_rf.c

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
(def (dissect-btle-rf buffer)
  "Bluetooth Low Energy RF Info"
  (try
    (let* (
           (rf-channel (unwrap (read-u8 buffer 0)))
           (rf-signed-byte-unused (unwrap (read-u8 buffer 1)))
           (rf-signal-dbm (unwrap (read-u8 buffer 1)))
           (rf-noise-dbm (unwrap (read-u8 buffer 2)))
           (rf-unsigned-byte-unused (unwrap (read-u8 buffer 3)))
           (rf-access-address-offenses (unwrap (read-u8 buffer 3)))
           (rf-word-unused (unwrap (read-u32be buffer 4)))
           (rf-reference-access-address (unwrap (read-u32be buffer 4)))
           (rf-flags (unwrap (read-u16le buffer 8)))
           (rf-dewhitened-flag (extract-bits rf-flags 0x0 0))
           (rf-sigpower-valid-flag (extract-bits rf-flags 0x0 0))
           (rf-noisepower-valid-flag (extract-bits rf-flags 0x0 0))
           (rf-packet-decrypted-flag (extract-bits rf-flags 0x0 0))
           (rf-ref-aa-valid-flag (extract-bits rf-flags 0x0 0))
           (rf-aa-offenses-valid-flag (extract-bits rf-flags 0x0 0))
           (rf-channel-aliased-flag (extract-bits rf-flags 0x0 0))
           (rf-crc-checked-flag (extract-bits rf-flags 0x0 0))
           (rf-crc-valid-flag (extract-bits rf-flags 0x0 0))
           (rf-mic-checked-flag (extract-bits rf-flags 0x0 0))
           (rf-mic-valid-flag (extract-bits rf-flags 0x0 0))
           )

      (ok (list
        (cons 'rf-channel (list (cons 'raw rf-channel) (cons 'formatted (number->string rf-channel))))
        (cons 'rf-signed-byte-unused (list (cons 'raw rf-signed-byte-unused) (cons 'formatted (number->string rf-signed-byte-unused))))
        (cons 'rf-signal-dbm (list (cons 'raw rf-signal-dbm) (cons 'formatted (number->string rf-signal-dbm))))
        (cons 'rf-noise-dbm (list (cons 'raw rf-noise-dbm) (cons 'formatted (number->string rf-noise-dbm))))
        (cons 'rf-unsigned-byte-unused (list (cons 'raw rf-unsigned-byte-unused) (cons 'formatted (number->string rf-unsigned-byte-unused))))
        (cons 'rf-access-address-offenses (list (cons 'raw rf-access-address-offenses) (cons 'formatted (number->string rf-access-address-offenses))))
        (cons 'rf-word-unused (list (cons 'raw rf-word-unused) (cons 'formatted (fmt-hex rf-word-unused))))
        (cons 'rf-reference-access-address (list (cons 'raw rf-reference-access-address) (cons 'formatted (fmt-hex rf-reference-access-address))))
        (cons 'rf-flags (list (cons 'raw rf-flags) (cons 'formatted (fmt-hex rf-flags))))
        (cons 'rf-dewhitened-flag (list (cons 'raw rf-dewhitened-flag) (cons 'formatted (if (= rf-dewhitened-flag 0) "Not set" "Set"))))
        (cons 'rf-sigpower-valid-flag (list (cons 'raw rf-sigpower-valid-flag) (cons 'formatted (if (= rf-sigpower-valid-flag 0) "Not set" "Set"))))
        (cons 'rf-noisepower-valid-flag (list (cons 'raw rf-noisepower-valid-flag) (cons 'formatted (if (= rf-noisepower-valid-flag 0) "Not set" "Set"))))
        (cons 'rf-packet-decrypted-flag (list (cons 'raw rf-packet-decrypted-flag) (cons 'formatted (if (= rf-packet-decrypted-flag 0) "Not set" "Set"))))
        (cons 'rf-ref-aa-valid-flag (list (cons 'raw rf-ref-aa-valid-flag) (cons 'formatted (if (= rf-ref-aa-valid-flag 0) "Not set" "Set"))))
        (cons 'rf-aa-offenses-valid-flag (list (cons 'raw rf-aa-offenses-valid-flag) (cons 'formatted (if (= rf-aa-offenses-valid-flag 0) "Not set" "Set"))))
        (cons 'rf-channel-aliased-flag (list (cons 'raw rf-channel-aliased-flag) (cons 'formatted (if (= rf-channel-aliased-flag 0) "Not set" "Set"))))
        (cons 'rf-crc-checked-flag (list (cons 'raw rf-crc-checked-flag) (cons 'formatted (if (= rf-crc-checked-flag 0) "Not set" "Set"))))
        (cons 'rf-crc-valid-flag (list (cons 'raw rf-crc-valid-flag) (cons 'formatted (if (= rf-crc-valid-flag 0) "Not set" "Set"))))
        (cons 'rf-mic-checked-flag (list (cons 'raw rf-mic-checked-flag) (cons 'formatted (if (= rf-mic-checked-flag 0) "Not set" "Set"))))
        (cons 'rf-mic-valid-flag (list (cons 'raw rf-mic-valid-flag) (cons 'formatted (if (= rf-mic-valid-flag 0) "Not set" "Set"))))
        )))

    (catch (e)
      (err (str "BTLE-RF parse error: " e)))))

;; dissect-btle-rf: parse BTLE-RF from bytevector
;; Returns (ok fields-alist) or (err message)