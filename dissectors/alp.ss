;; packet-alp.c
;; Routines for ALP dissection
;; Copyright 2020, Nick Kelsey <nickk@silicondust.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/alp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-alp.c

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
(def (dissect-alp buffer)
  "ATSC Link-Layer Protocol"
  (try
    (let* (
           (payload-configuration (unwrap (read-u8 buffer 0)))
           (header-mode (unwrap (read-u8 buffer 0)))
           (single-length (unwrap (read-u24be buffer 2)))
           (single-sif (unwrap (read-u8 buffer 4)))
           (single-hef (unwrap (read-u8 buffer 4)))
           (length (unwrap (read-u16be buffer 4)))
           (segment-sequence-number (unwrap (read-u8 buffer 6)))
           (segment-last-indicator (unwrap (read-u8 buffer 6)))
           (segment-sif (unwrap (read-u8 buffer 6)))
           (segment-hef (unwrap (read-u8 buffer 6)))
           (concat-length (unwrap (read-u24be buffer 6)))
           (concat-count (unwrap (read-u8 buffer 8)))
           (concat-sif (unwrap (read-u8 buffer 8)))
           (sid (unwrap (read-u8 buffer 8)))
           (header-extension-type (unwrap (read-u8 buffer 8)))
           (header-extension-sony-l1d-timeinfo (unwrap (read-u64be buffer 8)))
           (header-extension-sony-l1d-timeinfo-flag (unwrap (read-u64be buffer 8)))
           (header-extension-sony-l1d-timeinfo-sec (unwrap (read-u64be buffer 8)))
           (header-extension-sony-l1d-timeinfo-ms (unwrap (read-u64be buffer 8)))
           (header-extension-sony-l1d-timeinfo-us (unwrap (read-u64be buffer 8)))
           (header-extension-sony-l1d-timeinfo-ns (unwrap (read-u64be buffer 8)))
           (header-extension-sony-l1d-timeinfo-time-ns (unwrap (read-u64be buffer 8)))
           (header-extension-sony-plp-id (unwrap (read-u8 buffer 16)))
           (header-extension-sony-plp-unk (unwrap (read-u8 buffer 16)))
           (sig-info-type-extension (unwrap (read-u16be buffer 16)))
           (sig-info-version (unwrap (read-u8 buffer 18)))
           (lmt-numplp (unwrap (read-u8 buffer 18)))
           (lmt-reserved (unwrap (read-u8 buffer 18)))
           (lmt-plp-id (unwrap (read-u8 buffer 18)))
           (lmt-plp-reserved (unwrap (read-u8 buffer 18)))
           (lmt-plp-nummc (unwrap (read-u8 buffer 18)))
           (lmt-plp-mc-src-ip (unwrap (read-u32be buffer 18)))
           (lmt-plp-mc-dst-ip (unwrap (read-u32be buffer 22)))
           (lmt-plp-mc-src-port (unwrap (read-u16be buffer 26)))
           (lmt-plp-mc-dst-port (unwrap (read-u16be buffer 28)))
           (lmt-plp-mc-sid-flag (unwrap (read-u8 buffer 30)))
           (lmt-plp-mc-comp-flag (unwrap (read-u8 buffer 30)))
           (lmt-plp-mc-reserved (unwrap (read-u8 buffer 30)))
           (lmt-plp-mc-sid (unwrap (read-u8 buffer 31)))
           (lmt-plp-mc-context-id (unwrap (read-u8 buffer 32)))
           (junk (unwrap (slice buffer 33 1)))
           )

      (ok (list
        (cons 'payload-configuration (list (cons 'raw payload-configuration) (cons 'formatted (number->string payload-configuration))))
        (cons 'header-mode (list (cons 'raw header-mode) (cons 'formatted (number->string header-mode))))
        (cons 'single-length (list (cons 'raw single-length) (cons 'formatted (number->string single-length))))
        (cons 'single-sif (list (cons 'raw single-sif) (cons 'formatted (number->string single-sif))))
        (cons 'single-hef (list (cons 'raw single-hef) (cons 'formatted (number->string single-hef))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'segment-sequence-number (list (cons 'raw segment-sequence-number) (cons 'formatted (number->string segment-sequence-number))))
        (cons 'segment-last-indicator (list (cons 'raw segment-last-indicator) (cons 'formatted (number->string segment-last-indicator))))
        (cons 'segment-sif (list (cons 'raw segment-sif) (cons 'formatted (number->string segment-sif))))
        (cons 'segment-hef (list (cons 'raw segment-hef) (cons 'formatted (number->string segment-hef))))
        (cons 'concat-length (list (cons 'raw concat-length) (cons 'formatted (number->string concat-length))))
        (cons 'concat-count (list (cons 'raw concat-count) (cons 'formatted (number->string concat-count))))
        (cons 'concat-sif (list (cons 'raw concat-sif) (cons 'formatted (number->string concat-sif))))
        (cons 'sid (list (cons 'raw sid) (cons 'formatted (number->string sid))))
        (cons 'header-extension-type (list (cons 'raw header-extension-type) (cons 'formatted (fmt-hex header-extension-type))))
        (cons 'header-extension-sony-l1d-timeinfo (list (cons 'raw header-extension-sony-l1d-timeinfo) (cons 'formatted (fmt-hex header-extension-sony-l1d-timeinfo))))
        (cons 'header-extension-sony-l1d-timeinfo-flag (list (cons 'raw header-extension-sony-l1d-timeinfo-flag) (cons 'formatted (fmt-hex header-extension-sony-l1d-timeinfo-flag))))
        (cons 'header-extension-sony-l1d-timeinfo-sec (list (cons 'raw header-extension-sony-l1d-timeinfo-sec) (cons 'formatted (number->string header-extension-sony-l1d-timeinfo-sec))))
        (cons 'header-extension-sony-l1d-timeinfo-ms (list (cons 'raw header-extension-sony-l1d-timeinfo-ms) (cons 'formatted (number->string header-extension-sony-l1d-timeinfo-ms))))
        (cons 'header-extension-sony-l1d-timeinfo-us (list (cons 'raw header-extension-sony-l1d-timeinfo-us) (cons 'formatted (number->string header-extension-sony-l1d-timeinfo-us))))
        (cons 'header-extension-sony-l1d-timeinfo-ns (list (cons 'raw header-extension-sony-l1d-timeinfo-ns) (cons 'formatted (number->string header-extension-sony-l1d-timeinfo-ns))))
        (cons 'header-extension-sony-l1d-timeinfo-time-ns (list (cons 'raw header-extension-sony-l1d-timeinfo-time-ns) (cons 'formatted (number->string header-extension-sony-l1d-timeinfo-time-ns))))
        (cons 'header-extension-sony-plp-id (list (cons 'raw header-extension-sony-plp-id) (cons 'formatted (number->string header-extension-sony-plp-id))))
        (cons 'header-extension-sony-plp-unk (list (cons 'raw header-extension-sony-plp-unk) (cons 'formatted (fmt-hex header-extension-sony-plp-unk))))
        (cons 'sig-info-type-extension (list (cons 'raw sig-info-type-extension) (cons 'formatted (fmt-hex sig-info-type-extension))))
        (cons 'sig-info-version (list (cons 'raw sig-info-version) (cons 'formatted (fmt-hex sig-info-version))))
        (cons 'lmt-numplp (list (cons 'raw lmt-numplp) (cons 'formatted (number->string lmt-numplp))))
        (cons 'lmt-reserved (list (cons 'raw lmt-reserved) (cons 'formatted (fmt-hex lmt-reserved))))
        (cons 'lmt-plp-id (list (cons 'raw lmt-plp-id) (cons 'formatted (number->string lmt-plp-id))))
        (cons 'lmt-plp-reserved (list (cons 'raw lmt-plp-reserved) (cons 'formatted (fmt-hex lmt-plp-reserved))))
        (cons 'lmt-plp-nummc (list (cons 'raw lmt-plp-nummc) (cons 'formatted (number->string lmt-plp-nummc))))
        (cons 'lmt-plp-mc-src-ip (list (cons 'raw lmt-plp-mc-src-ip) (cons 'formatted (fmt-ipv4 lmt-plp-mc-src-ip))))
        (cons 'lmt-plp-mc-dst-ip (list (cons 'raw lmt-plp-mc-dst-ip) (cons 'formatted (fmt-ipv4 lmt-plp-mc-dst-ip))))
        (cons 'lmt-plp-mc-src-port (list (cons 'raw lmt-plp-mc-src-port) (cons 'formatted (number->string lmt-plp-mc-src-port))))
        (cons 'lmt-plp-mc-dst-port (list (cons 'raw lmt-plp-mc-dst-port) (cons 'formatted (number->string lmt-plp-mc-dst-port))))
        (cons 'lmt-plp-mc-sid-flag (list (cons 'raw lmt-plp-mc-sid-flag) (cons 'formatted (number->string lmt-plp-mc-sid-flag))))
        (cons 'lmt-plp-mc-comp-flag (list (cons 'raw lmt-plp-mc-comp-flag) (cons 'formatted (number->string lmt-plp-mc-comp-flag))))
        (cons 'lmt-plp-mc-reserved (list (cons 'raw lmt-plp-mc-reserved) (cons 'formatted (fmt-hex lmt-plp-mc-reserved))))
        (cons 'lmt-plp-mc-sid (list (cons 'raw lmt-plp-mc-sid) (cons 'formatted (number->string lmt-plp-mc-sid))))
        (cons 'lmt-plp-mc-context-id (list (cons 'raw lmt-plp-mc-context-id) (cons 'formatted (fmt-hex lmt-plp-mc-context-id))))
        (cons 'junk (list (cons 'raw junk) (cons 'formatted (fmt-bytes junk))))
        )))

    (catch (e)
      (err (str "ALP parse error: " e)))))

;; dissect-alp: parse ALP from bytevector
;; Returns (ok fields-alist) or (err message)