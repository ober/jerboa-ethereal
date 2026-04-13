;; packet-xra.c
;; Routines for Excentis DOCSIS31 XRA31 sniffer dissection
;; Copyright 2017, Bruno Verstuyft <bruno.verstuyft[AT]excentis.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/xra.ss
;; Auto-generated from wireshark/epan/dissectors/packet-xra.c

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
(def (dissect-xra buffer)
  "Excentis XRA Header"
  (try
    (let* (
           (segment-pointerfield (unwrap (read-u16be buffer 0)))
           (segment-reserved (unwrap (read-u8 buffer 0)))
           (segment-pfi (unwrap (read-u8 buffer 0)))
           (init-ranging-mac (unwrap (slice buffer 0 6)))
           (mb-l (unwrap (read-u8 buffer 0)))
           (mb-n (unwrap (read-u8 buffer 0)))
           (mb-c (unwrap (read-u8 buffer 0)))
           (mb-z (unwrap (read-u8 buffer 0)))
           (mb-profileid (unwrap (read-u8 buffer 0)))
           (mb (unwrap (slice buffer 0 3)))
           (trigger-mb (unwrap (slice buffer 0 1)))
           (em-mb (unwrap (slice buffer 0 1)))
           (mb-mc-pspf-present (unwrap (read-u8 buffer 0)))
           (mb-mc-reserved (unwrap (read-u8 buffer 0)))
           (mb-ts-reserved (unwrap (read-u8 buffer 0)))
           (tlv (unwrap (slice buffer 0 1)))
           (tlv-burst-info (unwrap (slice buffer 0 1)))
           (tlv-ms-info (unwrap (slice buffer 0 1)))
           (tlv-cw-info (unwrap (slice buffer 0 1)))
           (version (unwrap (read-u8 buffer 0)))
           (mb-subcarrier-start-pointer (unwrap (read-u16be buffer 1)))
           (mb-r (unwrap (read-u8 buffer 1)))
           (mb-u (unwrap (read-u8 buffer 1)))
           (mb-t (unwrap (read-u8 buffer 1)))
           (mb-mc-psp (unwrap (read-u16be buffer 1)))
           (mb-ts-timestamp (unwrap (read-u64be buffer 1)))
           (unknown (unwrap (slice buffer 1 1)))
           (segment-sequencenumber (unwrap (read-u16be buffer 2)))
           (tlvlength (unwrap (read-u16be buffer 2)))
           (segment-sidclusterid (unwrap (read-u8 buffer 3)))
           (crc (unwrap (slice buffer 3 3)))
           (segment-request (unwrap (read-u16be buffer 4)))
           (init-ranging-ds-channel-id (unwrap (read-u8 buffer 6)))
           (init-ranging-crc (unwrap (slice buffer 7 3)))
           (segment-data (unwrap (slice buffer 8 1)))
           (mb-ts-crc24d (unwrap (slice buffer 9 3)))
           )

      (ok (list
        (cons 'segment-pointerfield (list (cons 'raw segment-pointerfield) (cons 'formatted (number->string segment-pointerfield))))
        (cons 'segment-reserved (list (cons 'raw segment-reserved) (cons 'formatted (number->string segment-reserved))))
        (cons 'segment-pfi (list (cons 'raw segment-pfi) (cons 'formatted (number->string segment-pfi))))
        (cons 'init-ranging-mac (list (cons 'raw init-ranging-mac) (cons 'formatted (fmt-mac init-ranging-mac))))
        (cons 'mb-l (list (cons 'raw mb-l) (cons 'formatted (if (= mb-l 0) "this NCP is followed by another NCP" "this is the last NCP in the chain and is followed by an NCP CRC message block"))))
        (cons 'mb-n (list (cons 'raw mb-n) (cons 'formatted (if (= mb-n 0) "use even profile" "use odd profile"))))
        (cons 'mb-c (list (cons 'raw mb-c) (cons 'formatted (if (= mb-c 0) "use even profile" "use odd profile"))))
        (cons 'mb-z (list (cons 'raw mb-z) (cons 'formatted (if (= mb-z 0) "subcarriers follow profile" "subcarriers are all zero-bit-loaded"))))
        (cons 'mb-profileid (list (cons 'raw mb-profileid) (cons 'formatted (number->string mb-profileid))))
        (cons 'mb (list (cons 'raw mb) (cons 'formatted (fmt-bytes mb))))
        (cons 'trigger-mb (list (cons 'raw trigger-mb) (cons 'formatted (fmt-bytes trigger-mb))))
        (cons 'em-mb (list (cons 'raw em-mb) (cons 'formatted (fmt-bytes em-mb))))
        (cons 'mb-mc-pspf-present (list (cons 'raw mb-mc-pspf-present) (cons 'formatted (if (= mb-mc-pspf-present 0) "False" "True"))))
        (cons 'mb-mc-reserved (list (cons 'raw mb-mc-reserved) (cons 'formatted (number->string mb-mc-reserved))))
        (cons 'mb-ts-reserved (list (cons 'raw mb-ts-reserved) (cons 'formatted (number->string mb-ts-reserved))))
        (cons 'tlv (list (cons 'raw tlv) (cons 'formatted (fmt-bytes tlv))))
        (cons 'tlv-burst-info (list (cons 'raw tlv-burst-info) (cons 'formatted (fmt-bytes tlv-burst-info))))
        (cons 'tlv-ms-info (list (cons 'raw tlv-ms-info) (cons 'formatted (fmt-bytes tlv-ms-info))))
        (cons 'tlv-cw-info (list (cons 'raw tlv-cw-info) (cons 'formatted (fmt-bytes tlv-cw-info))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'mb-subcarrier-start-pointer (list (cons 'raw mb-subcarrier-start-pointer) (cons 'formatted (number->string mb-subcarrier-start-pointer))))
        (cons 'mb-r (list (cons 'raw mb-r) (cons 'formatted (number->string mb-r))))
        (cons 'mb-u (list (cons 'raw mb-u) (cons 'formatted (number->string mb-u))))
        (cons 'mb-t (list (cons 'raw mb-t) (cons 'formatted (if (= mb-t 0) "this codeword is not included in the codeword counts reported by the CM in the OPT-RSP message" "this codeword is included in the codeword counts reported by the CM in the OPT-RSP message"))))
        (cons 'mb-mc-psp (list (cons 'raw mb-mc-psp) (cons 'formatted (number->string mb-mc-psp))))
        (cons 'mb-ts-timestamp (list (cons 'raw mb-ts-timestamp) (cons 'formatted (number->string mb-ts-timestamp))))
        (cons 'unknown (list (cons 'raw unknown) (cons 'formatted (fmt-bytes unknown))))
        (cons 'segment-sequencenumber (list (cons 'raw segment-sequencenumber) (cons 'formatted (number->string segment-sequencenumber))))
        (cons 'tlvlength (list (cons 'raw tlvlength) (cons 'formatted (number->string tlvlength))))
        (cons 'segment-sidclusterid (list (cons 'raw segment-sidclusterid) (cons 'formatted (number->string segment-sidclusterid))))
        (cons 'crc (list (cons 'raw crc) (cons 'formatted (fmt-bytes crc))))
        (cons 'segment-request (list (cons 'raw segment-request) (cons 'formatted (number->string segment-request))))
        (cons 'init-ranging-ds-channel-id (list (cons 'raw init-ranging-ds-channel-id) (cons 'formatted (number->string init-ranging-ds-channel-id))))
        (cons 'init-ranging-crc (list (cons 'raw init-ranging-crc) (cons 'formatted (fmt-bytes init-ranging-crc))))
        (cons 'segment-data (list (cons 'raw segment-data) (cons 'formatted (fmt-bytes segment-data))))
        (cons 'mb-ts-crc24d (list (cons 'raw mb-ts-crc24d) (cons 'formatted (fmt-bytes mb-ts-crc24d))))
        )))

    (catch (e)
      (err (str "XRA parse error: " e)))))

;; dissect-xra: parse XRA from bytevector
;; Returns (ok fields-alist) or (err message)