;; Do not modify this file. Changes will be overwritten.

;; jerboa-ethereal/dissectors/mpeg-pes.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mpeg_pes.c

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
(def (dissect-mpeg-pes buffer)
  "Moving Picture Experts Group"
  (try
    (let* (
           (pes-header-data (unwrap (slice buffer 0 1)))
           (pes-es-rate (unwrap (read-u24be buffer 16)))
           (pes-dsm-trick-mode (unwrap (slice buffer 19 1)))
           (pes-dsm-trick-mode-rep-cntrl (unwrap (read-u8 buffer 19)))
           (pes-copy-info (unwrap (read-u8 buffer 20)))
           (pes-crc (unwrap (read-u16be buffer 20)))
           (pes-extension-flags (unwrap (read-u8 buffer 22)))
           (pes-private-data (unwrap (slice buffer 22 16)))
           (pes-pack-length (unwrap (read-u8 buffer 38)))
           (pes-sequence (unwrap (read-u16be buffer 38)))
           (pes-pstd-buffer (unwrap (read-u16be buffer 40)))
           (pes-extension2 (unwrap (read-u16be buffer 42)))
           )

      (ok (list
        (cons 'pes-header-data (list (cons 'raw pes-header-data) (cons 'formatted (fmt-bytes pes-header-data))))
        (cons 'pes-es-rate (list (cons 'raw pes-es-rate) (cons 'formatted (number->string pes-es-rate))))
        (cons 'pes-dsm-trick-mode (list (cons 'raw pes-dsm-trick-mode) (cons 'formatted (fmt-bytes pes-dsm-trick-mode))))
        (cons 'pes-dsm-trick-mode-rep-cntrl (list (cons 'raw pes-dsm-trick-mode-rep-cntrl) (cons 'formatted (fmt-hex pes-dsm-trick-mode-rep-cntrl))))
        (cons 'pes-copy-info (list (cons 'raw pes-copy-info) (cons 'formatted (number->string pes-copy-info))))
        (cons 'pes-crc (list (cons 'raw pes-crc) (cons 'formatted (number->string pes-crc))))
        (cons 'pes-extension-flags (list (cons 'raw pes-extension-flags) (cons 'formatted (fmt-hex pes-extension-flags))))
        (cons 'pes-private-data (list (cons 'raw pes-private-data) (cons 'formatted (fmt-bytes pes-private-data))))
        (cons 'pes-pack-length (list (cons 'raw pes-pack-length) (cons 'formatted (number->string pes-pack-length))))
        (cons 'pes-sequence (list (cons 'raw pes-sequence) (cons 'formatted (fmt-hex pes-sequence))))
        (cons 'pes-pstd-buffer (list (cons 'raw pes-pstd-buffer) (cons 'formatted (number->string pes-pstd-buffer))))
        (cons 'pes-extension2 (list (cons 'raw pes-extension2) (cons 'formatted (fmt-hex pes-extension2))))
        )))

    (catch (e)
      (err (str "MPEG-PES parse error: " e)))))

;; dissect-mpeg-pes: parse MPEG-PES from bytevector
;; Returns (ok fields-alist) or (err message)