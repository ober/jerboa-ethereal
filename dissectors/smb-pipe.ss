;;
;; XXX  Fixme : shouldn't show [malformed frame] for long packets
;;

;; jerboa-ethereal/dissectors/smb-pipe.ss
;; Auto-generated from wireshark/epan/dissectors/packet-smb_pipe.c

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
(def (dissect-smb-pipe buffer)
  "Microsoft Windows Lanman Remote API Protocol"
  (try
    (let* (
           (pipe-stringz-param (unwrap (slice buffer 0 1)))
           (no-descriptor (unwrap (slice buffer 0 1)))
           (pipe-byte-param (unwrap (read-u8 buffer 6)))
           (pipe-bytes-param (unwrap (slice buffer 6 1)))
           (pipe-string-param (unwrap (slice buffer 6 1)))
           (hf-tzoffset (unwrap (read-u16be buffer 36)))
           (hf-timeinterval (unwrap (read-u16be buffer 38)))
           (hf-password (unwrap (slice buffer 62 15)))
           (name (unwrap (slice buffer 78 16)))
           (hf-padding (unwrap (slice buffer 100 1)))
           (buf-len (unwrap (read-u16be buffer 102)))
           (hf-ecount (unwrap (read-u16be buffer 110)))
           (data-struct-count (unwrap (read-u16be buffer 126)))
           )

      (ok (list
        (cons 'pipe-stringz-param (list (cons 'raw pipe-stringz-param) (cons 'formatted (utf8->string pipe-stringz-param))))
        (cons 'no-descriptor (list (cons 'raw no-descriptor) (cons 'formatted (fmt-bytes no-descriptor))))
        (cons 'pipe-byte-param (list (cons 'raw pipe-byte-param) (cons 'formatted (number->string pipe-byte-param))))
        (cons 'pipe-bytes-param (list (cons 'raw pipe-bytes-param) (cons 'formatted (fmt-bytes pipe-bytes-param))))
        (cons 'pipe-string-param (list (cons 'raw pipe-string-param) (cons 'formatted (utf8->string pipe-string-param))))
        (cons 'hf-tzoffset (list (cons 'raw hf-tzoffset) (cons 'formatted (number->string hf-tzoffset))))
        (cons 'hf-timeinterval (list (cons 'raw hf-timeinterval) (cons 'formatted (number->string hf-timeinterval))))
        (cons 'hf-password (list (cons 'raw hf-password) (cons 'formatted (utf8->string hf-password))))
        (cons 'name (list (cons 'raw name) (cons 'formatted (utf8->string name))))
        (cons 'hf-padding (list (cons 'raw hf-padding) (cons 'formatted (fmt-bytes hf-padding))))
        (cons 'buf-len (list (cons 'raw buf-len) (cons 'formatted (number->string buf-len))))
        (cons 'hf-ecount (list (cons 'raw hf-ecount) (cons 'formatted (number->string hf-ecount))))
        (cons 'data-struct-count (list (cons 'raw data-struct-count) (cons 'formatted (number->string data-struct-count))))
        )))

    (catch (e)
      (err (str "SMB-PIPE parse error: " e)))))

;; dissect-smb-pipe: parse SMB-PIPE from bytevector
;; Returns (ok fields-alist) or (err message)