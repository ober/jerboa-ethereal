;; packet-darwin.c
;; Support for Apple Legacy and Custom pcapng blocks and options
;; Copyright 2025, Omer Shapira <oesh@apple.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/darwin.ss
;; Auto-generated from wireshark/epan/dissectors/packet-darwin.c

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
(def (dissect-darwin buffer)
  "Apple Darwin"
  (try
    (let* (
           (metadata-comp-gencnt (unwrap (read-u32be buffer 0)))
           (metadata-drop-domain (unwrap (slice buffer 0 1)))
           (metadata-drop-component (unwrap (slice buffer 0 1)))
           (metadata-drop-reason (unwrap (slice buffer 0 1)))
           (metadata-drop-reason-code (unwrap (read-u32be buffer 0)))
           (metadata-drop-line (unwrap (read-u32be buffer 0)))
           (metadata-drop-func (unwrap (slice buffer 0 1)))
           (metadata-dropped (unwrap (read-u8 buffer 0)))
           (metadata-trace-tag (unwrap (read-u32be buffer 0)))
           (metadata-flow-id (unwrap (read-u32be buffer 0)))
           (metadata (unwrap (read-u8 buffer 0)))
           (info-pname (unwrap (slice buffer 0 1)))
           (info-pid (unwrap (read-u32be buffer 0)))
           )

      (ok (list
        (cons 'metadata-comp-gencnt (list (cons 'raw metadata-comp-gencnt) (cons 'formatted (number->string metadata-comp-gencnt))))
        (cons 'metadata-drop-domain (list (cons 'raw metadata-drop-domain) (cons 'formatted (utf8->string metadata-drop-domain))))
        (cons 'metadata-drop-component (list (cons 'raw metadata-drop-component) (cons 'formatted (utf8->string metadata-drop-component))))
        (cons 'metadata-drop-reason (list (cons 'raw metadata-drop-reason) (cons 'formatted (utf8->string metadata-drop-reason))))
        (cons 'metadata-drop-reason-code (list (cons 'raw metadata-drop-reason-code) (cons 'formatted (fmt-hex metadata-drop-reason-code))))
        (cons 'metadata-drop-line (list (cons 'raw metadata-drop-line) (cons 'formatted (number->string metadata-drop-line))))
        (cons 'metadata-drop-func (list (cons 'raw metadata-drop-func) (cons 'formatted (utf8->string metadata-drop-func))))
        (cons 'metadata-dropped (list (cons 'raw metadata-dropped) (cons 'formatted (number->string metadata-dropped))))
        (cons 'metadata-trace-tag (list (cons 'raw metadata-trace-tag) (cons 'formatted (fmt-hex metadata-trace-tag))))
        (cons 'metadata-flow-id (list (cons 'raw metadata-flow-id) (cons 'formatted (fmt-hex metadata-flow-id))))
        (cons 'metadata (list (cons 'raw metadata) (cons 'formatted (number->string metadata))))
        (cons 'info-pname (list (cons 'raw info-pname) (cons 'formatted (utf8->string info-pname))))
        (cons 'info-pid (list (cons 'raw info-pid) (cons 'formatted (number->string info-pid))))
        )))

    (catch (e)
      (err (str "DARWIN parse error: " e)))))

;; dissect-darwin: parse DARWIN from bytevector
;; Returns (ok fields-alist) or (err message)