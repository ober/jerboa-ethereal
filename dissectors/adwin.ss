;; packet-adwin.c
;; Routines for ADwin protocol dissection
;; Copyright 2010, Thomas Boehne <TBoehne[AT]ADwin.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/adwin.ss
;; Auto-generated from wireshark/epan/dissectors/packet-adwin.c

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
(def (dissect-adwin buffer)
  "ADwin communication protocol"
  (try
    (let* (
           (request-no (unwrap (read-u32be buffer 4)))
           (packet-index (unwrap (read-u32be buffer 4)))
           (complete-packets (unwrap (read-u32be buffer 8)))
           (password (unwrap (slice buffer 8 10)))
           (gdsh-status (unwrap (read-u32be buffer 12)))
           (is-range (unwrap (read-u32be buffer 12)))
           (val2 (unwrap (read-u32be buffer 12)))
           (data-int (unwrap (read-u32be buffer 12)))
           (data-float (unwrap (read-u32be buffer 12)))
           (data-hex (unwrap (read-u32be buffer 12)))
           (packet-start (unwrap (read-u32be buffer 16)))
           (val3 (unwrap (read-u32be buffer 16)))
           (packet-end (unwrap (read-u32be buffer 20)))
           (val4 (unwrap (read-u32be buffer 20)))
           (address (unwrap (read-u32be buffer 20)))
           (armVersion (unwrap (read-u32be buffer 20)))
           (data-packet-index (unwrap (read-u32be buffer 20)))
           (memsize (unwrap (read-u32be buffer 20)))
           (fifo-no16 (unwrap (read-u32be buffer 24)))
           (data-no16 (unwrap (read-u16be buffer 24)))
           (blocksize (unwrap (read-u32be buffer 24)))
           (fifo-no32 (unwrap (read-u32be buffer 24)))
           (data-no32 (unwrap (read-u32be buffer 24)))
           (process-no (unwrap (read-u32be buffer 24)))
           (mem-type (unwrap (read-u32be buffer 24)))
           (retry-packet-index (unwrap (read-u32be buffer 28)))
           (start-index (unwrap (read-u32be buffer 28)))
           (processor (unwrap (read-u32be buffer 28)))
           (val1f (unwrap (read-u32be buffer 28)))
           (val1 (unwrap (read-u32be buffer 28)))
           (count (unwrap (read-u32be buffer 32)))
           (binfilesize (unwrap (read-u32be buffer 32)))
           (link-addr (unwrap (read-u32be buffer 36)))
           (timeout (unwrap (read-u32be buffer 40)))
           (dll-version (unwrap (slice buffer 52 4)))
           (packet-no (unwrap (read-u32be buffer 1408)))
           )

      (ok (list
        (cons 'request-no (list (cons 'raw request-no) (cons 'formatted (number->string request-no))))
        (cons 'packet-index (list (cons 'raw packet-index) (cons 'formatted (number->string packet-index))))
        (cons 'complete-packets (list (cons 'raw complete-packets) (cons 'formatted (number->string complete-packets))))
        (cons 'password (list (cons 'raw password) (cons 'formatted (utf8->string password))))
        (cons 'gdsh-status (list (cons 'raw gdsh-status) (cons 'formatted (number->string gdsh-status))))
        (cons 'is-range (list (cons 'raw is-range) (cons 'formatted (number->string is-range))))
        (cons 'val2 (list (cons 'raw val2) (cons 'formatted (number->string val2))))
        (cons 'data-int (list (cons 'raw data-int) (cons 'formatted (number->string data-int))))
        (cons 'data-float (list (cons 'raw data-float) (cons 'formatted (number->string data-float))))
        (cons 'data-hex (list (cons 'raw data-hex) (cons 'formatted (fmt-hex data-hex))))
        (cons 'packet-start (list (cons 'raw packet-start) (cons 'formatted (number->string packet-start))))
        (cons 'val3 (list (cons 'raw val3) (cons 'formatted (number->string val3))))
        (cons 'packet-end (list (cons 'raw packet-end) (cons 'formatted (number->string packet-end))))
        (cons 'val4 (list (cons 'raw val4) (cons 'formatted (number->string val4))))
        (cons 'address (list (cons 'raw address) (cons 'formatted (fmt-hex address))))
        (cons 'armVersion (list (cons 'raw armVersion) (cons 'formatted (number->string armVersion))))
        (cons 'data-packet-index (list (cons 'raw data-packet-index) (cons 'formatted (number->string data-packet-index))))
        (cons 'memsize (list (cons 'raw memsize) (cons 'formatted (number->string memsize))))
        (cons 'fifo-no16 (list (cons 'raw fifo-no16) (cons 'formatted (number->string fifo-no16))))
        (cons 'data-no16 (list (cons 'raw data-no16) (cons 'formatted (number->string data-no16))))
        (cons 'blocksize (list (cons 'raw blocksize) (cons 'formatted (number->string blocksize))))
        (cons 'fifo-no32 (list (cons 'raw fifo-no32) (cons 'formatted (number->string fifo-no32))))
        (cons 'data-no32 (list (cons 'raw data-no32) (cons 'formatted (number->string data-no32))))
        (cons 'process-no (list (cons 'raw process-no) (cons 'formatted (number->string process-no))))
        (cons 'mem-type (list (cons 'raw mem-type) (cons 'formatted (number->string mem-type))))
        (cons 'retry-packet-index (list (cons 'raw retry-packet-index) (cons 'formatted (number->string retry-packet-index))))
        (cons 'start-index (list (cons 'raw start-index) (cons 'formatted (number->string start-index))))
        (cons 'processor (list (cons 'raw processor) (cons 'formatted (number->string processor))))
        (cons 'val1f (list (cons 'raw val1f) (cons 'formatted (number->string val1f))))
        (cons 'val1 (list (cons 'raw val1) (cons 'formatted (number->string val1))))
        (cons 'count (list (cons 'raw count) (cons 'formatted (number->string count))))
        (cons 'binfilesize (list (cons 'raw binfilesize) (cons 'formatted (number->string binfilesize))))
        (cons 'link-addr (list (cons 'raw link-addr) (cons 'formatted (fmt-hex link-addr))))
        (cons 'timeout (list (cons 'raw timeout) (cons 'formatted (number->string timeout))))
        (cons 'dll-version (list (cons 'raw dll-version) (cons 'formatted (utf8->string dll-version))))
        (cons 'packet-no (list (cons 'raw packet-no) (cons 'formatted (number->string packet-no))))
        )))

    (catch (e)
      (err (str "ADWIN parse error: " e)))))

;; dissect-adwin: parse ADWIN from bytevector
;; Returns (ok fields-alist) or (err message)