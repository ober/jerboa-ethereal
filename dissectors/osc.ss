;; packet-osc.c
;; Routines for "Open Sound Control" packet dissection
;; Copyright 2014-2016 Hanspeter Portner <dev@open-music-kontrollers.ch>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/osc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-osc.c

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
(def (dissect-osc buffer)
  "Open Sound Control Encoding"
  (try
    (let* (
           (message-int32-type (unwrap (read-u32be buffer 0)))
           (message-float-type (unwrap (read-u32be buffer 4)))
           (message-string-type (unwrap (slice buffer 8 1)))
           (message-blob-data-type (unwrap (slice buffer 12 1)))
           (message-int64-type (unwrap (read-u64be buffer 12)))
           (message-double-type (unwrap (read-u64be buffer 20)))
           (message-symbol-type (unwrap (slice buffer 36 1)))
           (message-char-type (unwrap (slice buffer 39 1)))
           (message-rgba-type (unwrap (read-u32be buffer 40)))
           (message-rgba-red-type (unwrap (read-u8 buffer 40)))
           (message-rgba-green-type (unwrap (read-u8 buffer 41)))
           (message-rgba-blue-type (unwrap (read-u8 buffer 42)))
           (message-rgba-alpha-type (unwrap (read-u8 buffer 43)))
           (message-midi-port-type (unwrap (read-u8 buffer 44)))
           (message-midi-channel-type (unwrap (read-u8 buffer 48)))
           (message-midi-velocity-type (unwrap (read-u8 buffer 50)))
           (message-midi-pressure-type (unwrap (read-u8 buffer 55)))
           (message-midi-bender-type (unwrap (read-u16be buffer 57)))
           (message-midi-data1-type (unwrap (read-u8 buffer 59)))
           (message-midi-data2-type (unwrap (read-u8 buffer 60)))
           )

      (ok (list
        (cons 'message-int32-type (list (cons 'raw message-int32-type) (cons 'formatted (number->string message-int32-type))))
        (cons 'message-float-type (list (cons 'raw message-float-type) (cons 'formatted (number->string message-float-type))))
        (cons 'message-string-type (list (cons 'raw message-string-type) (cons 'formatted (utf8->string message-string-type))))
        (cons 'message-blob-data-type (list (cons 'raw message-blob-data-type) (cons 'formatted (fmt-bytes message-blob-data-type))))
        (cons 'message-int64-type (list (cons 'raw message-int64-type) (cons 'formatted (number->string message-int64-type))))
        (cons 'message-double-type (list (cons 'raw message-double-type) (cons 'formatted (number->string message-double-type))))
        (cons 'message-symbol-type (list (cons 'raw message-symbol-type) (cons 'formatted (utf8->string message-symbol-type))))
        (cons 'message-char-type (list (cons 'raw message-char-type) (cons 'formatted (utf8->string message-char-type))))
        (cons 'message-rgba-type (list (cons 'raw message-rgba-type) (cons 'formatted (fmt-hex message-rgba-type))))
        (cons 'message-rgba-red-type (list (cons 'raw message-rgba-red-type) (cons 'formatted (number->string message-rgba-red-type))))
        (cons 'message-rgba-green-type (list (cons 'raw message-rgba-green-type) (cons 'formatted (number->string message-rgba-green-type))))
        (cons 'message-rgba-blue-type (list (cons 'raw message-rgba-blue-type) (cons 'formatted (number->string message-rgba-blue-type))))
        (cons 'message-rgba-alpha-type (list (cons 'raw message-rgba-alpha-type) (cons 'formatted (number->string message-rgba-alpha-type))))
        (cons 'message-midi-port-type (list (cons 'raw message-midi-port-type) (cons 'formatted (number->string message-midi-port-type))))
        (cons 'message-midi-channel-type (list (cons 'raw message-midi-channel-type) (cons 'formatted (number->string message-midi-channel-type))))
        (cons 'message-midi-velocity-type (list (cons 'raw message-midi-velocity-type) (cons 'formatted (number->string message-midi-velocity-type))))
        (cons 'message-midi-pressure-type (list (cons 'raw message-midi-pressure-type) (cons 'formatted (number->string message-midi-pressure-type))))
        (cons 'message-midi-bender-type (list (cons 'raw message-midi-bender-type) (cons 'formatted (number->string message-midi-bender-type))))
        (cons 'message-midi-data1-type (list (cons 'raw message-midi-data1-type) (cons 'formatted (number->string message-midi-data1-type))))
        (cons 'message-midi-data2-type (list (cons 'raw message-midi-data2-type) (cons 'formatted (number->string message-midi-data2-type))))
        )))

    (catch (e)
      (err (str "OSC parse error: " e)))))

;; dissect-osc: parse OSC from bytevector
;; Returns (ok fields-alist) or (err message)