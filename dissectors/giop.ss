;; packet-giop.c
;; Routines for CORBA GIOP/IIOP packet disassembly
;;
;; Initial Code by,
;; Laurent Deniel <laurent.deniel@free.fr>
;; Craig Rodrigues <rodrigc@attbi.com>
;;
;; GIOP API extensions by,
;; Frank Singleton <frank.singleton@ericsson.com>
;; Trevor Shepherd <eustrsd@am1.ericsson.se>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/giop.ss
;; Auto-generated from wireshark/epan/dissectors/packet-giop.c

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
(def (dissect-giop buffer)
  "General Inter-ORB Protocol"
  (try
    (let* (
           (req-id (unwrap (read-u32be buffer 0)))
           (rsp-expected (unwrap (read-u8 buffer 0)))
           (objekt-key-len (unwrap (read-u32be buffer 0)))
           (objekt-key (unwrap (slice buffer 0 1)))
           (addressing-disposition (unwrap (read-u16be buffer 0)))
           (reserved (unwrap (slice buffer 1 3)))
           (message-magic (unwrap (slice buffer 1 4)))
           (req-operation (unwrap (slice buffer 1 1)))
           (req-principal-len (unwrap (read-u32be buffer 1)))
           (req-principal (unwrap (slice buffer 1 1)))
           (type-id (unwrap (slice buffer 1 1)))
           (stub-data (unwrap (slice buffer 1 1)))
           (message-major-version (unwrap (read-u8 buffer 4)))
           (message-minor-version (unwrap (read-u8 buffer 5)))
           (message-flags (unwrap (read-u8 buffer 6)))
           (message-flags-ziop-enabled (extract-bits message-flags 0x0 0))
           (message-flags-ziop-supported (extract-bits message-flags 0x0 0))
           (message-flags-fragment (extract-bits message-flags 0x0 0))
           (message-flags-little-endian (extract-bits message-flags 0x0 0))
           (message-size (unwrap (read-u32be buffer 8)))
           (exception-len (unwrap (read-u32be buffer 40)))
           (address-disp (unwrap (read-u16be buffer 40)))
           (reply-body (unwrap (slice buffer 40 1)))
           )

      (ok (list
        (cons 'req-id (list (cons 'raw req-id) (cons 'formatted (number->string req-id))))
        (cons 'rsp-expected (list (cons 'raw rsp-expected) (cons 'formatted (number->string rsp-expected))))
        (cons 'objekt-key-len (list (cons 'raw objekt-key-len) (cons 'formatted (number->string objekt-key-len))))
        (cons 'objekt-key (list (cons 'raw objekt-key) (cons 'formatted (fmt-bytes objekt-key))))
        (cons 'addressing-disposition (list (cons 'raw addressing-disposition) (cons 'formatted (number->string addressing-disposition))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'message-magic (list (cons 'raw message-magic) (cons 'formatted (utf8->string message-magic))))
        (cons 'req-operation (list (cons 'raw req-operation) (cons 'formatted (utf8->string req-operation))))
        (cons 'req-principal-len (list (cons 'raw req-principal-len) (cons 'formatted (number->string req-principal-len))))
        (cons 'req-principal (list (cons 'raw req-principal) (cons 'formatted (utf8->string req-principal))))
        (cons 'type-id (list (cons 'raw type-id) (cons 'formatted (utf8->string type-id))))
        (cons 'stub-data (list (cons 'raw stub-data) (cons 'formatted (fmt-bytes stub-data))))
        (cons 'message-major-version (list (cons 'raw message-major-version) (cons 'formatted (number->string message-major-version))))
        (cons 'message-minor-version (list (cons 'raw message-minor-version) (cons 'formatted (number->string message-minor-version))))
        (cons 'message-flags (list (cons 'raw message-flags) (cons 'formatted (fmt-hex message-flags))))
        (cons 'message-flags-ziop-enabled (list (cons 'raw message-flags-ziop-enabled) (cons 'formatted (if (= message-flags-ziop-enabled 0) "Not set" "Set"))))
        (cons 'message-flags-ziop-supported (list (cons 'raw message-flags-ziop-supported) (cons 'formatted (if (= message-flags-ziop-supported 0) "Not set" "Set"))))
        (cons 'message-flags-fragment (list (cons 'raw message-flags-fragment) (cons 'formatted (if (= message-flags-fragment 0) "Not set" "Set"))))
        (cons 'message-flags-little-endian (list (cons 'raw message-flags-little-endian) (cons 'formatted (if (= message-flags-little-endian 0) "Not set" "Set"))))
        (cons 'message-size (list (cons 'raw message-size) (cons 'formatted (number->string message-size))))
        (cons 'exception-len (list (cons 'raw exception-len) (cons 'formatted (number->string exception-len))))
        (cons 'address-disp (list (cons 'raw address-disp) (cons 'formatted (number->string address-disp))))
        (cons 'reply-body (list (cons 'raw reply-body) (cons 'formatted (fmt-bytes reply-body))))
        )))

    (catch (e)
      (err (str "GIOP parse error: " e)))))

;; dissect-giop: parse GIOP from bytevector
;; Returns (ok fields-alist) or (err message)