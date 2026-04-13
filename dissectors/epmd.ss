;; packet-epmd.c
;; dissector for EPMD (Erlang Port Mapper Daemon) messages;
;; this are the messages sent between Erlang nodes and
;; the empd process.
;; The message formats are derived from the
;; lib/kernel/src/erl_epmd.* files as part of the Erlang
;; distribution available from http://www.erlang.org/
;;
;; (c) 2007 Joost Yervante Damad <joost[AT]teluna.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald[AT]wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-time.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/epmd.ss
;; Auto-generated from wireshark/epan/dissectors/packet-epmd.c

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
(def (dissect-epmd buffer)
  "Erlang Port Mapper Daemon"
  (try
    (let* (
           (len (unwrap (read-u16be buffer 0)))
           (creation2 (unwrap (read-u32be buffer 18)))
           (creation (unwrap (read-u16be buffer 22)))
           (result (unwrap (read-u8 buffer 24)))
           (port-no (unwrap (read-u16be buffer 24)))
           (name-len (unwrap (read-u16be buffer 30)))
           (name (unwrap (slice buffer 30 1)))
           (elen (unwrap (read-u16be buffer 32)))
           (edata (unwrap (slice buffer 32 1)))
           )

      (ok (list
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'creation2 (list (cons 'raw creation2) (cons 'formatted (number->string creation2))))
        (cons 'creation (list (cons 'raw creation) (cons 'formatted (number->string creation))))
        (cons 'result (list (cons 'raw result) (cons 'formatted (number->string result))))
        (cons 'port-no (list (cons 'raw port-no) (cons 'formatted (number->string port-no))))
        (cons 'name-len (list (cons 'raw name-len) (cons 'formatted (number->string name-len))))
        (cons 'name (list (cons 'raw name) (cons 'formatted (utf8->string name))))
        (cons 'elen (list (cons 'raw elen) (cons 'formatted (number->string elen))))
        (cons 'edata (list (cons 'raw edata) (cons 'formatted (fmt-bytes edata))))
        )))

    (catch (e)
      (err (str "EPMD parse error: " e)))))

;; dissect-epmd: parse EPMD from bytevector
;; Returns (ok fields-alist) or (err message)