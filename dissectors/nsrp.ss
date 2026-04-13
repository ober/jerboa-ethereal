;; packet-nsrp.c
;; Routines for the Juniper Netscreen Redundant Protocol (NSRP)
;;
;; Secfire <secfire@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nsrp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nsrp.c

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
(def (dissect-nsrp buffer)
  "Juniper Netscreen Redundant Protocol"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (clust-id (unwrap (read-u8 buffer 2)))
           (msg-flag (unwrap (read-u8 buffer 3)))
           (len (unwrap (read-u16be buffer 4)))
           (ha-port (unwrap (read-u8 buffer 6)))
           (dst-unit (unwrap (read-u32be buffer 8)))
           (src-unit (unwrap (read-u32be buffer 12)))
           (ns (unwrap (read-u16be buffer 28)))
           (nr (unwrap (read-u16be buffer 30)))
           (no-used (unwrap (read-u16be buffer 32)))
           (authflag (unwrap (read-u8 buffer 42)))
           (priority (unwrap (read-u8 buffer 44)))
           (dummy (unwrap (read-u8 buffer 45)))
           (wst-group (unwrap (read-u8 buffer 49)))
           (hst-group (unwrap (read-u8 buffer 50)))
           (msglen (unwrap (read-u16be buffer 52)))
           (ifnum (unwrap (read-u16be buffer 54)))
           (not-used (unwrap (read-u8 buffer 55)))
           (total-size (unwrap (read-u32be buffer 56)))
           (data (unwrap (slice buffer 60 1)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'clust-id (list (cons 'raw clust-id) (cons 'formatted (number->string clust-id))))
        (cons 'msg-flag (list (cons 'raw msg-flag) (cons 'formatted (number->string msg-flag))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'ha-port (list (cons 'raw ha-port) (cons 'formatted (number->string ha-port))))
        (cons 'dst-unit (list (cons 'raw dst-unit) (cons 'formatted (number->string dst-unit))))
        (cons 'src-unit (list (cons 'raw src-unit) (cons 'formatted (number->string src-unit))))
        (cons 'ns (list (cons 'raw ns) (cons 'formatted (number->string ns))))
        (cons 'nr (list (cons 'raw nr) (cons 'formatted (number->string nr))))
        (cons 'no-used (list (cons 'raw no-used) (cons 'formatted (number->string no-used))))
        (cons 'authflag (list (cons 'raw authflag) (cons 'formatted (fmt-hex authflag))))
        (cons 'priority (list (cons 'raw priority) (cons 'formatted (fmt-hex priority))))
        (cons 'dummy (list (cons 'raw dummy) (cons 'formatted (fmt-hex dummy))))
        (cons 'wst-group (list (cons 'raw wst-group) (cons 'formatted (number->string wst-group))))
        (cons 'hst-group (list (cons 'raw hst-group) (cons 'formatted (number->string hst-group))))
        (cons 'msglen (list (cons 'raw msglen) (cons 'formatted (number->string msglen))))
        (cons 'ifnum (list (cons 'raw ifnum) (cons 'formatted (fmt-hex ifnum))))
        (cons 'not-used (list (cons 'raw not-used) (cons 'formatted (number->string not-used))))
        (cons 'total-size (list (cons 'raw total-size) (cons 'formatted (number->string total-size))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (utf8->string data))))
        )))

    (catch (e)
      (err (str "NSRP parse error: " e)))))

;; dissect-nsrp: parse NSRP from bytevector
;; Returns (ok fields-alist) or (err message)