;; packet-tipc.c
;; Routines for Transparent Inter Process Communication packet dissection
;;
;; Copyright 2005-2006, Anders Broman <anders.broman@ericsson.com>
;;
;; TIPCv2 protocol updates
;; Copyright 2006-2008, Martin Peylo <wireshark@izac.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;; Protocol ref:
;; https://tipc.sourceforge.net/
;; https://tipc.sourceforge.net/protocol.html
;;

;; jerboa-ethereal/dissectors/tipc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-tipc.c

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
(def (dissect-tipc buffer)
  "Transparent Inter Process Communication(TIPC)"
  (try
    (let* (
           (name-dist-lower (unwrap (read-u32be buffer 0)))
           (name-dist-upper (unwrap (read-u32be buffer 0)))
           (name-dist-port (unwrap (read-u32be buffer 0)))
           (name-dist-key (unwrap (read-u32be buffer 0)))
           (name-dist-port-id-node (unwrap (slice buffer 0 4)))
           (unused2 (unwrap (read-u32be buffer 16)))
           (importance (unwrap (read-u32be buffer 16)))
           (link-selector (unwrap (read-u32be buffer 16)))
           (msg-cnt (unwrap (read-u32be buffer 16)))
           (probe (unwrap (read-u32be buffer 16)))
           (bearer-id (unwrap (read-u32be buffer 16)))
           (link-selector2 (unwrap (read-u32be buffer 16)))
           (remote-addr (unwrap (read-u32be buffer 16)))
           (unknown-msg-type (unwrap (read-u32be buffer 16)))
           (seq-gap (unwrap (read-u32be buffer 16)))
           (nxt-snt-pkg (unwrap (read-u32be buffer 16)))
           (bearer-name (unwrap (slice buffer 16 1)))
           (changeover-protocol (unwrap (read-u32be buffer 16)))
           (data-fragment (unwrap (slice buffer 16 1)))
           (msg-no-bundle (unwrap (read-u32be buffer 16)))
           (data (unwrap (slice buffer 16 1)))
           (name-dist-type (unwrap (read-u32be buffer 20)))
           )

      (ok (list
        (cons 'name-dist-lower (list (cons 'raw name-dist-lower) (cons 'formatted (number->string name-dist-lower))))
        (cons 'name-dist-upper (list (cons 'raw name-dist-upper) (cons 'formatted (number->string name-dist-upper))))
        (cons 'name-dist-port (list (cons 'raw name-dist-port) (cons 'formatted (number->string name-dist-port))))
        (cons 'name-dist-key (list (cons 'raw name-dist-key) (cons 'formatted (number->string name-dist-key))))
        (cons 'name-dist-port-id-node (list (cons 'raw name-dist-port-id-node) (cons 'formatted (utf8->string name-dist-port-id-node))))
        (cons 'unused2 (list (cons 'raw unused2) (cons 'formatted (number->string unused2))))
        (cons 'importance (list (cons 'raw importance) (cons 'formatted (number->string importance))))
        (cons 'link-selector (list (cons 'raw link-selector) (cons 'formatted (number->string link-selector))))
        (cons 'msg-cnt (list (cons 'raw msg-cnt) (cons 'formatted (number->string msg-cnt))))
        (cons 'probe (list (cons 'raw probe) (cons 'formatted (number->string probe))))
        (cons 'bearer-id (list (cons 'raw bearer-id) (cons 'formatted (number->string bearer-id))))
        (cons 'link-selector2 (list (cons 'raw link-selector2) (cons 'formatted (number->string link-selector2))))
        (cons 'remote-addr (list (cons 'raw remote-addr) (cons 'formatted (number->string remote-addr))))
        (cons 'unknown-msg-type (list (cons 'raw unknown-msg-type) (cons 'formatted (number->string unknown-msg-type))))
        (cons 'seq-gap (list (cons 'raw seq-gap) (cons 'formatted (number->string seq-gap))))
        (cons 'nxt-snt-pkg (list (cons 'raw nxt-snt-pkg) (cons 'formatted (number->string nxt-snt-pkg))))
        (cons 'bearer-name (list (cons 'raw bearer-name) (cons 'formatted (utf8->string bearer-name))))
        (cons 'changeover-protocol (list (cons 'raw changeover-protocol) (cons 'formatted (number->string changeover-protocol))))
        (cons 'data-fragment (list (cons 'raw data-fragment) (cons 'formatted (fmt-bytes data-fragment))))
        (cons 'msg-no-bundle (list (cons 'raw msg-no-bundle) (cons 'formatted (number->string msg-no-bundle))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'name-dist-type (list (cons 'raw name-dist-type) (cons 'formatted (number->string name-dist-type))))
        )))

    (catch (e)
      (err (str "TIPC parse error: " e)))))

;; dissect-tipc: parse TIPC from bytevector
;; Returns (ok fields-alist) or (err message)