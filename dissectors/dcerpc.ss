;; packet-dcerpc.c
;; Routines for DCERPC packet disassembly
;; Copyright 2001, Todd Sabin <tas[AT]webspan.net>
;; Copyright 2003, Tim Potter <tpot[AT]samba.org>
;; Copyright 2010, Julien Kerihuel <j.kerihuel[AT]openchange.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dcerpc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dcerpc.c

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
(def (dissect-dcerpc buffer)
  "Distributed Computing Environment / Remote Procedure Call (DCE/RPC)"
  (try
    (let* (
           (sec-vt-bitmask (unwrap (read-u32le buffer 0)))
           (sec-vt-bitmask-sign (extract-bits sec-vt-bitmask 0x1 0))
           (reassembled-in (unwrap (read-u32be buffer 0)))
           (op (unwrap (read-u16be buffer 0)))
           (drep (unwrap (slice buffer 0 1)))
           (encrypted-stub-data (unwrap (slice buffer 0 1)))
           (decrypted-stub-data (unwrap (slice buffer 0 1)))
           (stub-data (unwrap (slice buffer 0 1)))
           (null-pointer (unwrap (slice buffer 0 1)))
           (duplicate-ptr (unwrap (slice buffer 0 1)))
           (referent-id64 (unwrap (read-u64be buffer 0)))
           (referent-id32 (unwrap (read-u32be buffer 0)))
           (sec-vt-signature (unwrap (slice buffer 0 1)))
           (sec-vt-command (unwrap (read-u16le buffer 0)))
           (sec-vt-command-end (extract-bits sec-vt-command 0x4000 14))
           (sec-vt-command-must (extract-bits sec-vt-command 0x8000 15))
           (unknown-if-id (unwrap (read-u8 buffer 0)))
           (cn-deseg-req (unwrap (read-u32be buffer 0)))
           (krb5-av-key-vers-num (unwrap (read-u8 buffer 0)))
           (ver (unwrap (read-u8 buffer 0)))
           (dg-serial-hi (unwrap (read-u8 buffer 0)))
           (obj-id (unwrap (slice buffer 0 16)))
           (sec-vt-command-length (unwrap (read-u16be buffer 2)))
           (missalign (unwrap (slice buffer 4 1)))
           (cn-bind-if-id (unwrap (slice buffer 4 16)))
           (krb5-av-key-auth-verifier (unwrap (slice buffer 8 16)))
           (dg-if-id (unwrap (slice buffer 16 16)))
           (sec-vt-pcontext-uuid (unwrap (slice buffer 20 16)))
           (cn-bind-trans-id (unwrap (slice buffer 20 16)))
           (authentication-verifier (unwrap (slice buffer 24 1)))
           (fragment-data (unwrap (slice buffer 24 1)))
           (dg-act-id (unwrap (slice buffer 32 16)))
           (sec-vt-pcontext-ver (unwrap (read-u32be buffer 36)))
           (cn-sec-addr (unwrap (slice buffer 36 1)))
           (cn-ack-trans-id (unwrap (slice buffer 43 16)))
           (dg-if-ver (unwrap (read-u32be buffer 52)))
           (dg-seqnum (unwrap (read-u32be buffer 56)))
           (opnum (unwrap (read-u16be buffer 60)))
           (dg-ihint (unwrap (read-u16be buffer 62)))
           (dg-ahint (unwrap (read-u16be buffer 64)))
           (dg-frag-len (unwrap (read-u16be buffer 66)))
           (dg-frag-num (unwrap (read-u16be buffer 68)))
           (dg-serial-lo (unwrap (read-u8 buffer 70)))
           (reserved (unwrap (slice buffer 80 4)))
           (cn-rts-command-conformancecount (unwrap (read-u32be buffer 90)))
           (cmd-client-ipv4 (unwrap (read-u32be buffer 98)))
           (cmd-client-ipv6 (unwrap (slice buffer 102 16)))
           (cn-rts-command-padding (unwrap (slice buffer 118 12)))
           (ver-minor (unwrap (read-u8 buffer 142)))
           (cn-frag-len (unwrap (read-u16be buffer 142)))
           (cn-auth-len (unwrap (read-u16be buffer 144)))
           (cn-call-id (unwrap (read-u32be buffer 146)))
           )

      (ok (list
        (cons 'sec-vt-bitmask (list (cons 'raw sec-vt-bitmask) (cons 'formatted (fmt-hex sec-vt-bitmask))))
        (cons 'sec-vt-bitmask-sign (list (cons 'raw sec-vt-bitmask-sign) (cons 'formatted (if (= sec-vt-bitmask-sign 0) "Not set" "Set"))))
        (cons 'reassembled-in (list (cons 'raw reassembled-in) (cons 'formatted (number->string reassembled-in))))
        (cons 'op (list (cons 'raw op) (cons 'formatted (number->string op))))
        (cons 'drep (list (cons 'raw drep) (cons 'formatted (fmt-bytes drep))))
        (cons 'encrypted-stub-data (list (cons 'raw encrypted-stub-data) (cons 'formatted (fmt-bytes encrypted-stub-data))))
        (cons 'decrypted-stub-data (list (cons 'raw decrypted-stub-data) (cons 'formatted (fmt-bytes decrypted-stub-data))))
        (cons 'stub-data (list (cons 'raw stub-data) (cons 'formatted (fmt-bytes stub-data))))
        (cons 'null-pointer (list (cons 'raw null-pointer) (cons 'formatted (fmt-bytes null-pointer))))
        (cons 'duplicate-ptr (list (cons 'raw duplicate-ptr) (cons 'formatted (utf8->string duplicate-ptr))))
        (cons 'referent-id64 (list (cons 'raw referent-id64) (cons 'formatted (fmt-hex referent-id64))))
        (cons 'referent-id32 (list (cons 'raw referent-id32) (cons 'formatted (fmt-hex referent-id32))))
        (cons 'sec-vt-signature (list (cons 'raw sec-vt-signature) (cons 'formatted (fmt-bytes sec-vt-signature))))
        (cons 'sec-vt-command (list (cons 'raw sec-vt-command) (cons 'formatted (fmt-hex sec-vt-command))))
        (cons 'sec-vt-command-end (list (cons 'raw sec-vt-command-end) (cons 'formatted (if (= sec-vt-command-end 0) "Not set" "Set"))))
        (cons 'sec-vt-command-must (list (cons 'raw sec-vt-command-must) (cons 'formatted (if (= sec-vt-command-must 0) "Not set" "Set"))))
        (cons 'unknown-if-id (list (cons 'raw unknown-if-id) (cons 'formatted (number->string unknown-if-id))))
        (cons 'cn-deseg-req (list (cons 'raw cn-deseg-req) (cons 'formatted (number->string cn-deseg-req))))
        (cons 'krb5-av-key-vers-num (list (cons 'raw krb5-av-key-vers-num) (cons 'formatted (number->string krb5-av-key-vers-num))))
        (cons 'ver (list (cons 'raw ver) (cons 'formatted (number->string ver))))
        (cons 'dg-serial-hi (list (cons 'raw dg-serial-hi) (cons 'formatted (fmt-hex dg-serial-hi))))
        (cons 'obj-id (list (cons 'raw obj-id) (cons 'formatted (fmt-bytes obj-id))))
        (cons 'sec-vt-command-length (list (cons 'raw sec-vt-command-length) (cons 'formatted (number->string sec-vt-command-length))))
        (cons 'missalign (list (cons 'raw missalign) (cons 'formatted (fmt-bytes missalign))))
        (cons 'cn-bind-if-id (list (cons 'raw cn-bind-if-id) (cons 'formatted (fmt-bytes cn-bind-if-id))))
        (cons 'krb5-av-key-auth-verifier (list (cons 'raw krb5-av-key-auth-verifier) (cons 'formatted (fmt-bytes krb5-av-key-auth-verifier))))
        (cons 'dg-if-id (list (cons 'raw dg-if-id) (cons 'formatted (fmt-bytes dg-if-id))))
        (cons 'sec-vt-pcontext-uuid (list (cons 'raw sec-vt-pcontext-uuid) (cons 'formatted (fmt-bytes sec-vt-pcontext-uuid))))
        (cons 'cn-bind-trans-id (list (cons 'raw cn-bind-trans-id) (cons 'formatted (fmt-bytes cn-bind-trans-id))))
        (cons 'authentication-verifier (list (cons 'raw authentication-verifier) (cons 'formatted (fmt-bytes authentication-verifier))))
        (cons 'fragment-data (list (cons 'raw fragment-data) (cons 'formatted (fmt-bytes fragment-data))))
        (cons 'dg-act-id (list (cons 'raw dg-act-id) (cons 'formatted (fmt-bytes dg-act-id))))
        (cons 'sec-vt-pcontext-ver (list (cons 'raw sec-vt-pcontext-ver) (cons 'formatted (fmt-hex sec-vt-pcontext-ver))))
        (cons 'cn-sec-addr (list (cons 'raw cn-sec-addr) (cons 'formatted (utf8->string cn-sec-addr))))
        (cons 'cn-ack-trans-id (list (cons 'raw cn-ack-trans-id) (cons 'formatted (fmt-bytes cn-ack-trans-id))))
        (cons 'dg-if-ver (list (cons 'raw dg-if-ver) (cons 'formatted (number->string dg-if-ver))))
        (cons 'dg-seqnum (list (cons 'raw dg-seqnum) (cons 'formatted (number->string dg-seqnum))))
        (cons 'opnum (list (cons 'raw opnum) (cons 'formatted (number->string opnum))))
        (cons 'dg-ihint (list (cons 'raw dg-ihint) (cons 'formatted (fmt-hex dg-ihint))))
        (cons 'dg-ahint (list (cons 'raw dg-ahint) (cons 'formatted (fmt-hex dg-ahint))))
        (cons 'dg-frag-len (list (cons 'raw dg-frag-len) (cons 'formatted (number->string dg-frag-len))))
        (cons 'dg-frag-num (list (cons 'raw dg-frag-num) (cons 'formatted (number->string dg-frag-num))))
        (cons 'dg-serial-lo (list (cons 'raw dg-serial-lo) (cons 'formatted (fmt-hex dg-serial-lo))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'cn-rts-command-conformancecount (list (cons 'raw cn-rts-command-conformancecount) (cons 'formatted (fmt-hex cn-rts-command-conformancecount))))
        (cons 'cmd-client-ipv4 (list (cons 'raw cmd-client-ipv4) (cons 'formatted (fmt-ipv4 cmd-client-ipv4))))
        (cons 'cmd-client-ipv6 (list (cons 'raw cmd-client-ipv6) (cons 'formatted (fmt-ipv6-address cmd-client-ipv6))))
        (cons 'cn-rts-command-padding (list (cons 'raw cn-rts-command-padding) (cons 'formatted (fmt-bytes cn-rts-command-padding))))
        (cons 'ver-minor (list (cons 'raw ver-minor) (cons 'formatted (number->string ver-minor))))
        (cons 'cn-frag-len (list (cons 'raw cn-frag-len) (cons 'formatted (number->string cn-frag-len))))
        (cons 'cn-auth-len (list (cons 'raw cn-auth-len) (cons 'formatted (number->string cn-auth-len))))
        (cons 'cn-call-id (list (cons 'raw cn-call-id) (cons 'formatted (number->string cn-call-id))))
        )))

    (catch (e)
      (err (str "DCERPC parse error: " e)))))

;; dissect-dcerpc: parse DCERPC from bytevector
;; Returns (ok fields-alist) or (err message)