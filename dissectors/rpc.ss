;; packet-rpc.c
;; Routines for rpc dissection
;; Copyright 1999, Uwe Girlich <Uwe.Girlich@philosys.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-smb.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rpc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rpc.c
;; RFC 1831

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
(def (dissect-rpc buffer)
  "Remote Procedure Call"
  (try
    (let* (
           (fraglen (unwrap (read-u32be buffer 0)))
           (lastfrag (unwrap (read-u8 buffer 0)))
           (reply-dup (unwrap (read-u32be buffer 0)))
           (call-dup (unwrap (read-u32be buffer 0)))
           (continuation-data (unwrap (slice buffer 0 1)))
           (authgss-ctx-destroy-frame (unwrap (read-u32be buffer 0)))
           (authgss-ctx-create-frame (unwrap (read-u32be buffer 0)))
           (opaque-length (unwrap (read-u32be buffer 0)))
           (fragment-data (unwrap (slice buffer 4 1)))
           (fill-bytes (unwrap (slice buffer 4 1)))
           (value-follows (unwrap (read-u8 buffer 4)))
           (auth-stamp (unwrap (read-u32be buffer 20)))
           (auth-uid (unwrap (read-u32be buffer 24)))
           (auth-gid (unwrap (read-u32be buffer 28)))
           (authgss-ctx-len (unwrap (read-u32be buffer 32)))
           (authgss-ctx (unwrap (slice buffer 36 1)))
           (authgss-v (unwrap (read-u32be buffer 36)))
           (authdes-window (unwrap (read-u32be buffer 56)))
           (auth-lk-owner (unwrap (slice buffer 92 1)))
           (authgssapi-v (unwrap (read-u32be buffer 92)))
           (authgssapi-msg (unwrap (read-u8 buffer 96)))
           (authgss-token-length (unwrap (read-u32be buffer 108)))
           (auth-length (unwrap (read-u32be buffer 112)))
           (authdes-windowverf (unwrap (read-u32be buffer 112)))
           (authdes-nickname (unwrap (read-u32be buffer 112)))
           (opaque-data (unwrap (slice buffer 112 1)))
           (authgss-window (unwrap (read-u32be buffer 128)))
           (authgssapi-msgv (unwrap (read-u32be buffer 136)))
           (authgss-major (unwrap (read-u32be buffer 140)))
           (authgss-minor (unwrap (read-u32be buffer 144)))
           (authgss-seq (unwrap (read-u32be buffer 148)))
           (authgss-data-length (unwrap (read-u32be buffer 156)))
           (authgss-data (unwrap (slice buffer 160 1)))
           (argument-length (unwrap (read-u32be buffer 164)))
           (xid (unwrap (read-u32be buffer 168)))
           (version (unwrap (read-u32be buffer 176)))
           (program (unwrap (read-u32be buffer 176)))
           (programversion (unwrap (read-u32be buffer 176)))
           (procedure (unwrap (read-u32be buffer 176)))
           (programversion-min (unwrap (read-u32be buffer 200)))
           (programversion-max (unwrap (read-u32be buffer 200)))
           (version-min (unwrap (read-u32be buffer 212)))
           (version-max (unwrap (read-u32be buffer 212)))
           )

      (ok (list
        (cons 'fraglen (list (cons 'raw fraglen) (cons 'formatted (number->string fraglen))))
        (cons 'lastfrag (list (cons 'raw lastfrag) (cons 'formatted (if (= lastfrag 0) "False" "True"))))
        (cons 'reply-dup (list (cons 'raw reply-dup) (cons 'formatted (number->string reply-dup))))
        (cons 'call-dup (list (cons 'raw call-dup) (cons 'formatted (number->string call-dup))))
        (cons 'continuation-data (list (cons 'raw continuation-data) (cons 'formatted (fmt-bytes continuation-data))))
        (cons 'authgss-ctx-destroy-frame (list (cons 'raw authgss-ctx-destroy-frame) (cons 'formatted (number->string authgss-ctx-destroy-frame))))
        (cons 'authgss-ctx-create-frame (list (cons 'raw authgss-ctx-create-frame) (cons 'formatted (number->string authgss-ctx-create-frame))))
        (cons 'opaque-length (list (cons 'raw opaque-length) (cons 'formatted (number->string opaque-length))))
        (cons 'fragment-data (list (cons 'raw fragment-data) (cons 'formatted (fmt-bytes fragment-data))))
        (cons 'fill-bytes (list (cons 'raw fill-bytes) (cons 'formatted (fmt-bytes fill-bytes))))
        (cons 'value-follows (list (cons 'raw value-follows) (cons 'formatted (if (= value-follows 0) "False" "True"))))
        (cons 'auth-stamp (list (cons 'raw auth-stamp) (cons 'formatted (fmt-hex auth-stamp))))
        (cons 'auth-uid (list (cons 'raw auth-uid) (cons 'formatted (number->string auth-uid))))
        (cons 'auth-gid (list (cons 'raw auth-gid) (cons 'formatted (number->string auth-gid))))
        (cons 'authgss-ctx-len (list (cons 'raw authgss-ctx-len) (cons 'formatted (number->string authgss-ctx-len))))
        (cons 'authgss-ctx (list (cons 'raw authgss-ctx) (cons 'formatted (fmt-bytes authgss-ctx))))
        (cons 'authgss-v (list (cons 'raw authgss-v) (cons 'formatted (number->string authgss-v))))
        (cons 'authdes-window (list (cons 'raw authdes-window) (cons 'formatted (fmt-hex authdes-window))))
        (cons 'auth-lk-owner (list (cons 'raw auth-lk-owner) (cons 'formatted (fmt-bytes auth-lk-owner))))
        (cons 'authgssapi-v (list (cons 'raw authgssapi-v) (cons 'formatted (number->string authgssapi-v))))
        (cons 'authgssapi-msg (list (cons 'raw authgssapi-msg) (cons 'formatted (if (= authgssapi-msg 0) "False" "True"))))
        (cons 'authgss-token-length (list (cons 'raw authgss-token-length) (cons 'formatted (number->string authgss-token-length))))
        (cons 'auth-length (list (cons 'raw auth-length) (cons 'formatted (number->string auth-length))))
        (cons 'authdes-windowverf (list (cons 'raw authdes-windowverf) (cons 'formatted (fmt-hex authdes-windowverf))))
        (cons 'authdes-nickname (list (cons 'raw authdes-nickname) (cons 'formatted (fmt-hex authdes-nickname))))
        (cons 'opaque-data (list (cons 'raw opaque-data) (cons 'formatted (fmt-bytes opaque-data))))
        (cons 'authgss-window (list (cons 'raw authgss-window) (cons 'formatted (number->string authgss-window))))
        (cons 'authgssapi-msgv (list (cons 'raw authgssapi-msgv) (cons 'formatted (number->string authgssapi-msgv))))
        (cons 'authgss-major (list (cons 'raw authgss-major) (cons 'formatted (number->string authgss-major))))
        (cons 'authgss-minor (list (cons 'raw authgss-minor) (cons 'formatted (number->string authgss-minor))))
        (cons 'authgss-seq (list (cons 'raw authgss-seq) (cons 'formatted (number->string authgss-seq))))
        (cons 'authgss-data-length (list (cons 'raw authgss-data-length) (cons 'formatted (number->string authgss-data-length))))
        (cons 'authgss-data (list (cons 'raw authgss-data) (cons 'formatted (fmt-bytes authgss-data))))
        (cons 'argument-length (list (cons 'raw argument-length) (cons 'formatted (number->string argument-length))))
        (cons 'xid (list (cons 'raw xid) (cons 'formatted (fmt-hex xid))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'program (list (cons 'raw program) (cons 'formatted (number->string program))))
        (cons 'programversion (list (cons 'raw programversion) (cons 'formatted (number->string programversion))))
        (cons 'procedure (list (cons 'raw procedure) (cons 'formatted (number->string procedure))))
        (cons 'programversion-min (list (cons 'raw programversion-min) (cons 'formatted (number->string programversion-min))))
        (cons 'programversion-max (list (cons 'raw programversion-max) (cons 'formatted (number->string programversion-max))))
        (cons 'version-min (list (cons 'raw version-min) (cons 'formatted (number->string version-min))))
        (cons 'version-max (list (cons 'raw version-max) (cons 'formatted (number->string version-max))))
        )))

    (catch (e)
      (err (str "RPC parse error: " e)))))

;; dissect-rpc: parse RPC from bytevector
;; Returns (ok fields-alist) or (err message)