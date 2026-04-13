;; packet-dcerpc-fldb.c
;;
;; Routines for DCE DFS Fileset Location Server Calls
;; Copyright 2004, Jaime Fournier <Jaime.Fournier@hush.com>
;; This information is based off the released idl files from opengroup.
;; ftp://ftp.opengroup.org/pub/dce122/dce/src/file.tar.gz file/flserver/fldb_proc.idl
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dcerpc-fldb.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dcerpc_fldb.c

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
(def (dissect-dcerpc-fldb buffer)
  "DCE DFS Fileset Location Server"
  (try
    (let* (
           (vlconf-cell-name (unwrap (slice buffer 14 114)))
           (vlconf-cell-hostname (unwrap (slice buffer 14 64)))
           (afsNameString-t-principalName-string (unwrap (slice buffer 78 1)))
           (vldbentry-volumename (unwrap (slice buffer 78 114)))
           (vldbentry-siteprincipal (unwrap (slice buffer 188 64)))
           (vldbentry-lockername (unwrap (slice buffer 252 1)))
           (vldbentry-charspares (unwrap (slice buffer 252 50)))
           (namestring (unwrap (slice buffer 354 64)))
           )

      (ok (list
        (cons 'vlconf-cell-name (list (cons 'raw vlconf-cell-name) (cons 'formatted (utf8->string vlconf-cell-name))))
        (cons 'vlconf-cell-hostname (list (cons 'raw vlconf-cell-hostname) (cons 'formatted (utf8->string vlconf-cell-hostname))))
        (cons 'afsNameString-t-principalName-string (list (cons 'raw afsNameString-t-principalName-string) (cons 'formatted (utf8->string afsNameString-t-principalName-string))))
        (cons 'vldbentry-volumename (list (cons 'raw vldbentry-volumename) (cons 'formatted (utf8->string vldbentry-volumename))))
        (cons 'vldbentry-siteprincipal (list (cons 'raw vldbentry-siteprincipal) (cons 'formatted (utf8->string vldbentry-siteprincipal))))
        (cons 'vldbentry-lockername (list (cons 'raw vldbentry-lockername) (cons 'formatted (utf8->string vldbentry-lockername))))
        (cons 'vldbentry-charspares (list (cons 'raw vldbentry-charspares) (cons 'formatted (utf8->string vldbentry-charspares))))
        (cons 'namestring (list (cons 'raw namestring) (cons 'formatted (utf8->string namestring))))
        )))

    (catch (e)
      (err (str "DCERPC-FLDB parse error: " e)))))

;; dissect-dcerpc-fldb: parse DCERPC-FLDB from bytevector
;; Returns (ok fields-alist) or (err message)