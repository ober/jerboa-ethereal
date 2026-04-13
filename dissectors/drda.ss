;; packet-drda.c
;; Routines for Distributed Relational Database Architecture packet dissection
;;
;; metatech <metatech@flashmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/drda.ss
;; Auto-generated from wireshark/epan/dissectors/packet-drda.c

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
(def (dissect-drda buffer)
  "DRDA"
  (try
    (let* (
           (rslsetflg (unwrap (read-u8 buffer 0)))
           (rslsetflg-unused (extract-bits rslsetflg 0xE0 5))
           (rslsetflg-dsconly (extract-bits rslsetflg 0x10 4))
           (rslsetflg-reserved (extract-bits rslsetflg 0x3 0))
           (monitor (unwrap (read-u32be buffer 0)))
           (monitor-etime (extract-bits monitor 0x80000000 31))
           (monitor-reserved (extract-bits monitor 0x7FFFFFFF 0))
           (ddm-length (unwrap (read-u16be buffer 0)))
           (pktobj (unwrap (slice buffer 0 1)))
           (qryblkfct (unwrap (read-u32be buffer 0)))
           (qryinsid (unwrap (slice buffer 0 1)))
           (qryrowset (unwrap (read-u32be buffer 0)))
           (meddtasz (unwrap (read-u64be buffer 0)))
           (smldtasz (unwrap (read-u64be buffer 0)))
           (qryblksz (unwrap (read-u32be buffer 0)))
           (rtnsetstt (unwrap (read-u8 buffer 0)))
           (rdbinttkn (unwrap (slice buffer 0 1)))
           (respktsz (unwrap (read-u32be buffer 0)))
           (sectkn (unwrap (slice buffer 0 1)))
           (typdefnam (unwrap (slice buffer 0 1)))
           (mgrlvln (unwrap (read-u16be buffer 0)))
           (ddm-magic (unwrap (read-u8 buffer 2)))
           (ddm-rc (unwrap (read-u16be buffer 4)))
           (sqlerrmsg (unwrap (slice buffer 4 1)))
           (sqlcode (unwrap (read-u32be buffer 4)))
           (sqlstate (unwrap (slice buffer 4 1)))
           (ddm-length2 (unwrap (read-u16be buffer 6)))
           (clob-length (unwrap (read-u32be buffer 8)))
           (param-length (unwrap (read-u16be buffer 10)))
           (param-data (unwrap (slice buffer 10 1)))
           (param-data-ebcdic (unwrap (slice buffer 10 1)))
           (rdbnam (unwrap (slice buffer 56 1)))
           (rdbnam-ebcdic (unwrap (slice buffer 56 1)))
           (rdbcolid (unwrap (slice buffer 58 1)))
           (rdbcolid-ebcdic (unwrap (slice buffer 58 1)))
           (pkgid (unwrap (slice buffer 60 1)))
           (pkgid-ebcdic (unwrap (slice buffer 60 1)))
           (pkgsn (unwrap (read-u16be buffer 68)))
           )

      (ok (list
        (cons 'rslsetflg (list (cons 'raw rslsetflg) (cons 'formatted (fmt-hex rslsetflg))))
        (cons 'rslsetflg-unused (list (cons 'raw rslsetflg-unused) (cons 'formatted (if (= rslsetflg-unused 0) "Not set" "Set"))))
        (cons 'rslsetflg-dsconly (list (cons 'raw rslsetflg-dsconly) (cons 'formatted (if (= rslsetflg-dsconly 0) "Not set" "Set"))))
        (cons 'rslsetflg-reserved (list (cons 'raw rslsetflg-reserved) (cons 'formatted (if (= rslsetflg-reserved 0) "Not set" "Set"))))
        (cons 'monitor (list (cons 'raw monitor) (cons 'formatted (fmt-hex monitor))))
        (cons 'monitor-etime (list (cons 'raw monitor-etime) (cons 'formatted (if (= monitor-etime 0) "Not set" "Set"))))
        (cons 'monitor-reserved (list (cons 'raw monitor-reserved) (cons 'formatted (if (= monitor-reserved 0) "Not set" "Set"))))
        (cons 'ddm-length (list (cons 'raw ddm-length) (cons 'formatted (number->string ddm-length))))
        (cons 'pktobj (list (cons 'raw pktobj) (cons 'formatted (fmt-bytes pktobj))))
        (cons 'qryblkfct (list (cons 'raw qryblkfct) (cons 'formatted (number->string qryblkfct))))
        (cons 'qryinsid (list (cons 'raw qryinsid) (cons 'formatted (fmt-bytes qryinsid))))
        (cons 'qryrowset (list (cons 'raw qryrowset) (cons 'formatted (number->string qryrowset))))
        (cons 'meddtasz (list (cons 'raw meddtasz) (cons 'formatted (number->string meddtasz))))
        (cons 'smldtasz (list (cons 'raw smldtasz) (cons 'formatted (number->string smldtasz))))
        (cons 'qryblksz (list (cons 'raw qryblksz) (cons 'formatted (number->string qryblksz))))
        (cons 'rtnsetstt (list (cons 'raw rtnsetstt) (cons 'formatted (number->string rtnsetstt))))
        (cons 'rdbinttkn (list (cons 'raw rdbinttkn) (cons 'formatted (fmt-bytes rdbinttkn))))
        (cons 'respktsz (list (cons 'raw respktsz) (cons 'formatted (number->string respktsz))))
        (cons 'sectkn (list (cons 'raw sectkn) (cons 'formatted (fmt-bytes sectkn))))
        (cons 'typdefnam (list (cons 'raw typdefnam) (cons 'formatted (utf8->string typdefnam))))
        (cons 'mgrlvln (list (cons 'raw mgrlvln) (cons 'formatted (number->string mgrlvln))))
        (cons 'ddm-magic (list (cons 'raw ddm-magic) (cons 'formatted (fmt-hex ddm-magic))))
        (cons 'ddm-rc (list (cons 'raw ddm-rc) (cons 'formatted (number->string ddm-rc))))
        (cons 'sqlerrmsg (list (cons 'raw sqlerrmsg) (cons 'formatted (utf8->string sqlerrmsg))))
        (cons 'sqlcode (list (cons 'raw sqlcode) (cons 'formatted (number->string sqlcode))))
        (cons 'sqlstate (list (cons 'raw sqlstate) (cons 'formatted (utf8->string sqlstate))))
        (cons 'ddm-length2 (list (cons 'raw ddm-length2) (cons 'formatted (number->string ddm-length2))))
        (cons 'clob-length (list (cons 'raw clob-length) (cons 'formatted (number->string clob-length))))
        (cons 'param-length (list (cons 'raw param-length) (cons 'formatted (number->string param-length))))
        (cons 'param-data (list (cons 'raw param-data) (cons 'formatted (utf8->string param-data))))
        (cons 'param-data-ebcdic (list (cons 'raw param-data-ebcdic) (cons 'formatted (utf8->string param-data-ebcdic))))
        (cons 'rdbnam (list (cons 'raw rdbnam) (cons 'formatted (utf8->string rdbnam))))
        (cons 'rdbnam-ebcdic (list (cons 'raw rdbnam-ebcdic) (cons 'formatted (utf8->string rdbnam-ebcdic))))
        (cons 'rdbcolid (list (cons 'raw rdbcolid) (cons 'formatted (utf8->string rdbcolid))))
        (cons 'rdbcolid-ebcdic (list (cons 'raw rdbcolid-ebcdic) (cons 'formatted (utf8->string rdbcolid-ebcdic))))
        (cons 'pkgid (list (cons 'raw pkgid) (cons 'formatted (utf8->string pkgid))))
        (cons 'pkgid-ebcdic (list (cons 'raw pkgid-ebcdic) (cons 'formatted (utf8->string pkgid-ebcdic))))
        (cons 'pkgsn (list (cons 'raw pkgsn) (cons 'formatted (number->string pkgsn))))
        )))

    (catch (e)
      (err (str "DRDA parse error: " e)))))

;; dissect-drda: parse DRDA from bytevector
;; Returns (ok fields-alist) or (err message)