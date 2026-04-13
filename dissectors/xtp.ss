;; packet-xtp.c
;; Routines for Xpress Transport Protocol dissection
;; Copyright 2008, Shigeo Nakamura <naka_shigeo@yahoo.co.jp>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Ref: http://www.packeteer.com/resources/prod-sol/XTP.pdf
;;

;; jerboa-ethereal/dissectors/xtp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-xtp.c

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
(def (dissect-xtp buffer)
  "Xpress Transport Protocol"
  (try
    (let* (
           (key (unwrap (read-u64be buffer 0)))
           (aseg-alen (unwrap (read-u16be buffer 2)))
           (aseg-adomain (unwrap (read-u8 buffer 4)))
           (aseg-address (unwrap (read-u32be buffer 4)))
           (aseg-dsthost (unwrap (read-u32be buffer 8)))
           (cmd (unwrap (read-u32be buffer 8)))
           (cmd-options (unwrap (read-u24be buffer 8)))
           (cmd-options-nocheck (extract-bits cmd-options 0x0 0))
           (cmd-options-edge (extract-bits cmd-options 0x0 0))
           (cmd-options-noerr (extract-bits cmd-options 0x0 0))
           (cmd-options-multi (extract-bits cmd-options 0x0 0))
           (cmd-options-res (extract-bits cmd-options 0x0 0))
           (cmd-options-sort (extract-bits cmd-options 0x0 0))
           (cmd-options-noflow (extract-bits cmd-options 0x0 0))
           (cmd-options-fastnak (extract-bits cmd-options 0x0 0))
           (cmd-options-sreq (extract-bits cmd-options 0x0 0))
           (cmd-options-dreq (extract-bits cmd-options 0x0 0))
           (cmd-options-rclose (extract-bits cmd-options 0x0 0))
           (cmd-options-wclose (extract-bits cmd-options 0x0 0))
           (cmd-options-eom (extract-bits cmd-options 0x0 0))
           (cmd-options-end (extract-bits cmd-options 0x0 0))
           (cmd-options-btag (extract-bits cmd-options 0x0 0))
           (cmd-ptype (unwrap (read-u8 buffer 11)))
           (dlen (unwrap (read-u32be buffer 11)))
           (aseg-srchost (unwrap (read-u32be buffer 12)))
           (aseg-dstport (unwrap (read-u16be buffer 16)))
           (sort (unwrap (read-u16be buffer 17)))
           (aseg-srcport (unwrap (read-u16be buffer 18)))
           (sync (unwrap (read-u32be buffer 19)))
           (seq (unwrap (read-u64be buffer 23)))
           (tcntl-rseq (unwrap (read-u64be buffer 44)))
           (tcntl-alloc (unwrap (read-u64be buffer 52)))
           (tcntl-echo (unwrap (read-u32be buffer 56)))
           (tcntl-rsvd (unwrap (read-u32be buffer 60)))
           (tcntl-xkey (unwrap (read-u64be buffer 64)))
           (tspec-tlen (unwrap (read-u16be buffer 74)))
           (tspec-tformat (unwrap (read-u8 buffer 76)))
           (tspec-traffic (unwrap (read-u32be buffer 76)))
           (tspec-maxdata (unwrap (read-u32be buffer 80)))
           (tspec-inrate (unwrap (read-u32be buffer 84)))
           (tspec-inburst (unwrap (read-u32be buffer 88)))
           (tspec-outrate (unwrap (read-u32be buffer 92)))
           (tspec-outburst (unwrap (read-u32be buffer 96)))
           (btag (unwrap (read-u64be buffer 100)))
           (data (unwrap (slice buffer 108 1)))
           (cntl-rseq (unwrap (read-u64be buffer 124)))
           (cntl-alloc (unwrap (read-u64be buffer 132)))
           (cntl-echo (unwrap (read-u32be buffer 136)))
           (ecntl-rseq (unwrap (read-u64be buffer 160)))
           (ecntl-alloc (unwrap (read-u64be buffer 168)))
           (ecntl-echo (unwrap (read-u32be buffer 176)))
           (ecntl-nspan (unwrap (read-u32be buffer 180)))
           (ecntl-span-left (unwrap (read-u64be buffer 184)))
           (ecntl-span-right (unwrap (read-u64be buffer 192)))
           (diag-msg (unwrap (slice buffer 208 1)))
           )

      (ok (list
        (cons 'key (list (cons 'raw key) (cons 'formatted (fmt-hex key))))
        (cons 'aseg-alen (list (cons 'raw aseg-alen) (cons 'formatted (number->string aseg-alen))))
        (cons 'aseg-adomain (list (cons 'raw aseg-adomain) (cons 'formatted (number->string aseg-adomain))))
        (cons 'aseg-address (list (cons 'raw aseg-address) (cons 'formatted (number->string aseg-address))))
        (cons 'aseg-dsthost (list (cons 'raw aseg-dsthost) (cons 'formatted (fmt-ipv4 aseg-dsthost))))
        (cons 'cmd (list (cons 'raw cmd) (cons 'formatted (fmt-hex cmd))))
        (cons 'cmd-options (list (cons 'raw cmd-options) (cons 'formatted (fmt-hex cmd-options))))
        (cons 'cmd-options-nocheck (list (cons 'raw cmd-options-nocheck) (cons 'formatted (if (= cmd-options-nocheck 0) "Not set" "Set"))))
        (cons 'cmd-options-edge (list (cons 'raw cmd-options-edge) (cons 'formatted (if (= cmd-options-edge 0) "Not set" "Set"))))
        (cons 'cmd-options-noerr (list (cons 'raw cmd-options-noerr) (cons 'formatted (if (= cmd-options-noerr 0) "Not set" "Set"))))
        (cons 'cmd-options-multi (list (cons 'raw cmd-options-multi) (cons 'formatted (if (= cmd-options-multi 0) "Not set" "Set"))))
        (cons 'cmd-options-res (list (cons 'raw cmd-options-res) (cons 'formatted (if (= cmd-options-res 0) "Not set" "Set"))))
        (cons 'cmd-options-sort (list (cons 'raw cmd-options-sort) (cons 'formatted (if (= cmd-options-sort 0) "Not set" "Set"))))
        (cons 'cmd-options-noflow (list (cons 'raw cmd-options-noflow) (cons 'formatted (if (= cmd-options-noflow 0) "Not set" "Set"))))
        (cons 'cmd-options-fastnak (list (cons 'raw cmd-options-fastnak) (cons 'formatted (if (= cmd-options-fastnak 0) "Not set" "Set"))))
        (cons 'cmd-options-sreq (list (cons 'raw cmd-options-sreq) (cons 'formatted (if (= cmd-options-sreq 0) "Not set" "Set"))))
        (cons 'cmd-options-dreq (list (cons 'raw cmd-options-dreq) (cons 'formatted (if (= cmd-options-dreq 0) "Not set" "Set"))))
        (cons 'cmd-options-rclose (list (cons 'raw cmd-options-rclose) (cons 'formatted (if (= cmd-options-rclose 0) "Not set" "Set"))))
        (cons 'cmd-options-wclose (list (cons 'raw cmd-options-wclose) (cons 'formatted (if (= cmd-options-wclose 0) "Not set" "Set"))))
        (cons 'cmd-options-eom (list (cons 'raw cmd-options-eom) (cons 'formatted (if (= cmd-options-eom 0) "Not set" "Set"))))
        (cons 'cmd-options-end (list (cons 'raw cmd-options-end) (cons 'formatted (if (= cmd-options-end 0) "Not set" "Set"))))
        (cons 'cmd-options-btag (list (cons 'raw cmd-options-btag) (cons 'formatted (if (= cmd-options-btag 0) "Not set" "Set"))))
        (cons 'cmd-ptype (list (cons 'raw cmd-ptype) (cons 'formatted (fmt-hex cmd-ptype))))
        (cons 'dlen (list (cons 'raw dlen) (cons 'formatted (number->string dlen))))
        (cons 'aseg-srchost (list (cons 'raw aseg-srchost) (cons 'formatted (fmt-ipv4 aseg-srchost))))
        (cons 'aseg-dstport (list (cons 'raw aseg-dstport) (cons 'formatted (number->string aseg-dstport))))
        (cons 'sort (list (cons 'raw sort) (cons 'formatted (number->string sort))))
        (cons 'aseg-srcport (list (cons 'raw aseg-srcport) (cons 'formatted (number->string aseg-srcport))))
        (cons 'sync (list (cons 'raw sync) (cons 'formatted (number->string sync))))
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (number->string seq))))
        (cons 'tcntl-rseq (list (cons 'raw tcntl-rseq) (cons 'formatted (number->string tcntl-rseq))))
        (cons 'tcntl-alloc (list (cons 'raw tcntl-alloc) (cons 'formatted (number->string tcntl-alloc))))
        (cons 'tcntl-echo (list (cons 'raw tcntl-echo) (cons 'formatted (number->string tcntl-echo))))
        (cons 'tcntl-rsvd (list (cons 'raw tcntl-rsvd) (cons 'formatted (number->string tcntl-rsvd))))
        (cons 'tcntl-xkey (list (cons 'raw tcntl-xkey) (cons 'formatted (fmt-hex tcntl-xkey))))
        (cons 'tspec-tlen (list (cons 'raw tspec-tlen) (cons 'formatted (number->string tspec-tlen))))
        (cons 'tspec-tformat (list (cons 'raw tspec-tformat) (cons 'formatted (number->string tspec-tformat))))
        (cons 'tspec-traffic (list (cons 'raw tspec-traffic) (cons 'formatted (number->string tspec-traffic))))
        (cons 'tspec-maxdata (list (cons 'raw tspec-maxdata) (cons 'formatted (number->string tspec-maxdata))))
        (cons 'tspec-inrate (list (cons 'raw tspec-inrate) (cons 'formatted (number->string tspec-inrate))))
        (cons 'tspec-inburst (list (cons 'raw tspec-inburst) (cons 'formatted (number->string tspec-inburst))))
        (cons 'tspec-outrate (list (cons 'raw tspec-outrate) (cons 'formatted (number->string tspec-outrate))))
        (cons 'tspec-outburst (list (cons 'raw tspec-outburst) (cons 'formatted (number->string tspec-outburst))))
        (cons 'btag (list (cons 'raw btag) (cons 'formatted (fmt-hex btag))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'cntl-rseq (list (cons 'raw cntl-rseq) (cons 'formatted (number->string cntl-rseq))))
        (cons 'cntl-alloc (list (cons 'raw cntl-alloc) (cons 'formatted (number->string cntl-alloc))))
        (cons 'cntl-echo (list (cons 'raw cntl-echo) (cons 'formatted (number->string cntl-echo))))
        (cons 'ecntl-rseq (list (cons 'raw ecntl-rseq) (cons 'formatted (number->string ecntl-rseq))))
        (cons 'ecntl-alloc (list (cons 'raw ecntl-alloc) (cons 'formatted (number->string ecntl-alloc))))
        (cons 'ecntl-echo (list (cons 'raw ecntl-echo) (cons 'formatted (number->string ecntl-echo))))
        (cons 'ecntl-nspan (list (cons 'raw ecntl-nspan) (cons 'formatted (number->string ecntl-nspan))))
        (cons 'ecntl-span-left (list (cons 'raw ecntl-span-left) (cons 'formatted (number->string ecntl-span-left))))
        (cons 'ecntl-span-right (list (cons 'raw ecntl-span-right) (cons 'formatted (number->string ecntl-span-right))))
        (cons 'diag-msg (list (cons 'raw diag-msg) (cons 'formatted (utf8->string diag-msg))))
        )))

    (catch (e)
      (err (str "XTP parse error: " e)))))

;; dissect-xtp: parse XTP from bytevector
;; Returns (ok fields-alist) or (err message)