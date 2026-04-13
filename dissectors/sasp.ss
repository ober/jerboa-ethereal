;; packet-sasp.c
;; Routines for sasp packet dissection
;; Copyright 2010, Venkateshwaran Dorai<venkateshwaran.d@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/sasp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-sasp.c

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
(def (dissect-sasp buffer)
  "Server/Application State Protocol"
  (try
    (let* (
           (length (unwrap (read-u16be buffer 2)))
           (vrsn (unwrap (read-u8 buffer 4)))
           (len (unwrap (read-u32be buffer 5)))
           (id (unwrap (read-u32be buffer 9)))
           (reg-req-sz (unwrap (read-u32be buffer 15)))
           (reg-rep-sz (unwrap (read-u16be buffer 20)))
           (dereg-req-sz (unwrap (read-u32be buffer 22)))
           (req-reason-flag (unwrap (read-u8 buffer 25)))
           (gmd-cnt (unwrap (read-u16be buffer 26)))
           (dereg-rep-sz (unwrap (read-u16be buffer 28)))
           (sendwt-sz (unwrap (read-u16be buffer 30)))
           (sendwt-gwedcnt (unwrap (read-u16be buffer 32)))
           (setmemstate-req-sz (unwrap (read-u16be buffer 34)))
           (req-lbflag (unwrap (read-u8 buffer 36)))
           (setmemstate-req-gmsd-cnt (unwrap (read-u16be buffer 37)))
           (setmemstate-rep-sz (unwrap (read-u16be buffer 39)))
           (memdatacomp-sz (unwrap (read-u16be buffer 43)))
           (memdatacomp-port (unwrap (read-u16be buffer 46)))
           (memdatacomp-ip (unwrap (slice buffer 48 16)))
           (memdatacomp-lab-len (unwrap (read-u8 buffer 64)))
           (memdatacomp-label (unwrap (slice buffer 65 1)))
           (grpdatacomp-sz (unwrap (read-u16be buffer 67)))
           (grpdatacomp-LB-uid-len (unwrap (read-u8 buffer 69)))
           (grpdatacomp-LB-uid (unwrap (slice buffer 70 1)))
           (grpdatacomp-grp-name-len (unwrap (read-u8 buffer 70)))
           (grpdatacomp-grp-name (unwrap (slice buffer 71 1)))
           (grp-memdatacomp-sz (unwrap (read-u16be buffer 73)))
           (grp-memdatacomp-cnt (unwrap (read-u16be buffer 75)))
           (wt-req-sz (unwrap (read-u16be buffer 77)))
           (wt-req-gd-cnt (unwrap (read-u16be buffer 79)))
           (wt-rep-sz (unwrap (read-u16be buffer 81)))
           (wt-rep-interval (unwrap (read-u16be buffer 84)))
           (wt-rep-gwed-cnt (unwrap (read-u16be buffer 86)))
           (setlbstate-req-sz (unwrap (read-u16be buffer 88)))
           (setlbstate-req-LB-uid-len (unwrap (read-u8 buffer 90)))
           (setlbstate-req-LB-uid (unwrap (slice buffer 91 1)))
           (setlbstate-rep-sz (unwrap (read-u16be buffer 92)))
           (grp-memstatedatacomp-sz (unwrap (read-u16be buffer 96)))
           (grp-memstatedatacomp-cnt (unwrap (read-u16be buffer 98)))
           (memstatedatacomp-sz (unwrap (read-u16be buffer 102)))
           (memstatedatacomp-state (unwrap (read-u8 buffer 104)))
           (memstatedatacomp-quiesce-flag (unwrap (read-u8 buffer 105)))
           (weight-entry-data-comp-sz (unwrap (read-u16be buffer 108)))
           (weight-entry-data-comp-state (unwrap (read-u8 buffer 110)))
           (weight-entry-data-comp-weight (unwrap (read-u16be buffer 112)))
           (grp-wt-entry-datacomp-sz (unwrap (read-u16be buffer 116)))
           (grp-wt-entry-datacomp-cnt (unwrap (read-u16be buffer 118)))
           (type (unwrap (read-u16be buffer 120)))
           )

      (ok (list
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'vrsn (list (cons 'raw vrsn) (cons 'formatted (number->string vrsn))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        (cons 'reg-req-sz (list (cons 'raw reg-req-sz) (cons 'formatted (number->string reg-req-sz))))
        (cons 'reg-rep-sz (list (cons 'raw reg-rep-sz) (cons 'formatted (number->string reg-rep-sz))))
        (cons 'dereg-req-sz (list (cons 'raw dereg-req-sz) (cons 'formatted (number->string dereg-req-sz))))
        (cons 'req-reason-flag (list (cons 'raw req-reason-flag) (cons 'formatted (fmt-hex req-reason-flag))))
        (cons 'gmd-cnt (list (cons 'raw gmd-cnt) (cons 'formatted (number->string gmd-cnt))))
        (cons 'dereg-rep-sz (list (cons 'raw dereg-rep-sz) (cons 'formatted (number->string dereg-rep-sz))))
        (cons 'sendwt-sz (list (cons 'raw sendwt-sz) (cons 'formatted (number->string sendwt-sz))))
        (cons 'sendwt-gwedcnt (list (cons 'raw sendwt-gwedcnt) (cons 'formatted (number->string sendwt-gwedcnt))))
        (cons 'setmemstate-req-sz (list (cons 'raw setmemstate-req-sz) (cons 'formatted (number->string setmemstate-req-sz))))
        (cons 'req-lbflag (list (cons 'raw req-lbflag) (cons 'formatted (number->string req-lbflag))))
        (cons 'setmemstate-req-gmsd-cnt (list (cons 'raw setmemstate-req-gmsd-cnt) (cons 'formatted (number->string setmemstate-req-gmsd-cnt))))
        (cons 'setmemstate-rep-sz (list (cons 'raw setmemstate-rep-sz) (cons 'formatted (number->string setmemstate-rep-sz))))
        (cons 'memdatacomp-sz (list (cons 'raw memdatacomp-sz) (cons 'formatted (number->string memdatacomp-sz))))
        (cons 'memdatacomp-port (list (cons 'raw memdatacomp-port) (cons 'formatted (number->string memdatacomp-port))))
        (cons 'memdatacomp-ip (list (cons 'raw memdatacomp-ip) (cons 'formatted (fmt-ipv6-address memdatacomp-ip))))
        (cons 'memdatacomp-lab-len (list (cons 'raw memdatacomp-lab-len) (cons 'formatted (number->string memdatacomp-lab-len))))
        (cons 'memdatacomp-label (list (cons 'raw memdatacomp-label) (cons 'formatted (utf8->string memdatacomp-label))))
        (cons 'grpdatacomp-sz (list (cons 'raw grpdatacomp-sz) (cons 'formatted (number->string grpdatacomp-sz))))
        (cons 'grpdatacomp-LB-uid-len (list (cons 'raw grpdatacomp-LB-uid-len) (cons 'formatted (number->string grpdatacomp-LB-uid-len))))
        (cons 'grpdatacomp-LB-uid (list (cons 'raw grpdatacomp-LB-uid) (cons 'formatted (utf8->string grpdatacomp-LB-uid))))
        (cons 'grpdatacomp-grp-name-len (list (cons 'raw grpdatacomp-grp-name-len) (cons 'formatted (number->string grpdatacomp-grp-name-len))))
        (cons 'grpdatacomp-grp-name (list (cons 'raw grpdatacomp-grp-name) (cons 'formatted (utf8->string grpdatacomp-grp-name))))
        (cons 'grp-memdatacomp-sz (list (cons 'raw grp-memdatacomp-sz) (cons 'formatted (number->string grp-memdatacomp-sz))))
        (cons 'grp-memdatacomp-cnt (list (cons 'raw grp-memdatacomp-cnt) (cons 'formatted (number->string grp-memdatacomp-cnt))))
        (cons 'wt-req-sz (list (cons 'raw wt-req-sz) (cons 'formatted (number->string wt-req-sz))))
        (cons 'wt-req-gd-cnt (list (cons 'raw wt-req-gd-cnt) (cons 'formatted (number->string wt-req-gd-cnt))))
        (cons 'wt-rep-sz (list (cons 'raw wt-rep-sz) (cons 'formatted (number->string wt-rep-sz))))
        (cons 'wt-rep-interval (list (cons 'raw wt-rep-interval) (cons 'formatted (number->string wt-rep-interval))))
        (cons 'wt-rep-gwed-cnt (list (cons 'raw wt-rep-gwed-cnt) (cons 'formatted (number->string wt-rep-gwed-cnt))))
        (cons 'setlbstate-req-sz (list (cons 'raw setlbstate-req-sz) (cons 'formatted (number->string setlbstate-req-sz))))
        (cons 'setlbstate-req-LB-uid-len (list (cons 'raw setlbstate-req-LB-uid-len) (cons 'formatted (number->string setlbstate-req-LB-uid-len))))
        (cons 'setlbstate-req-LB-uid (list (cons 'raw setlbstate-req-LB-uid) (cons 'formatted (utf8->string setlbstate-req-LB-uid))))
        (cons 'setlbstate-rep-sz (list (cons 'raw setlbstate-rep-sz) (cons 'formatted (number->string setlbstate-rep-sz))))
        (cons 'grp-memstatedatacomp-sz (list (cons 'raw grp-memstatedatacomp-sz) (cons 'formatted (number->string grp-memstatedatacomp-sz))))
        (cons 'grp-memstatedatacomp-cnt (list (cons 'raw grp-memstatedatacomp-cnt) (cons 'formatted (number->string grp-memstatedatacomp-cnt))))
        (cons 'memstatedatacomp-sz (list (cons 'raw memstatedatacomp-sz) (cons 'formatted (number->string memstatedatacomp-sz))))
        (cons 'memstatedatacomp-state (list (cons 'raw memstatedatacomp-state) (cons 'formatted (fmt-hex memstatedatacomp-state))))
        (cons 'memstatedatacomp-quiesce-flag (list (cons 'raw memstatedatacomp-quiesce-flag) (cons 'formatted (number->string memstatedatacomp-quiesce-flag))))
        (cons 'weight-entry-data-comp-sz (list (cons 'raw weight-entry-data-comp-sz) (cons 'formatted (number->string weight-entry-data-comp-sz))))
        (cons 'weight-entry-data-comp-state (list (cons 'raw weight-entry-data-comp-state) (cons 'formatted (fmt-hex weight-entry-data-comp-state))))
        (cons 'weight-entry-data-comp-weight (list (cons 'raw weight-entry-data-comp-weight) (cons 'formatted (number->string weight-entry-data-comp-weight))))
        (cons 'grp-wt-entry-datacomp-sz (list (cons 'raw grp-wt-entry-datacomp-sz) (cons 'formatted (number->string grp-wt-entry-datacomp-sz))))
        (cons 'grp-wt-entry-datacomp-cnt (list (cons 'raw grp-wt-entry-datacomp-cnt) (cons 'formatted (number->string grp-wt-entry-datacomp-cnt))))
        (cons 'type (list (cons 'raw type) (cons 'formatted (fmt-hex type))))
        )))

    (catch (e)
      (err (str "SASP parse error: " e)))))

;; dissect-sasp: parse SASP from bytevector
;; Returns (ok fields-alist) or (err message)