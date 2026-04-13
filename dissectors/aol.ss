;; packet-aol.c
;;
;; Routines for dissecting the America Online protocol
;; Copyright (C) 2012 Tim Hentenaar <tim at hentenaar dot com>
;;
;; More information on the P3 frame protocol can be found on page 66 of:
;; http://koin.org/files/aol.aim/aol/fdo/manuals/WAOL.doc
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/aol.ss
;; Auto-generated from wireshark/epan/dissectors/packet-aol.c

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
(def (dissect-aol buffer)
  "America Online"
  (try
    (let* (
           (start (unwrap (read-u8 buffer 0)))
           (version (unwrap (read-u8 buffer 1)))
           (subversion (unwrap (read-u8 buffer 2)))
           (unused (unwrap (read-u8 buffer 3)))
           (len (unwrap (read-u16be buffer 3)))
           (machine-mem (unwrap (read-u8 buffer 4)))
           (app-mem (unwrap (read-u8 buffer 5)))
           (tx-seq (unwrap (read-u8 buffer 5)))
           (pc-type (unwrap (read-u16be buffer 6)))
           (rx-seq (unwrap (read-u8 buffer 6)))
           (rel-month (unwrap (read-u8 buffer 8)))
           (token (unwrap (slice buffer 8 2)))
           (rel-day (unwrap (read-u8 buffer 9)))
           (cust-class (unwrap (read-u16be buffer 10)))
           (data (unwrap (slice buffer 10 1)))
           (end (unwrap (read-u8 buffer 10)))
           (udo-timestamp (unwrap (read-u32be buffer 12)))
           (dos-ver (unwrap (read-u16be buffer 16)))
           (sess-flags (unwrap (read-u16be buffer 18)))
           (video-type (unwrap (read-u8 buffer 20)))
           (cpu-type (unwrap (read-u8 buffer 21)))
           (media-type (unwrap (read-u32be buffer 22)))
           (win-ver (unwrap (read-u32be buffer 26)))
           (horiz-res (unwrap (read-u16be buffer 31)))
           (vert-res (unwrap (read-u16be buffer 33)))
           (num-colors (unwrap (read-u16be buffer 35)))
           (filler (unwrap (read-u8 buffer 37)))
           (region (unwrap (read-u16be buffer 38)))
           (lang (unwrap (read-u64be buffer 40)))
           (conn-spd (unwrap (read-u8 buffer 48)))
           )

      (ok (list
        (cons 'start (list (cons 'raw start) (cons 'formatted (fmt-hex start))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'subversion (list (cons 'raw subversion) (cons 'formatted (number->string subversion))))
        (cons 'unused (list (cons 'raw unused) (cons 'formatted (fmt-hex unused))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'machine-mem (list (cons 'raw machine-mem) (cons 'formatted (number->string machine-mem))))
        (cons 'app-mem (list (cons 'raw app-mem) (cons 'formatted (number->string app-mem))))
        (cons 'tx-seq (list (cons 'raw tx-seq) (cons 'formatted (fmt-hex tx-seq))))
        (cons 'pc-type (list (cons 'raw pc-type) (cons 'formatted (fmt-hex pc-type))))
        (cons 'rx-seq (list (cons 'raw rx-seq) (cons 'formatted (fmt-hex rx-seq))))
        (cons 'rel-month (list (cons 'raw rel-month) (cons 'formatted (number->string rel-month))))
        (cons 'token (list (cons 'raw token) (cons 'formatted (utf8->string token))))
        (cons 'rel-day (list (cons 'raw rel-day) (cons 'formatted (number->string rel-day))))
        (cons 'cust-class (list (cons 'raw cust-class) (cons 'formatted (fmt-hex cust-class))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'end (list (cons 'raw end) (cons 'formatted (fmt-hex end))))
        (cons 'udo-timestamp (list (cons 'raw udo-timestamp) (cons 'formatted (number->string udo-timestamp))))
        (cons 'dos-ver (list (cons 'raw dos-ver) (cons 'formatted (fmt-hex dos-ver))))
        (cons 'sess-flags (list (cons 'raw sess-flags) (cons 'formatted (fmt-hex sess-flags))))
        (cons 'video-type (list (cons 'raw video-type) (cons 'formatted (number->string video-type))))
        (cons 'cpu-type (list (cons 'raw cpu-type) (cons 'formatted (number->string cpu-type))))
        (cons 'media-type (list (cons 'raw media-type) (cons 'formatted (fmt-hex media-type))))
        (cons 'win-ver (list (cons 'raw win-ver) (cons 'formatted (fmt-hex win-ver))))
        (cons 'horiz-res (list (cons 'raw horiz-res) (cons 'formatted (number->string horiz-res))))
        (cons 'vert-res (list (cons 'raw vert-res) (cons 'formatted (number->string vert-res))))
        (cons 'num-colors (list (cons 'raw num-colors) (cons 'formatted (number->string num-colors))))
        (cons 'filler (list (cons 'raw filler) (cons 'formatted (fmt-hex filler))))
        (cons 'region (list (cons 'raw region) (cons 'formatted (fmt-hex region))))
        (cons 'lang (list (cons 'raw lang) (cons 'formatted (fmt-hex lang))))
        (cons 'conn-spd (list (cons 'raw conn-spd) (cons 'formatted (fmt-hex conn-spd))))
        )))

    (catch (e)
      (err (str "AOL parse error: " e)))))

;; dissect-aol: parse AOL from bytevector
;; Returns (ok fields-alist) or (err message)