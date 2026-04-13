;; packet-fmp.c
;; Routines for fmp dissection
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/fmp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-fmp.c

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
(def (dissect-fmp buffer)
  "File Mapping Protocol"
  (try
    (let* (
           (fsid (unwrap (read-u32be buffer 14)))
           (fid (unwrap (read-u16be buffer 18)))
           (tid (unwrap (read-u16be buffer 20)))
           (uid (unwrap (read-u16be buffer 22)))
           (cifsport (unwrap (read-u16be buffer 24)))
           (plugInID (unwrap (slice buffer 30 1)))
           (cmd (unwrap (read-u32be buffer 30)))
           (number-of-disk (unwrap (read-u32be buffer 34)))
           (sigoffset (unwrap (read-u32be buffer 90)))
           (length-of-list (unwrap (read-u32be buffer 94)))
           (length-of-volume-list (unwrap (read-u32be buffer 102)))
           (volindex (unwrap (read-u32be buffer 110)))
           (blockindex (unwrap (read-u32be buffer 114)))
           (cap (unwrap (read-u32be buffer 118)))
           (cap-revoke-handle-list (extract-bits cap 0x0 0))
           (cap-unc-names (extract-bits cap 0x0 0))
           (cap-cifsv2 (extract-bits cap 0x0 0))
           )

      (ok (list
        (cons 'fsid (list (cons 'raw fsid) (cons 'formatted (number->string fsid))))
        (cons 'fid (list (cons 'raw fid) (cons 'formatted (number->string fid))))
        (cons 'tid (list (cons 'raw tid) (cons 'formatted (number->string tid))))
        (cons 'uid (list (cons 'raw uid) (cons 'formatted (number->string uid))))
        (cons 'cifsport (list (cons 'raw cifsport) (cons 'formatted (number->string cifsport))))
        (cons 'plugInID (list (cons 'raw plugInID) (cons 'formatted (fmt-bytes plugInID))))
        (cons 'cmd (list (cons 'raw cmd) (cons 'formatted (number->string cmd))))
        (cons 'number-of-disk (list (cons 'raw number-of-disk) (cons 'formatted (number->string number-of-disk))))
        (cons 'sigoffset (list (cons 'raw sigoffset) (cons 'formatted (fmt-hex sigoffset))))
        (cons 'length-of-list (list (cons 'raw length-of-list) (cons 'formatted (number->string length-of-list))))
        (cons 'length-of-volume-list (list (cons 'raw length-of-volume-list) (cons 'formatted (number->string length-of-volume-list))))
        (cons 'volindex (list (cons 'raw volindex) (cons 'formatted (fmt-hex volindex))))
        (cons 'blockindex (list (cons 'raw blockindex) (cons 'formatted (fmt-hex blockindex))))
        (cons 'cap (list (cons 'raw cap) (cons 'formatted (fmt-hex cap))))
        (cons 'cap-revoke-handle-list (list (cons 'raw cap-revoke-handle-list) (cons 'formatted (if (= cap-revoke-handle-list 0) "Not set" "Set"))))
        (cons 'cap-unc-names (list (cons 'raw cap-unc-names) (cons 'formatted (if (= cap-unc-names 0) "Not set" "Set"))))
        (cons 'cap-cifsv2 (list (cons 'raw cap-cifsv2) (cons 'formatted (if (= cap-cifsv2 0) "Not set" "Set"))))
        )))

    (catch (e)
      (err (str "FMP parse error: " e)))))

;; dissect-fmp: parse FMP from bytevector
;; Returns (ok fields-alist) or (err message)