;; packet-nvme-tcp.c
;; Routines for NVM Express over Fabrics(TCP) dissection
;; Code by Solganik Alexander <solganik@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nvme-tcp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nvme_tcp.c

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
(def (dissect-nvme-tcp buffer)
  "NVM Express Fabrics TCP"
  (try
    (let* (
           (tcp-icreq-pfv (unwrap (read-u16be buffer 0)))
           (tcp-icreq-hpda (unwrap (read-u8 buffer 0)))
           (tcp-icreq-digest (unwrap (read-u8 buffer 0)))
           (tcp-icreq-maxr2t (unwrap (read-u32be buffer 0)))
           (tcp-icresp-pfv (unwrap (read-u16be buffer 0)))
           (tcp-icresp-cpda (unwrap (read-u8 buffer 0)))
           (tcp-icresp-digest (unwrap (read-u8 buffer 0)))
           (tcp-icresp-maxdata (unwrap (read-u32be buffer 0)))
           (fabrics-cmd-cid (unwrap (read-u16be buffer 0)))
           (tcp-pdu-ttag (unwrap (read-u16be buffer 0)))
           (tcp-data-pdu-data-offset (unwrap (read-u32be buffer 0)))
           (tcp-data-pdu-data-length (unwrap (read-u32be buffer 0)))
           (tcp-data-pdu-data-resvd (unwrap (slice buffer 0 4)))
           (tcp-unknown-data (unwrap (slice buffer 0 1)))
           (tcp-h2ctermreq-phfo (unwrap (read-u32be buffer 0)))
           (tcp-h2ctermreq-phd (unwrap (read-u32be buffer 0)))
           (tcp-h2ctermreq-upfo (unwrap (read-u32be buffer 0)))
           (tcp-h2ctermreq-reserved (unwrap (read-u32be buffer 0)))
           (tcp-c2htermreq-phfo (unwrap (read-u32be buffer 0)))
           (tcp-c2htermreq-phd (unwrap (read-u32be buffer 0)))
           (tcp-c2htermreq-upfo (unwrap (read-u32be buffer 0)))
           (tcp-c2htermreq-reserved (unwrap (read-u32be buffer 0)))
           (tcp-r2t-offset (unwrap (read-u32be buffer 0)))
           (tcp-r2t-length (unwrap (read-u32be buffer 0)))
           (tcp-r2t-resvd (unwrap (slice buffer 0 4)))
           (tcp-hlen (unwrap (read-u8 buffer 0)))
           (tcp-pdo (unwrap (read-u8 buffer 0)))
           (tcp-plen (unwrap (read-u32be buffer 0)))
           )

      (ok (list
        (cons 'tcp-icreq-pfv (list (cons 'raw tcp-icreq-pfv) (cons 'formatted (number->string tcp-icreq-pfv))))
        (cons 'tcp-icreq-hpda (list (cons 'raw tcp-icreq-hpda) (cons 'formatted (number->string tcp-icreq-hpda))))
        (cons 'tcp-icreq-digest (list (cons 'raw tcp-icreq-digest) (cons 'formatted (number->string tcp-icreq-digest))))
        (cons 'tcp-icreq-maxr2t (list (cons 'raw tcp-icreq-maxr2t) (cons 'formatted (number->string tcp-icreq-maxr2t))))
        (cons 'tcp-icresp-pfv (list (cons 'raw tcp-icresp-pfv) (cons 'formatted (number->string tcp-icresp-pfv))))
        (cons 'tcp-icresp-cpda (list (cons 'raw tcp-icresp-cpda) (cons 'formatted (number->string tcp-icresp-cpda))))
        (cons 'tcp-icresp-digest (list (cons 'raw tcp-icresp-digest) (cons 'formatted (number->string tcp-icresp-digest))))
        (cons 'tcp-icresp-maxdata (list (cons 'raw tcp-icresp-maxdata) (cons 'formatted (number->string tcp-icresp-maxdata))))
        (cons 'fabrics-cmd-cid (list (cons 'raw fabrics-cmd-cid) (cons 'formatted (fmt-hex fabrics-cmd-cid))))
        (cons 'tcp-pdu-ttag (list (cons 'raw tcp-pdu-ttag) (cons 'formatted (fmt-hex tcp-pdu-ttag))))
        (cons 'tcp-data-pdu-data-offset (list (cons 'raw tcp-data-pdu-data-offset) (cons 'formatted (number->string tcp-data-pdu-data-offset))))
        (cons 'tcp-data-pdu-data-length (list (cons 'raw tcp-data-pdu-data-length) (cons 'formatted (number->string tcp-data-pdu-data-length))))
        (cons 'tcp-data-pdu-data-resvd (list (cons 'raw tcp-data-pdu-data-resvd) (cons 'formatted (fmt-bytes tcp-data-pdu-data-resvd))))
        (cons 'tcp-unknown-data (list (cons 'raw tcp-unknown-data) (cons 'formatted (fmt-bytes tcp-unknown-data))))
        (cons 'tcp-h2ctermreq-phfo (list (cons 'raw tcp-h2ctermreq-phfo) (cons 'formatted (fmt-hex tcp-h2ctermreq-phfo))))
        (cons 'tcp-h2ctermreq-phd (list (cons 'raw tcp-h2ctermreq-phd) (cons 'formatted (fmt-hex tcp-h2ctermreq-phd))))
        (cons 'tcp-h2ctermreq-upfo (list (cons 'raw tcp-h2ctermreq-upfo) (cons 'formatted (fmt-hex tcp-h2ctermreq-upfo))))
        (cons 'tcp-h2ctermreq-reserved (list (cons 'raw tcp-h2ctermreq-reserved) (cons 'formatted (fmt-hex tcp-h2ctermreq-reserved))))
        (cons 'tcp-c2htermreq-phfo (list (cons 'raw tcp-c2htermreq-phfo) (cons 'formatted (fmt-hex tcp-c2htermreq-phfo))))
        (cons 'tcp-c2htermreq-phd (list (cons 'raw tcp-c2htermreq-phd) (cons 'formatted (fmt-hex tcp-c2htermreq-phd))))
        (cons 'tcp-c2htermreq-upfo (list (cons 'raw tcp-c2htermreq-upfo) (cons 'formatted (fmt-hex tcp-c2htermreq-upfo))))
        (cons 'tcp-c2htermreq-reserved (list (cons 'raw tcp-c2htermreq-reserved) (cons 'formatted (fmt-hex tcp-c2htermreq-reserved))))
        (cons 'tcp-r2t-offset (list (cons 'raw tcp-r2t-offset) (cons 'formatted (number->string tcp-r2t-offset))))
        (cons 'tcp-r2t-length (list (cons 'raw tcp-r2t-length) (cons 'formatted (number->string tcp-r2t-length))))
        (cons 'tcp-r2t-resvd (list (cons 'raw tcp-r2t-resvd) (cons 'formatted (fmt-bytes tcp-r2t-resvd))))
        (cons 'tcp-hlen (list (cons 'raw tcp-hlen) (cons 'formatted (number->string tcp-hlen))))
        (cons 'tcp-pdo (list (cons 'raw tcp-pdo) (cons 'formatted (number->string tcp-pdo))))
        (cons 'tcp-plen (list (cons 'raw tcp-plen) (cons 'formatted (number->string tcp-plen))))
        )))

    (catch (e)
      (err (str "NVME-TCP parse error: " e)))))

;; dissect-nvme-tcp: parse NVME-TCP from bytevector
;; Returns (ok fields-alist) or (err message)