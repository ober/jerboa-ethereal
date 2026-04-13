;; packet-nvme-rdma.c
;; Routines for NVM Express over Fabrics(RDMA) dissection
;; Copyright 2016
;; Code by Parav Pandit
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nvme-rdma.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nvme_rdma.c

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
(def (dissect-nvme-rdma buffer)
  "NVM Express Fabrics RDMA"
  (try
    (let* (
           (rdma-cm-rej-recfmt (unwrap (read-u16be buffer 0)))
           (rdma-cm-rsp-recfmt (unwrap (read-u16be buffer 0)))
           (rdma-cm-req-recfmt (unwrap (read-u16be buffer 0)))
           (rdma-cm-rej-status (unwrap (read-u16be buffer 2)))
           (rdma-cm-rsp-crqsize (unwrap (read-u16be buffer 2)))
           (rdma-cm-rsp-reserved (unwrap (slice buffer 4 28)))
           (rdma-cm-req-hrqsize (unwrap (read-u16be buffer 4)))
           (rdma-cm-req-cntlid (unwrap (read-u16be buffer 8)))
           (rdma-cm-req-reserved (unwrap (slice buffer 10 22)))
           )

      (ok (list
        (cons 'rdma-cm-rej-recfmt (list (cons 'raw rdma-cm-rej-recfmt) (cons 'formatted (number->string rdma-cm-rej-recfmt))))
        (cons 'rdma-cm-rsp-recfmt (list (cons 'raw rdma-cm-rsp-recfmt) (cons 'formatted (number->string rdma-cm-rsp-recfmt))))
        (cons 'rdma-cm-req-recfmt (list (cons 'raw rdma-cm-req-recfmt) (cons 'formatted (number->string rdma-cm-req-recfmt))))
        (cons 'rdma-cm-rej-status (list (cons 'raw rdma-cm-rej-status) (cons 'formatted (fmt-hex rdma-cm-rej-status))))
        (cons 'rdma-cm-rsp-crqsize (list (cons 'raw rdma-cm-rsp-crqsize) (cons 'formatted (number->string rdma-cm-rsp-crqsize))))
        (cons 'rdma-cm-rsp-reserved (list (cons 'raw rdma-cm-rsp-reserved) (cons 'formatted (fmt-bytes rdma-cm-rsp-reserved))))
        (cons 'rdma-cm-req-hrqsize (list (cons 'raw rdma-cm-req-hrqsize) (cons 'formatted (number->string rdma-cm-req-hrqsize))))
        (cons 'rdma-cm-req-cntlid (list (cons 'raw rdma-cm-req-cntlid) (cons 'formatted (fmt-hex rdma-cm-req-cntlid))))
        (cons 'rdma-cm-req-reserved (list (cons 'raw rdma-cm-req-reserved) (cons 'formatted (fmt-bytes rdma-cm-req-reserved))))
        )))

    (catch (e)
      (err (str "NVME-RDMA parse error: " e)))))

;; dissect-nvme-rdma: parse NVME-RDMA from bytevector
;; Returns (ok fields-alist) or (err message)