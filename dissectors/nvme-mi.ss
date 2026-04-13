;; packet-nvme-mi.c
;; Routines for NVMe Management Interface (NVMe-MI), over MCTP
;; Copyright 2022, Jeremy Kerr <jk@codeconstruct.com.au>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nvme-mi.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nvme_mi.c

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
(def (dissect-nvme-mi buffer)
  "NVMe-MI"
  (try
    (let* (
           (mi-meb (unwrap (read-u8 buffer 0)))
           (mi-ror (unwrap (read-u8 buffer 0)))
           (mi-csi (unwrap (read-u32be buffer 0)))
           (mi-mctp-ic (unwrap (read-u8 buffer 0)))
           (mi-admin-status (unwrap (read-u8 buffer 0)))
           (mi-mi-status (unwrap (read-u8 buffer 0)))
           (mi-admin-flags (unwrap (read-u8 buffer 1)))
           (mi-admin-flags-doff (extract-bits mi-admin-flags 0x2 1))
           (mi-admin-flags-dlen (extract-bits mi-admin-flags 0x1 0))
           (mi-mi-nmresp (unwrap (read-u24be buffer 1)))
           (mi-admin-ctrl-id (unwrap (read-u16be buffer 2)))
           (mi-admin-sqe1 (unwrap (read-u32be buffer 4)))
           (mi-admin-cqe1 (unwrap (read-u32be buffer 4)))
           (mi-mi-cdw0 (unwrap (read-u32be buffer 4)))
           (mi-admin-sqe2 (unwrap (read-u32be buffer 8)))
           (mi-admin-cqe2 (unwrap (read-u32be buffer 8)))
           (mi-mi-cdw1 (unwrap (read-u32be buffer 8)))
           (mi-admin-sqe3 (unwrap (read-u32be buffer 12)))
           (mi-admin-cqe3 (unwrap (read-u32be buffer 12)))
           (mi-admin-sqe4 (unwrap (read-u32be buffer 16)))
           (mi-admin-sqe5 (unwrap (read-u32be buffer 20)))
           (mi-admin-doff (unwrap (read-u32be buffer 24)))
           (mi-admin-dlen (unwrap (read-u32be buffer 28)))
           (mi-admin-resv0 (unwrap (read-u32be buffer 32)))
           (mi-admin-resv1 (unwrap (read-u32be buffer 36)))
           (mi-admin-sqe10 (unwrap (read-u32be buffer 40)))
           (mi-admin-sqe11 (unwrap (read-u32be buffer 44)))
           (mi-admin-sqe12 (unwrap (read-u32be buffer 48)))
           (mi-admin-sqe13 (unwrap (read-u32be buffer 52)))
           (mi-admin-sqe14 (unwrap (read-u32be buffer 56)))
           (mi-admin-sqe15 (unwrap (read-u32be buffer 60)))
           )

      (ok (list
        (cons 'mi-meb (list (cons 'raw mi-meb) (cons 'formatted (if (= mi-meb 0) "data in message" "data in MEB"))))
        (cons 'mi-ror (list (cons 'raw mi-ror) (cons 'formatted (if (= mi-ror 0) "False" "True"))))
        (cons 'mi-csi (list (cons 'raw mi-csi) (cons 'formatted (number->string mi-csi))))
        (cons 'mi-mctp-ic (list (cons 'raw mi-mctp-ic) (cons 'formatted (number->string mi-mctp-ic))))
        (cons 'mi-admin-status (list (cons 'raw mi-admin-status) (cons 'formatted (fmt-hex mi-admin-status))))
        (cons 'mi-mi-status (list (cons 'raw mi-mi-status) (cons 'formatted (fmt-hex mi-mi-status))))
        (cons 'mi-admin-flags (list (cons 'raw mi-admin-flags) (cons 'formatted (fmt-hex mi-admin-flags))))
        (cons 'mi-admin-flags-doff (list (cons 'raw mi-admin-flags-doff) (cons 'formatted (if (= mi-admin-flags-doff 0) "Not set" "Set"))))
        (cons 'mi-admin-flags-dlen (list (cons 'raw mi-admin-flags-dlen) (cons 'formatted (if (= mi-admin-flags-dlen 0) "Not set" "Set"))))
        (cons 'mi-mi-nmresp (list (cons 'raw mi-mi-nmresp) (cons 'formatted (fmt-hex mi-mi-nmresp))))
        (cons 'mi-admin-ctrl-id (list (cons 'raw mi-admin-ctrl-id) (cons 'formatted (fmt-hex mi-admin-ctrl-id))))
        (cons 'mi-admin-sqe1 (list (cons 'raw mi-admin-sqe1) (cons 'formatted (fmt-hex mi-admin-sqe1))))
        (cons 'mi-admin-cqe1 (list (cons 'raw mi-admin-cqe1) (cons 'formatted (fmt-hex mi-admin-cqe1))))
        (cons 'mi-mi-cdw0 (list (cons 'raw mi-mi-cdw0) (cons 'formatted (fmt-hex mi-mi-cdw0))))
        (cons 'mi-admin-sqe2 (list (cons 'raw mi-admin-sqe2) (cons 'formatted (fmt-hex mi-admin-sqe2))))
        (cons 'mi-admin-cqe2 (list (cons 'raw mi-admin-cqe2) (cons 'formatted (fmt-hex mi-admin-cqe2))))
        (cons 'mi-mi-cdw1 (list (cons 'raw mi-mi-cdw1) (cons 'formatted (fmt-hex mi-mi-cdw1))))
        (cons 'mi-admin-sqe3 (list (cons 'raw mi-admin-sqe3) (cons 'formatted (fmt-hex mi-admin-sqe3))))
        (cons 'mi-admin-cqe3 (list (cons 'raw mi-admin-cqe3) (cons 'formatted (fmt-hex mi-admin-cqe3))))
        (cons 'mi-admin-sqe4 (list (cons 'raw mi-admin-sqe4) (cons 'formatted (fmt-hex mi-admin-sqe4))))
        (cons 'mi-admin-sqe5 (list (cons 'raw mi-admin-sqe5) (cons 'formatted (fmt-hex mi-admin-sqe5))))
        (cons 'mi-admin-doff (list (cons 'raw mi-admin-doff) (cons 'formatted (fmt-hex mi-admin-doff))))
        (cons 'mi-admin-dlen (list (cons 'raw mi-admin-dlen) (cons 'formatted (fmt-hex mi-admin-dlen))))
        (cons 'mi-admin-resv0 (list (cons 'raw mi-admin-resv0) (cons 'formatted (fmt-hex mi-admin-resv0))))
        (cons 'mi-admin-resv1 (list (cons 'raw mi-admin-resv1) (cons 'formatted (fmt-hex mi-admin-resv1))))
        (cons 'mi-admin-sqe10 (list (cons 'raw mi-admin-sqe10) (cons 'formatted (fmt-hex mi-admin-sqe10))))
        (cons 'mi-admin-sqe11 (list (cons 'raw mi-admin-sqe11) (cons 'formatted (fmt-hex mi-admin-sqe11))))
        (cons 'mi-admin-sqe12 (list (cons 'raw mi-admin-sqe12) (cons 'formatted (fmt-hex mi-admin-sqe12))))
        (cons 'mi-admin-sqe13 (list (cons 'raw mi-admin-sqe13) (cons 'formatted (fmt-hex mi-admin-sqe13))))
        (cons 'mi-admin-sqe14 (list (cons 'raw mi-admin-sqe14) (cons 'formatted (fmt-hex mi-admin-sqe14))))
        (cons 'mi-admin-sqe15 (list (cons 'raw mi-admin-sqe15) (cons 'formatted (fmt-hex mi-admin-sqe15))))
        )))

    (catch (e)
      (err (str "NVME-MI parse error: " e)))))

;; dissect-nvme-mi: parse NVME-MI from bytevector
;; Returns (ok fields-alist) or (err message)