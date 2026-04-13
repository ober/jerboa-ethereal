;; packet-hclnfsd.c
;; Routines for hclnfsd (Hummingbird NFS Daemon) dissection
;; Copyright 2001, Mike Frisch <frisch@hummingbird.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-ypserv.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/hclnfsd.ss
;; Auto-generated from wireshark/epan/dissectors/packet-hclnfsd.c

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
(def (dissect-hclnfsd buffer)
  "Hummingbird NFS Daemon"
  (try
    (let* (
           (server-ip (unwrap (read-u32be buffer 0)))
           (host-ip (unwrap (read-u32be buffer 0)))
           (uids (unwrap (read-u32be buffer 0)))
           (print-queues (unwrap (read-u32be buffer 0)))
           (print-jobs (unwrap (read-u32be buffer 0)))
           (status (unwrap (read-u32be buffer 4)))
           (job-id (unwrap (read-u32be buffer 4)))
           (username (unwrap (slice buffer 8 1)))
           (password (unwrap (slice buffer 8 1)))
           (gids (unwrap (read-u32be buffer 9)))
           )

      (ok (list
        (cons 'server-ip (list (cons 'raw server-ip) (cons 'formatted (fmt-ipv4 server-ip))))
        (cons 'host-ip (list (cons 'raw host-ip) (cons 'formatted (fmt-ipv4 host-ip))))
        (cons 'uids (list (cons 'raw uids) (cons 'formatted (number->string uids))))
        (cons 'print-queues (list (cons 'raw print-queues) (cons 'formatted (number->string print-queues))))
        (cons 'print-jobs (list (cons 'raw print-jobs) (cons 'formatted (number->string print-jobs))))
        (cons 'status (list (cons 'raw status) (cons 'formatted (number->string status))))
        (cons 'job-id (list (cons 'raw job-id) (cons 'formatted (number->string job-id))))
        (cons 'username (list (cons 'raw username) (cons 'formatted (utf8->string username))))
        (cons 'password (list (cons 'raw password) (cons 'formatted (utf8->string password))))
        (cons 'gids (list (cons 'raw gids) (cons 'formatted (number->string gids))))
        )))

    (catch (e)
      (err (str "HCLNFSD parse error: " e)))))

;; dissect-hclnfsd: parse HCLNFSD from bytevector
;; Returns (ok fields-alist) or (err message)