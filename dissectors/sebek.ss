;; packet-sebek.c
;; Routines for Sebek - Kernel based data capture - packet dissection
;; Modified to add sebek V3
;; Copyright 2006, Camilo Viecco <cviecco@indiana.edu>
;; Copyright 1999, Nathan Neulinger <nneul@umr.edu>
;;
;; See: http://project.honeynet.org/tools/sebek/ for more details
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/sebek.ss
;; Auto-generated from wireshark/epan/dissectors/packet-sebek.c

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
(def (dissect-sebek buffer)
  "SEBEK - Kernel Data Capture"
  (try
    (let* (
           (magic (unwrap (read-u32be buffer 48)))
           (version (unwrap (read-u16be buffer 52)))
           (type (unwrap (read-u16be buffer 54)))
           (counter (unwrap (read-u32be buffer 56)))
           (ppid (unwrap (read-u32be buffer 68)))
           (pid (unwrap (read-u32be buffer 72)))
           (uid (unwrap (read-u32be buffer 76)))
           (fd (unwrap (read-u32be buffer 80)))
           (inode (unwrap (read-u32be buffer 84)))
           (cmd (unwrap (slice buffer 88 12)))
           (len (unwrap (read-u32be buffer 100)))
           (socket-dst-ip (unwrap (read-u32be buffer 104)))
           (socket-dst-port (unwrap (read-u16be buffer 108)))
           (socket-src-ip (unwrap (read-u32be buffer 110)))
           (socket-src-port (unwrap (read-u16be buffer 114)))
           (socket-call (unwrap (read-u16be buffer 116)))
           (socket-proto (unwrap (read-u8 buffer 118)))
           (data (unwrap (slice buffer 119 1)))
           )

      (ok (list
        (cons 'magic (list (cons 'raw magic) (cons 'formatted (fmt-hex magic))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'type (list (cons 'raw type) (cons 'formatted (number->string type))))
        (cons 'counter (list (cons 'raw counter) (cons 'formatted (number->string counter))))
        (cons 'ppid (list (cons 'raw ppid) (cons 'formatted (number->string ppid))))
        (cons 'pid (list (cons 'raw pid) (cons 'formatted (number->string pid))))
        (cons 'uid (list (cons 'raw uid) (cons 'formatted (number->string uid))))
        (cons 'fd (list (cons 'raw fd) (cons 'formatted (number->string fd))))
        (cons 'inode (list (cons 'raw inode) (cons 'formatted (number->string inode))))
        (cons 'cmd (list (cons 'raw cmd) (cons 'formatted (utf8->string cmd))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'socket-dst-ip (list (cons 'raw socket-dst-ip) (cons 'formatted (fmt-ipv4 socket-dst-ip))))
        (cons 'socket-dst-port (list (cons 'raw socket-dst-port) (cons 'formatted (number->string socket-dst-port))))
        (cons 'socket-src-ip (list (cons 'raw socket-src-ip) (cons 'formatted (fmt-ipv4 socket-src-ip))))
        (cons 'socket-src-port (list (cons 'raw socket-src-port) (cons 'formatted (number->string socket-src-port))))
        (cons 'socket-call (list (cons 'raw socket-call) (cons 'formatted (number->string socket-call))))
        (cons 'socket-proto (list (cons 'raw socket-proto) (cons 'formatted (number->string socket-proto))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (utf8->string data))))
        )))

    (catch (e)
      (err (str "SEBEK parse error: " e)))))

;; dissect-sebek: parse SEBEK from bytevector
;; Returns (ok fields-alist) or (err message)