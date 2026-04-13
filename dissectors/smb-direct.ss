;;
;; packet-smb-direct.c
;;
;; Routines for [MS-SMBD] the RDMA transport layer for SMB2/3
;;
;; Copyright 2012-2014 Stefan Metzmacher <metze@samba.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/smb-direct.ss
;; Auto-generated from wireshark/epan/dissectors/packet-smb_direct.c

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
(def (dissect-smb-direct buffer)
  "SMB-Direct (SMB RDMA Transport)"
  (try
    (let* (
           (direct-min-version (unwrap (read-u16be buffer 20)))
           (direct-max-version (unwrap (read-u16be buffer 22)))
           (direct-negotiated-version (unwrap (read-u16be buffer 24)))
           (direct-max-read-write-size (unwrap (read-u32be buffer 36)))
           (direct-preferred-send-size (unwrap (read-u32be buffer 40)))
           (direct-max-receive-size (unwrap (read-u32be buffer 44)))
           (direct-max-fragmented-size (unwrap (read-u32be buffer 48)))
           (direct-credits-requested (unwrap (read-u16be buffer 52)))
           (direct-credits-granted (unwrap (read-u16be buffer 54)))
           (direct-flags (unwrap (read-u16le buffer 56)))
           (direct-flags-response-requested (extract-bits direct-flags 0x0 0))
           (direct-remaining-length (unwrap (read-u32be buffer 60)))
           (direct-data-offset (unwrap (read-u32be buffer 64)))
           (direct-data-length (unwrap (read-u32be buffer 68)))
           )

      (ok (list
        (cons 'direct-min-version (list (cons 'raw direct-min-version) (cons 'formatted (fmt-hex direct-min-version))))
        (cons 'direct-max-version (list (cons 'raw direct-max-version) (cons 'formatted (fmt-hex direct-max-version))))
        (cons 'direct-negotiated-version (list (cons 'raw direct-negotiated-version) (cons 'formatted (fmt-hex direct-negotiated-version))))
        (cons 'direct-max-read-write-size (list (cons 'raw direct-max-read-write-size) (cons 'formatted (number->string direct-max-read-write-size))))
        (cons 'direct-preferred-send-size (list (cons 'raw direct-preferred-send-size) (cons 'formatted (number->string direct-preferred-send-size))))
        (cons 'direct-max-receive-size (list (cons 'raw direct-max-receive-size) (cons 'formatted (number->string direct-max-receive-size))))
        (cons 'direct-max-fragmented-size (list (cons 'raw direct-max-fragmented-size) (cons 'formatted (number->string direct-max-fragmented-size))))
        (cons 'direct-credits-requested (list (cons 'raw direct-credits-requested) (cons 'formatted (number->string direct-credits-requested))))
        (cons 'direct-credits-granted (list (cons 'raw direct-credits-granted) (cons 'formatted (number->string direct-credits-granted))))
        (cons 'direct-flags (list (cons 'raw direct-flags) (cons 'formatted (fmt-hex direct-flags))))
        (cons 'direct-flags-response-requested (list (cons 'raw direct-flags-response-requested) (cons 'formatted (if (= direct-flags-response-requested 0) "Not set" "Set"))))
        (cons 'direct-remaining-length (list (cons 'raw direct-remaining-length) (cons 'formatted (number->string direct-remaining-length))))
        (cons 'direct-data-offset (list (cons 'raw direct-data-offset) (cons 'formatted (number->string direct-data-offset))))
        (cons 'direct-data-length (list (cons 'raw direct-data-length) (cons 'formatted (number->string direct-data-length))))
        )))

    (catch (e)
      (err (str "SMB-DIRECT parse error: " e)))))

;; dissect-smb-direct: parse SMB-DIRECT from bytevector
;; Returns (ok fields-alist) or (err message)