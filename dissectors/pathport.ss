;; packet-pathport.c
;; Routines for Pathport Protocol dissection
;; Copyright 2014, Kevin Loewen <kloewen@pathwayconnect.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/pathport.ss
;; Auto-generated from wireshark/epan/dissectors/packet-pathport.c

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
(def (dissect-pathport buffer)
  "Pathport Protocol"
  (try
    (let* (
           (pid-len (unwrap (read-u16be buffer 2)))
           (pid-value (unwrap (slice buffer 4 1)))
           (pid-pad-bytes (unwrap (slice buffer 4 1)))
           (data-len (unwrap (read-u16be buffer 8)))
           (data-dst (unwrap (read-u16be buffer 10)))
           (arp-id (unwrap (read-u32be buffer 12)))
           (arp-ip (unwrap (read-u32be buffer 16)))
           (pdu-len (unwrap (read-u16be buffer 22)))
           (pdu-payload (unwrap (slice buffer 24 1)))
           (prot (unwrap (read-u16be buffer 24)))
           (version (unwrap (read-u16be buffer 26)))
           (seq (unwrap (read-u16be buffer 28)))
           (reserved (unwrap (slice buffer 30 6)))
           (src (unwrap (read-u32be buffer 36)))
           (dst (unwrap (read-u32be buffer 40)))
           )

      (ok (list
        (cons 'pid-len (list (cons 'raw pid-len) (cons 'formatted (number->string pid-len))))
        (cons 'pid-value (list (cons 'raw pid-value) (cons 'formatted (fmt-bytes pid-value))))
        (cons 'pid-pad-bytes (list (cons 'raw pid-pad-bytes) (cons 'formatted (fmt-bytes pid-pad-bytes))))
        (cons 'data-len (list (cons 'raw data-len) (cons 'formatted (fmt-hex data-len))))
        (cons 'data-dst (list (cons 'raw data-dst) (cons 'formatted (fmt-hex data-dst))))
        (cons 'arp-id (list (cons 'raw arp-id) (cons 'formatted (fmt-hex arp-id))))
        (cons 'arp-ip (list (cons 'raw arp-ip) (cons 'formatted (fmt-ipv4 arp-ip))))
        (cons 'pdu-len (list (cons 'raw pdu-len) (cons 'formatted (number->string pdu-len))))
        (cons 'pdu-payload (list (cons 'raw pdu-payload) (cons 'formatted (fmt-bytes pdu-payload))))
        (cons 'prot (list (cons 'raw prot) (cons 'formatted (fmt-hex prot))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (fmt-hex version))))
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (number->string seq))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'src (list (cons 'raw src) (cons 'formatted (fmt-hex src))))
        (cons 'dst (list (cons 'raw dst) (cons 'formatted (fmt-hex dst))))
        )))

    (catch (e)
      (err (str "PATHPORT parse error: " e)))))

;; dissect-pathport: parse PATHPORT from bytevector
;; Returns (ok fields-alist) or (err message)