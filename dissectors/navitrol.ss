;; packet-navitrol.c
;; Routines for Navitec Systems Navitrol device
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/navitrol.ss
;; Auto-generated from wireshark/epan/dissectors/packet-navitrol.c

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
(def (dissect-navitrol buffer)
  "Navitec Systems Navitrol"
  (try
    (let* (
           (protocol-version (unwrap (read-u16be buffer 4)))
           (message-length (unwrap (read-u32be buffer 8)))
           (raw-ds (unwrap (read-u32be buffer 92)))
           (raw-dh (unwrap (read-u32be buffer 96)))
           (log-save-length (unwrap (read-u32be buffer 111)))
           (ip-address (unwrap (read-u32be buffer 116)))
           (port-front (unwrap (read-u32be buffer 120)))
           (port-rear (unwrap (read-u32be buffer 124)))
           (cum-s-long (unwrap (read-u32be buffer 227)))
           (cum-s-trans (unwrap (read-u32be buffer 231)))
           (raw-heading (unwrap (read-u32be buffer 235)))
           (vel-long (unwrap (read-u32be buffer 263)))
           (vel-trans (unwrap (read-u32be buffer 267)))
           (vel-angular (unwrap (read-u32be buffer 271)))
           (cum-s-left (unwrap (read-u32be buffer 283)))
           (cum-s-right (unwrap (read-u32be buffer 287)))
           (timestamp (unwrap (read-u32be buffer 293)))
           (position-x-double (unwrap (read-u64be buffer 298)))
           (position-y-double (unwrap (read-u64be buffer 306)))
           (error-description (unwrap (slice buffer 561 200)))
           (saved-log-number (unwrap (read-u32be buffer 761)))
           (comm-version (unwrap (read-u32be buffer 771)))
           (position-x (unwrap (read-u32be buffer 781)))
           (position-y (unwrap (read-u32be buffer 785)))
           (position-heading (unwrap (read-u32be buffer 789)))
           (floor (unwrap (read-u32be buffer 793)))
           (message-number (unwrap (read-u32be buffer 801)))
           (speed-left (unwrap (read-u32be buffer 805)))
           (speed-right (unwrap (read-u32be buffer 809)))
           (error-count (unwrap (read-u32be buffer 815)))
           (error-code (unwrap (read-u32be buffer 819)))
           )

      (ok (list
        (cons 'protocol-version (list (cons 'raw protocol-version) (cons 'formatted (number->string protocol-version))))
        (cons 'message-length (list (cons 'raw message-length) (cons 'formatted (number->string message-length))))
        (cons 'raw-ds (list (cons 'raw raw-ds) (cons 'formatted (number->string raw-ds))))
        (cons 'raw-dh (list (cons 'raw raw-dh) (cons 'formatted (number->string raw-dh))))
        (cons 'log-save-length (list (cons 'raw log-save-length) (cons 'formatted (number->string log-save-length))))
        (cons 'ip-address (list (cons 'raw ip-address) (cons 'formatted (fmt-ipv4 ip-address))))
        (cons 'port-front (list (cons 'raw port-front) (cons 'formatted (number->string port-front))))
        (cons 'port-rear (list (cons 'raw port-rear) (cons 'formatted (number->string port-rear))))
        (cons 'cum-s-long (list (cons 'raw cum-s-long) (cons 'formatted (number->string cum-s-long))))
        (cons 'cum-s-trans (list (cons 'raw cum-s-trans) (cons 'formatted (number->string cum-s-trans))))
        (cons 'raw-heading (list (cons 'raw raw-heading) (cons 'formatted (number->string raw-heading))))
        (cons 'vel-long (list (cons 'raw vel-long) (cons 'formatted (number->string vel-long))))
        (cons 'vel-trans (list (cons 'raw vel-trans) (cons 'formatted (number->string vel-trans))))
        (cons 'vel-angular (list (cons 'raw vel-angular) (cons 'formatted (number->string vel-angular))))
        (cons 'cum-s-left (list (cons 'raw cum-s-left) (cons 'formatted (number->string cum-s-left))))
        (cons 'cum-s-right (list (cons 'raw cum-s-right) (cons 'formatted (number->string cum-s-right))))
        (cons 'timestamp (list (cons 'raw timestamp) (cons 'formatted (number->string timestamp))))
        (cons 'position-x-double (list (cons 'raw position-x-double) (cons 'formatted (number->string position-x-double))))
        (cons 'position-y-double (list (cons 'raw position-y-double) (cons 'formatted (number->string position-y-double))))
        (cons 'error-description (list (cons 'raw error-description) (cons 'formatted (utf8->string error-description))))
        (cons 'saved-log-number (list (cons 'raw saved-log-number) (cons 'formatted (number->string saved-log-number))))
        (cons 'comm-version (list (cons 'raw comm-version) (cons 'formatted (number->string comm-version))))
        (cons 'position-x (list (cons 'raw position-x) (cons 'formatted (number->string position-x))))
        (cons 'position-y (list (cons 'raw position-y) (cons 'formatted (number->string position-y))))
        (cons 'position-heading (list (cons 'raw position-heading) (cons 'formatted (number->string position-heading))))
        (cons 'floor (list (cons 'raw floor) (cons 'formatted (number->string floor))))
        (cons 'message-number (list (cons 'raw message-number) (cons 'formatted (number->string message-number))))
        (cons 'speed-left (list (cons 'raw speed-left) (cons 'formatted (number->string speed-left))))
        (cons 'speed-right (list (cons 'raw speed-right) (cons 'formatted (number->string speed-right))))
        (cons 'error-count (list (cons 'raw error-count) (cons 'formatted (number->string error-count))))
        (cons 'error-code (list (cons 'raw error-code) (cons 'formatted (number->string error-code))))
        )))

    (catch (e)
      (err (str "NAVITROL parse error: " e)))))

;; dissect-navitrol: parse NAVITROL from bytevector
;; Returns (ok fields-alist) or (err message)