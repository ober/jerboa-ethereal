;; packet-hci_mon.c
;; Routines for Bluetooth Linux Monitor dissection
;;
;; Copyright 2013, Michal Labedzki for Tieto Corporation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/hci-mon.ss
;; Auto-generated from wireshark/epan/dissectors/packet-hci_mon.c

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
(def (dissect-hci-mon buffer)
  "Bluetooth Linux Monitor Transport"
  (try
    (let* (
           (hf-name (unwrap (slice buffer 2 8)))
           (hf-manufacturer (unwrap (read-u16be buffer 10)))
           (note (unwrap (slice buffer 12 1)))
           (hf-ident (unwrap (slice buffer 14 1)))
           (hf-message (unwrap (slice buffer 14 1)))
           (hf-version (unwrap (read-u8 buffer 20)))
           (hf-revision (unwrap (read-u16be buffer 20)))
           (hf-flags (unwrap (read-u32le buffer 23)))
           (trusted-socket (extract-bits hf-flags 0x1 0))
           (length (unwrap (read-u8 buffer 27)))
           (hf-command (unwrap (slice buffer 28 1)))
           (hf-cookie (unwrap (read-u32be buffer 38)))
           (id (unwrap (read-u16be buffer 42)))
           )

      (ok (list
        (cons 'hf-name (list (cons 'raw hf-name) (cons 'formatted (utf8->string hf-name))))
        (cons 'hf-manufacturer (list (cons 'raw hf-manufacturer) (cons 'formatted (fmt-hex hf-manufacturer))))
        (cons 'note (list (cons 'raw note) (cons 'formatted (utf8->string note))))
        (cons 'hf-ident (list (cons 'raw hf-ident) (cons 'formatted (utf8->string hf-ident))))
        (cons 'hf-message (list (cons 'raw hf-message) (cons 'formatted (utf8->string hf-message))))
        (cons 'hf-version (list (cons 'raw hf-version) (cons 'formatted (number->string hf-version))))
        (cons 'hf-revision (list (cons 'raw hf-revision) (cons 'formatted (number->string hf-revision))))
        (cons 'hf-flags (list (cons 'raw hf-flags) (cons 'formatted (fmt-hex hf-flags))))
        (cons 'trusted-socket (list (cons 'raw trusted-socket) (cons 'formatted (if (= trusted-socket 0) "Not set" "Set"))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'hf-command (list (cons 'raw hf-command) (cons 'formatted (utf8->string hf-command))))
        (cons 'hf-cookie (list (cons 'raw hf-cookie) (cons 'formatted (fmt-hex hf-cookie))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (number->string id))))
        )))

    (catch (e)
      (err (str "HCI-MON parse error: " e)))))

;; dissect-hci-mon: parse HCI-MON from bytevector
;; Returns (ok fields-alist) or (err message)