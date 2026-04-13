;; packet-rdp_dr.c
;; Routines for the DR RDP channel
;; Copyright 2025, David Fort <contact@hardening-consulting.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rdp-dr.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rdp_dr.c

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
(def (dissect-rdp-dr buffer)
  "RDP disk redirection virtual channel Protocol"
  (try
    (let* (
           (device-name (unwrap (slice buffer 0 1)))
           (deviceCount (unwrap (read-u32be buffer 4)))
           (deviceDataLen (unwrap (read-u32be buffer 24)))
           (deviceData (unwrap (slice buffer 28 1)))
           (fileId (unwrap (read-u32be buffer 32)))
           (io-request-control-outputBufLen (unwrap (read-u32be buffer 48)))
           (io-request-control-inputBufLen (unwrap (read-u32be buffer 52)))
           (io-request-control-padding (unwrap (slice buffer 60 20)))
           (resultCode (unwrap (read-u32be buffer 84)))
           (completionId (unwrap (read-u32be buffer 92)))
           (ioStatus (unwrap (read-u32be buffer 96)))
           (numCapabilities (unwrap (read-u16be buffer 100)))
           (padding (unwrap (read-u16be buffer 102)))
           (deviceId (unwrap (read-u32be buffer 104)))
           (dosName (unwrap (slice buffer 112 8)))
           (pnpNameLength (unwrap (read-u32be buffer 120)))
           (driverNameLength (unwrap (read-u32be buffer 124)))
           (printerNameLength (unwrap (read-u32be buffer 128)))
           (cachedFieldsLength (unwrap (read-u32be buffer 132)))
           (pnpName (unwrap (slice buffer 136 1)))
           (driverName (unwrap (slice buffer 136 1)))
           (printerName (unwrap (slice buffer 136 1)))
           (cachedFields (unwrap (slice buffer 136 1)))
           )

      (ok (list
        (cons 'device-name (list (cons 'raw device-name) (cons 'formatted (utf8->string device-name))))
        (cons 'deviceCount (list (cons 'raw deviceCount) (cons 'formatted (number->string deviceCount))))
        (cons 'deviceDataLen (list (cons 'raw deviceDataLen) (cons 'formatted (number->string deviceDataLen))))
        (cons 'deviceData (list (cons 'raw deviceData) (cons 'formatted (fmt-bytes deviceData))))
        (cons 'fileId (list (cons 'raw fileId) (cons 'formatted (fmt-hex fileId))))
        (cons 'io-request-control-outputBufLen (list (cons 'raw io-request-control-outputBufLen) (cons 'formatted (number->string io-request-control-outputBufLen))))
        (cons 'io-request-control-inputBufLen (list (cons 'raw io-request-control-inputBufLen) (cons 'formatted (number->string io-request-control-inputBufLen))))
        (cons 'io-request-control-padding (list (cons 'raw io-request-control-padding) (cons 'formatted (fmt-bytes io-request-control-padding))))
        (cons 'resultCode (list (cons 'raw resultCode) (cons 'formatted (fmt-hex resultCode))))
        (cons 'completionId (list (cons 'raw completionId) (cons 'formatted (fmt-hex completionId))))
        (cons 'ioStatus (list (cons 'raw ioStatus) (cons 'formatted (fmt-hex ioStatus))))
        (cons 'numCapabilities (list (cons 'raw numCapabilities) (cons 'formatted (number->string numCapabilities))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (number->string padding))))
        (cons 'deviceId (list (cons 'raw deviceId) (cons 'formatted (fmt-hex deviceId))))
        (cons 'dosName (list (cons 'raw dosName) (cons 'formatted (utf8->string dosName))))
        (cons 'pnpNameLength (list (cons 'raw pnpNameLength) (cons 'formatted (number->string pnpNameLength))))
        (cons 'driverNameLength (list (cons 'raw driverNameLength) (cons 'formatted (number->string driverNameLength))))
        (cons 'printerNameLength (list (cons 'raw printerNameLength) (cons 'formatted (number->string printerNameLength))))
        (cons 'cachedFieldsLength (list (cons 'raw cachedFieldsLength) (cons 'formatted (number->string cachedFieldsLength))))
        (cons 'pnpName (list (cons 'raw pnpName) (cons 'formatted (utf8->string pnpName))))
        (cons 'driverName (list (cons 'raw driverName) (cons 'formatted (utf8->string driverName))))
        (cons 'printerName (list (cons 'raw printerName) (cons 'formatted (utf8->string printerName))))
        (cons 'cachedFields (list (cons 'raw cachedFields) (cons 'formatted (fmt-bytes cachedFields))))
        )))

    (catch (e)
      (err (str "RDP-DR parse error: " e)))))

;; dissect-rdp-dr: parse RDP-DR from bytevector
;; Returns (ok fields-alist) or (err message)