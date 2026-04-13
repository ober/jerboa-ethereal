;; packet-usbip.c
;; Routines for USB/IP dissection
;; Copyright 2016, Christian Lamparter <chunkeey@googlemail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/usbip.ss
;; Auto-generated from wireshark/epan/dissectors/packet-usbip.c

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
(def (dissect-usbip buffer)
  "USBIP Protocol"
  (try
    (let* (
           (urb-data (unwrap (slice buffer 0 1)))
           (busnum (unwrap (read-u32be buffer 288)))
           (devnum (unwrap (read-u32be buffer 292)))
           (idProduct (unwrap (read-u16be buffer 302)))
           (bcdDevice (unwrap (read-u16be buffer 304)))
           (bDeviceSubClass (unwrap (read-u8 buffer 307)))
           (bDeviceProtocol (unwrap (read-u8 buffer 308)))
           (bConfigurationValue (unwrap (read-u8 buffer 309)))
           (bNumConfigurations (unwrap (read-u8 buffer 310)))
           (bNumInterfaces (unwrap (read-u8 buffer 311)))
           (number-devices (unwrap (read-u32be buffer 312)))
           (device (unwrap (read-u32be buffer 316)))
           (interface (unwrap (read-u32be buffer 316)))
           (bInterfaceSubClass (unwrap (read-u8 buffer 317)))
           (bInterfaceProtocol (unwrap (read-u8 buffer 318)))
           (padding (unwrap (slice buffer 319 1)))
           (busid (unwrap (slice buffer 320 32)))
           (transfer-buffer-length (unwrap (read-u32be buffer 324)))
           (interval (unwrap (read-u32be buffer 336)))
           (actual-length (unwrap (read-u32be buffer 352)))
           (start-frame (unwrap (read-u32be buffer 356)))
           (number-of-packets (unwrap (read-u32be buffer 360)))
           (error-count (unwrap (read-u32be buffer 364)))
           (setup (unwrap (slice buffer 368 8)))
           (version (unwrap (read-u16be buffer 384)))
           (seqnum (unwrap (read-u32be buffer 396)))
           (devid (unwrap (read-u32be buffer 400)))
           (ep (unwrap (read-u32be buffer 408)))
           (path (unwrap (slice buffer 412 256)))
           )

      (ok (list
        (cons 'urb-data (list (cons 'raw urb-data) (cons 'formatted (fmt-bytes urb-data))))
        (cons 'busnum (list (cons 'raw busnum) (cons 'formatted (fmt-hex busnum))))
        (cons 'devnum (list (cons 'raw devnum) (cons 'formatted (fmt-hex devnum))))
        (cons 'idProduct (list (cons 'raw idProduct) (cons 'formatted (fmt-hex idProduct))))
        (cons 'bcdDevice (list (cons 'raw bcdDevice) (cons 'formatted (fmt-hex bcdDevice))))
        (cons 'bDeviceSubClass (list (cons 'raw bDeviceSubClass) (cons 'formatted (number->string bDeviceSubClass))))
        (cons 'bDeviceProtocol (list (cons 'raw bDeviceProtocol) (cons 'formatted (number->string bDeviceProtocol))))
        (cons 'bConfigurationValue (list (cons 'raw bConfigurationValue) (cons 'formatted (number->string bConfigurationValue))))
        (cons 'bNumConfigurations (list (cons 'raw bNumConfigurations) (cons 'formatted (number->string bNumConfigurations))))
        (cons 'bNumInterfaces (list (cons 'raw bNumInterfaces) (cons 'formatted (number->string bNumInterfaces))))
        (cons 'number-devices (list (cons 'raw number-devices) (cons 'formatted (number->string number-devices))))
        (cons 'device (list (cons 'raw device) (cons 'formatted (number->string device))))
        (cons 'interface (list (cons 'raw interface) (cons 'formatted (number->string interface))))
        (cons 'bInterfaceSubClass (list (cons 'raw bInterfaceSubClass) (cons 'formatted (fmt-hex bInterfaceSubClass))))
        (cons 'bInterfaceProtocol (list (cons 'raw bInterfaceProtocol) (cons 'formatted (fmt-hex bInterfaceProtocol))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        (cons 'busid (list (cons 'raw busid) (cons 'formatted (utf8->string busid))))
        (cons 'transfer-buffer-length (list (cons 'raw transfer-buffer-length) (cons 'formatted (number->string transfer-buffer-length))))
        (cons 'interval (list (cons 'raw interval) (cons 'formatted (number->string interval))))
        (cons 'actual-length (list (cons 'raw actual-length) (cons 'formatted (number->string actual-length))))
        (cons 'start-frame (list (cons 'raw start-frame) (cons 'formatted (number->string start-frame))))
        (cons 'number-of-packets (list (cons 'raw number-of-packets) (cons 'formatted (number->string number-of-packets))))
        (cons 'error-count (list (cons 'raw error-count) (cons 'formatted (number->string error-count))))
        (cons 'setup (list (cons 'raw setup) (cons 'formatted (fmt-bytes setup))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (fmt-hex version))))
        (cons 'seqnum (list (cons 'raw seqnum) (cons 'formatted (number->string seqnum))))
        (cons 'devid (list (cons 'raw devid) (cons 'formatted (fmt-hex devid))))
        (cons 'ep (list (cons 'raw ep) (cons 'formatted (fmt-hex ep))))
        (cons 'path (list (cons 'raw path) (cons 'formatted (utf8->string path))))
        )))

    (catch (e)
      (err (str "USBIP parse error: " e)))))

;; dissect-usbip: parse USBIP from bytevector
;; Returns (ok fields-alist) or (err message)