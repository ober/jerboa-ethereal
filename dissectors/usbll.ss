;; packet-usbll.c
;;
;; 2019 Tomasz Mon <desowin@gmail.com>
;;
;; USB link layer dissector
;;
;; This code is separated from packet-usb.c on purpose.
;; It is important to note that packet-usb.c operates on the USB URB level.
;; The idea behind this file is to transform low level link layer data
;; (captured by hardware sniffers) into structures that resemble URB and pass
;; such URB to the URB common dissection code.
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/usbll.ss
;; Auto-generated from wireshark/epan/dissectors/packet-usbll.c

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
(def (dissect-usbll buffer)
  "USB Link Layer"
  (try
    (let* (
           (dst (unwrap (slice buffer 0 1)))
           (addr (unwrap (slice buffer 0 1)))
           (src (unwrap (slice buffer 0 1)))
           (sof-framenum (unwrap (read-u16be buffer 0)))
           (split-hub-addr (unwrap (read-u24be buffer 0)))
           (split-port (unwrap (read-u24be buffer 0)))
           (split-u (unwrap (read-u24be buffer 0)))
           (split-e (unwrap (read-u24be buffer 0)))
           )

      (ok (list
        (cons 'dst (list (cons 'raw dst) (cons 'formatted (utf8->string dst))))
        (cons 'addr (list (cons 'raw addr) (cons 'formatted (utf8->string addr))))
        (cons 'src (list (cons 'raw src) (cons 'formatted (utf8->string src))))
        (cons 'sof-framenum (list (cons 'raw sof-framenum) (cons 'formatted (number->string sof-framenum))))
        (cons 'split-hub-addr (list (cons 'raw split-hub-addr) (cons 'formatted (number->string split-hub-addr))))
        (cons 'split-port (list (cons 'raw split-port) (cons 'formatted (number->string split-port))))
        (cons 'split-u (list (cons 'raw split-u) (cons 'formatted (number->string split-u))))
        (cons 'split-e (list (cons 'raw split-e) (cons 'formatted (number->string split-e))))
        )))

    (catch (e)
      (err (str "USBLL parse error: " e)))))

;; dissect-usbll: parse USBLL from bytevector
;; Returns (ok fields-alist) or (err message)