;; packet-usbms-bot.c
;;
;; usb mass storage (bulk-only transport) dissector
;; Ronnie Sahlberg 2006
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/usbms-bot.ss
;; Auto-generated from wireshark/epan/dissectors/packet-usbms_bot.c

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
(def (dissect-usbms-bot buffer)
  "USB Mass Storage"
  (try
    (let* (
           (bot-dCBWSignature (unwrap (read-u32be buffer 0)))
           (bot-dCSWSignature (unwrap (read-u32be buffer 0)))
           (bot-dCBWTag (unwrap (read-u32be buffer 4)))
           (bot-value (unwrap (read-u16be buffer 6)))
           (bot-index (unwrap (read-u16be buffer 8)))
           (bot-dCBWDataTransferLength (unwrap (read-u32be buffer 8)))
           (bot-dCSWDataResidue (unwrap (read-u32be buffer 8)))
           (bot-length (unwrap (read-u16be buffer 10)))
           (bot-maxlun (unwrap (read-u8 buffer 12)))
           (bot-dCBWFlags (unwrap (read-u8 buffer 12)))
           (bot-dCBWTarget (unwrap (read-u8 buffer 13)))
           (bot-dCBWLUN (unwrap (read-u8 buffer 13)))
           (bot-dCBWCBLength (unwrap (read-u8 buffer 14)))
           )

      (ok (list
        (cons 'bot-dCBWSignature (list (cons 'raw bot-dCBWSignature) (cons 'formatted (fmt-hex bot-dCBWSignature))))
        (cons 'bot-dCSWSignature (list (cons 'raw bot-dCSWSignature) (cons 'formatted (fmt-hex bot-dCSWSignature))))
        (cons 'bot-dCBWTag (list (cons 'raw bot-dCBWTag) (cons 'formatted (fmt-hex bot-dCBWTag))))
        (cons 'bot-value (list (cons 'raw bot-value) (cons 'formatted (fmt-hex bot-value))))
        (cons 'bot-index (list (cons 'raw bot-index) (cons 'formatted (number->string bot-index))))
        (cons 'bot-dCBWDataTransferLength (list (cons 'raw bot-dCBWDataTransferLength) (cons 'formatted (number->string bot-dCBWDataTransferLength))))
        (cons 'bot-dCSWDataResidue (list (cons 'raw bot-dCSWDataResidue) (cons 'formatted (number->string bot-dCSWDataResidue))))
        (cons 'bot-length (list (cons 'raw bot-length) (cons 'formatted (number->string bot-length))))
        (cons 'bot-maxlun (list (cons 'raw bot-maxlun) (cons 'formatted (number->string bot-maxlun))))
        (cons 'bot-dCBWFlags (list (cons 'raw bot-dCBWFlags) (cons 'formatted (fmt-hex bot-dCBWFlags))))
        (cons 'bot-dCBWTarget (list (cons 'raw bot-dCBWTarget) (cons 'formatted (fmt-hex bot-dCBWTarget))))
        (cons 'bot-dCBWLUN (list (cons 'raw bot-dCBWLUN) (cons 'formatted (fmt-hex bot-dCBWLUN))))
        (cons 'bot-dCBWCBLength (list (cons 'raw bot-dCBWCBLength) (cons 'formatted (fmt-hex bot-dCBWCBLength))))
        )))

    (catch (e)
      (err (str "USBMS-BOT parse error: " e)))))

;; dissect-usbms-bot: parse USBMS-BOT from bytevector
;; Returns (ok fields-alist) or (err message)