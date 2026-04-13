;; packet-aoe.c
;; Routines for dissecting the ATA over Ethernet protocol.
;; Ronnie Sahlberg 2004
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/aoe.ss
;; Auto-generated from wireshark/epan/dissectors/packet-aoe.c

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
(def (dissect-aoe buffer)
  "ATAoverEthernet"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (flags-error (unwrap (read-u8 buffer 0)))
           (flags-response (unwrap (read-u8 buffer 0)))
           (aflags-e (unwrap (read-u8 buffer 0)))
           (aflags-d (unwrap (read-u8 buffer 0)))
           (aflags-a (unwrap (read-u8 buffer 0)))
           (aflags-w (unwrap (read-u8 buffer 0)))
           (err-feature (unwrap (read-u8 buffer 0)))
           (sector-count (unwrap (read-u8 buffer 0)))
           (astatus (unwrap (read-u8 buffer 0)))
           (major (unwrap (read-u16be buffer 2)))
           (minor (unwrap (read-u8 buffer 4)))
           (tag (unwrap (read-u32be buffer 6)))
           (lba (unwrap (read-u64be buffer 8)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'flags-error (list (cons 'raw flags-error) (cons 'formatted (if (= flags-error 0) "No error" "Error"))))
        (cons 'flags-response (list (cons 'raw flags-response) (cons 'formatted (if (= flags-response 0) "False" "True"))))
        (cons 'aflags-e (list (cons 'raw aflags-e) (cons 'formatted (if (= aflags-e 0) "Normal command" "LBA48 extended command"))))
        (cons 'aflags-d (list (cons 'raw aflags-d) (cons 'formatted (number->string aflags-d))))
        (cons 'aflags-a (list (cons 'raw aflags-a) (cons 'formatted (if (= aflags-a 0) "synchronous write" "ASYNCHRONOUS Write"))))
        (cons 'aflags-w (list (cons 'raw aflags-w) (cons 'formatted (if (= aflags-w 0) "No write to device" "WRITE to the device"))))
        (cons 'err-feature (list (cons 'raw err-feature) (cons 'formatted (fmt-hex err-feature))))
        (cons 'sector-count (list (cons 'raw sector-count) (cons 'formatted (number->string sector-count))))
        (cons 'astatus (list (cons 'raw astatus) (cons 'formatted (fmt-hex astatus))))
        (cons 'major (list (cons 'raw major) (cons 'formatted (fmt-hex major))))
        (cons 'minor (list (cons 'raw minor) (cons 'formatted (fmt-hex minor))))
        (cons 'tag (list (cons 'raw tag) (cons 'formatted (fmt-hex tag))))
        (cons 'lba (list (cons 'raw lba) (cons 'formatted (fmt-hex lba))))
        )))

    (catch (e)
      (err (str "AOE parse error: " e)))))

;; dissect-aoe: parse AOE from bytevector
;; Returns (ok fields-alist) or (err message)