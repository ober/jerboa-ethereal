;; Do not modify this file. Changes will be overwritten.

;; jerboa-ethereal/dissectors/cosem.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cosem.c

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
(def (dissect-cosem buffer)
  "DLMS/COSEM"
  (try
    (let* (
           (invoke-id (unwrap (read-u8 buffer 0)))
           (service-class (unwrap (read-u8 buffer 0)))
           (priority (unwrap (read-u8 buffer 0)))
           (hdlc-length (unwrap (read-u16be buffer 1)))
           (hdlc-segmentation (unwrap (read-u16be buffer 1)))
           (hdlc-type (unwrap (read-u16be buffer 1)))
           (hdlc-address (unwrap (read-u8 buffer 3)))
           (last-block (unwrap (read-u8 buffer 87)))
           (access-selector (unwrap (read-u8 buffer 98)))
           (response-allowed (unwrap (read-u8 buffer 103)))
           (proposed-quality-of-service (unwrap (read-u8 buffer 103)))
           (proposed-dlms-version-number (unwrap (read-u8 buffer 103)))
           (client-max-receive-pdu-size (unwrap (read-u16be buffer 103)))
           (negotiated-quality-of-service (unwrap (read-u8 buffer 103)))
           (negotiated-dlms-version-number (unwrap (read-u8 buffer 103)))
           (server-max-receive-pdu-size (unwrap (read-u16be buffer 103)))
           (object-name (unwrap (read-u16be buffer 105)))
           (block-number (unwrap (read-u32be buffer 117)))
           )

      (ok (list
        (cons 'invoke-id (list (cons 'raw invoke-id) (cons 'formatted (number->string invoke-id))))
        (cons 'service-class (list (cons 'raw service-class) (cons 'formatted (if (= service-class 0) "False" "True"))))
        (cons 'priority (list (cons 'raw priority) (cons 'formatted (if (= priority 0) "False" "True"))))
        (cons 'hdlc-length (list (cons 'raw hdlc-length) (cons 'formatted (number->string hdlc-length))))
        (cons 'hdlc-segmentation (list (cons 'raw hdlc-segmentation) (cons 'formatted (number->string hdlc-segmentation))))
        (cons 'hdlc-type (list (cons 'raw hdlc-type) (cons 'formatted (number->string hdlc-type))))
        (cons 'hdlc-address (list (cons 'raw hdlc-address) (cons 'formatted (number->string hdlc-address))))
        (cons 'last-block (list (cons 'raw last-block) (cons 'formatted (number->string last-block))))
        (cons 'access-selector (list (cons 'raw access-selector) (cons 'formatted (number->string access-selector))))
        (cons 'response-allowed (list (cons 'raw response-allowed) (cons 'formatted (number->string response-allowed))))
        (cons 'proposed-quality-of-service (list (cons 'raw proposed-quality-of-service) (cons 'formatted (number->string proposed-quality-of-service))))
        (cons 'proposed-dlms-version-number (list (cons 'raw proposed-dlms-version-number) (cons 'formatted (number->string proposed-dlms-version-number))))
        (cons 'client-max-receive-pdu-size (list (cons 'raw client-max-receive-pdu-size) (cons 'formatted (number->string client-max-receive-pdu-size))))
        (cons 'negotiated-quality-of-service (list (cons 'raw negotiated-quality-of-service) (cons 'formatted (number->string negotiated-quality-of-service))))
        (cons 'negotiated-dlms-version-number (list (cons 'raw negotiated-dlms-version-number) (cons 'formatted (number->string negotiated-dlms-version-number))))
        (cons 'server-max-receive-pdu-size (list (cons 'raw server-max-receive-pdu-size) (cons 'formatted (number->string server-max-receive-pdu-size))))
        (cons 'object-name (list (cons 'raw object-name) (cons 'formatted (number->string object-name))))
        (cons 'block-number (list (cons 'raw block-number) (cons 'formatted (number->string block-number))))
        )))

    (catch (e)
      (err (str "COSEM parse error: " e)))))

;; dissect-cosem: parse COSEM from bytevector
;; Returns (ok fields-alist) or (err message)