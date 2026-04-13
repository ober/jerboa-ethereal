;; packet-matter.c
;; Routines for Matter IoT protocol dissection
;; Copyright 2023, Nicolás Alvarez <nicolas.alvarez@gmail.com>
;; Copyright 2024, Arkadiusz Bokowy <a.bokowy@samsung.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/matter.ss
;; Auto-generated from wireshark/epan/dissectors/packet-matter.c

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
(def (dissect-matter buffer)
  "Matter"
  (try
    (let* (
           (flags (unwrap (read-u8 buffer 0)))
           (version (extract-bits flags 0x0 0))
           (has-source (extract-bits flags 0x0 0))
           (exchange-flags (unwrap (read-u8 buffer 0)))
           (flag-initiator (extract-bits exchange-flags 0x0 0))
           (flag-ack (extract-bits exchange-flags 0x0 0))
           (flag-reliability (extract-bits exchange-flags 0x0 0))
           (flag-secured-extensions (extract-bits exchange-flags 0x0 0))
           (flag-vendor (extract-bits exchange-flags 0x0 0))
           (tlv-elem-control (unwrap (read-u8 buffer 0)))
           (session-id (unwrap (read-u16be buffer 1)))
           (protocol-opcode (unwrap (read-u8 buffer 1)))
           (exchange-id (unwrap (read-u16be buffer 2)))
           (tlv-elem-length (unwrap (read-u64be buffer 2)))
           (security-flags (unwrap (read-u8 buffer 3)))
           (flag-privacy (extract-bits security-flags 0x0 0))
           (flag-control (extract-bits security-flags 0x0 0))
           (flag-extensions (extract-bits security-flags 0x0 0))
           (privacy-header (unwrap (slice buffer 4 1)))
           (counter (unwrap (read-u32be buffer 4)))
           (protocol-vendor-id (unwrap (read-u16be buffer 4)))
           (protocol-id (unwrap (read-u16be buffer 6)))
           (src-id (unwrap (read-u64be buffer 8)))
           (ack-counter (unwrap (read-u32be buffer 8)))
           (secured-ext-length (unwrap (read-u16be buffer 12)))
           (secured-ext (unwrap (slice buffer 14 1)))
           (application (unwrap (slice buffer 14 1)))
           (dest-node-id (unwrap (read-u64be buffer 16)))
           (dest-group-id (unwrap (read-u16be buffer 24)))
           (mic (unwrap (slice buffer 26 1)))
           )

      (ok (list
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (if (= version 0) "Not set" "Set"))))
        (cons 'has-source (list (cons 'raw has-source) (cons 'formatted (if (= has-source 0) "Not set" "Set"))))
        (cons 'exchange-flags (list (cons 'raw exchange-flags) (cons 'formatted (fmt-hex exchange-flags))))
        (cons 'flag-initiator (list (cons 'raw flag-initiator) (cons 'formatted (if (= flag-initiator 0) "Not set" "Set"))))
        (cons 'flag-ack (list (cons 'raw flag-ack) (cons 'formatted (if (= flag-ack 0) "Not set" "Set"))))
        (cons 'flag-reliability (list (cons 'raw flag-reliability) (cons 'formatted (if (= flag-reliability 0) "Not set" "Set"))))
        (cons 'flag-secured-extensions (list (cons 'raw flag-secured-extensions) (cons 'formatted (if (= flag-secured-extensions 0) "Not set" "Set"))))
        (cons 'flag-vendor (list (cons 'raw flag-vendor) (cons 'formatted (if (= flag-vendor 0) "Not set" "Set"))))
        (cons 'tlv-elem-control (list (cons 'raw tlv-elem-control) (cons 'formatted (fmt-hex tlv-elem-control))))
        (cons 'session-id (list (cons 'raw session-id) (cons 'formatted (fmt-hex session-id))))
        (cons 'protocol-opcode (list (cons 'raw protocol-opcode) (cons 'formatted (fmt-hex protocol-opcode))))
        (cons 'exchange-id (list (cons 'raw exchange-id) (cons 'formatted (fmt-hex exchange-id))))
        (cons 'tlv-elem-length (list (cons 'raw tlv-elem-length) (cons 'formatted (number->string tlv-elem-length))))
        (cons 'security-flags (list (cons 'raw security-flags) (cons 'formatted (fmt-hex security-flags))))
        (cons 'flag-privacy (list (cons 'raw flag-privacy) (cons 'formatted (if (= flag-privacy 0) "Not set" "Set"))))
        (cons 'flag-control (list (cons 'raw flag-control) (cons 'formatted (if (= flag-control 0) "Not set" "Set"))))
        (cons 'flag-extensions (list (cons 'raw flag-extensions) (cons 'formatted (if (= flag-extensions 0) "Not set" "Set"))))
        (cons 'privacy-header (list (cons 'raw privacy-header) (cons 'formatted (fmt-bytes privacy-header))))
        (cons 'counter (list (cons 'raw counter) (cons 'formatted (number->string counter))))
        (cons 'protocol-vendor-id (list (cons 'raw protocol-vendor-id) (cons 'formatted (fmt-hex protocol-vendor-id))))
        (cons 'protocol-id (list (cons 'raw protocol-id) (cons 'formatted (fmt-hex protocol-id))))
        (cons 'src-id (list (cons 'raw src-id) (cons 'formatted (fmt-hex src-id))))
        (cons 'ack-counter (list (cons 'raw ack-counter) (cons 'formatted (number->string ack-counter))))
        (cons 'secured-ext-length (list (cons 'raw secured-ext-length) (cons 'formatted (number->string secured-ext-length))))
        (cons 'secured-ext (list (cons 'raw secured-ext) (cons 'formatted (fmt-bytes secured-ext))))
        (cons 'application (list (cons 'raw application) (cons 'formatted (fmt-bytes application))))
        (cons 'dest-node-id (list (cons 'raw dest-node-id) (cons 'formatted (fmt-hex dest-node-id))))
        (cons 'dest-group-id (list (cons 'raw dest-group-id) (cons 'formatted (fmt-hex dest-group-id))))
        (cons 'mic (list (cons 'raw mic) (cons 'formatted (fmt-bytes mic))))
        )))

    (catch (e)
      (err (str "MATTER parse error: " e)))))

;; dissect-matter: parse MATTER from bytevector
;; Returns (ok fields-alist) or (err message)