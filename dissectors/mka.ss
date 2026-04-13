;; packet-mka.c
;; Routines for EAPOL-MKA IEEE 802.1X-2010 / IEEE 802.1bx-2014 /
;; IEEE Std 802.1Xck-2018 / IEEE 802.1X-2020 MKPDU dissection
;; Copyright 2014, Hitesh K Maisheri <maisheri.hitesh@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mka.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mka.c

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
(def (dissect-mka buffer)
  "MACsec Key Agreement"
  (try
    (let* (
           (cak-name-info (unwrap (slice buffer 0 1)))
           (version-id (unwrap (read-u8 buffer 0)))
           (keyserver-priority (unwrap (read-u8 buffer 1)))
           (key-server (unwrap (read-u8 buffer 2)))
           (macsec-desired (unwrap (read-u8 buffer 2)))
           (sci (unwrap (slice buffer 4 8)))
           (sci-system-identifier (unwrap (slice buffer 4 6)))
           (sci-port-identifier (unwrap (read-u16be buffer 10)))
           (actor-mi (unwrap (slice buffer 12 1)))
           (actor-mn (unwrap (read-u32be buffer 12)))
           (key-server-ssci (unwrap (read-u8 buffer 21)))
           (peer-mi (unwrap (slice buffer 32 1)))
           (peer-mn (unwrap (read-u32be buffer 32)))
           (latest-key-an (unwrap (read-u8 buffer 37)))
           (latest-key-tx (unwrap (read-u8 buffer 37)))
           (latest-key-rx (unwrap (read-u8 buffer 37)))
           (old-key-an (unwrap (read-u8 buffer 37)))
           (old-key-tx (unwrap (read-u8 buffer 37)))
           (old-key-rx (unwrap (read-u8 buffer 37)))
           (plain-tx (unwrap (read-u8 buffer 38)))
           (plain-rx (unwrap (read-u8 buffer 38)))
           (delay-protect (unwrap (read-u8 buffer 38)))
           (latest-key-server-mi (unwrap (slice buffer 40 12)))
           (latest-key-number (unwrap (read-u32be buffer 52)))
           (latest-lowest-acceptable-pn (unwrap (read-u32be buffer 56)))
           (old-key-server-mi (unwrap (slice buffer 60 12)))
           (old-key-number (unwrap (read-u32be buffer 72)))
           (old-lowest-acceptable-pn (unwrap (read-u32be buffer 76)))
           (distributed-an (unwrap (read-u8 buffer 81)))
           (key-number (unwrap (read-u32be buffer 84)))
           (aes-key-wrap-sak (unwrap (slice buffer 88 1)))
           (aes-key-wrap-cak (unwrap (slice buffer 92 24)))
           (cak-name (unwrap (slice buffer 116 1)))
           (tlv-info-string-length (unwrap (read-u16be buffer 124)))
           (kmd (unwrap (slice buffer 134 1)))
           (tlv-data (unwrap (slice buffer 134 1)))
           (suspension-time (unwrap (read-u8 buffer 135)))
           (latest-lowest-accept-pn-msb (unwrap (read-u32be buffer 138)))
           (old-lowest-accept-pn-msb (unwrap (read-u32be buffer 142)))
           (param-body-length (unwrap (read-u16be buffer 146)))
           (unknown-param-set (unwrap (slice buffer 148 1)))
           (padding (unwrap (slice buffer 152 1)))
           )

      (ok (list
        (cons 'cak-name-info (list (cons 'raw cak-name-info) (cons 'formatted (utf8->string cak-name-info))))
        (cons 'version-id (list (cons 'raw version-id) (cons 'formatted (number->string version-id))))
        (cons 'keyserver-priority (list (cons 'raw keyserver-priority) (cons 'formatted (number->string keyserver-priority))))
        (cons 'key-server (list (cons 'raw key-server) (cons 'formatted (number->string key-server))))
        (cons 'macsec-desired (list (cons 'raw macsec-desired) (cons 'formatted (number->string macsec-desired))))
        (cons 'sci (list (cons 'raw sci) (cons 'formatted (fmt-bytes sci))))
        (cons 'sci-system-identifier (list (cons 'raw sci-system-identifier) (cons 'formatted (fmt-mac sci-system-identifier))))
        (cons 'sci-port-identifier (list (cons 'raw sci-port-identifier) (cons 'formatted (number->string sci-port-identifier))))
        (cons 'actor-mi (list (cons 'raw actor-mi) (cons 'formatted (fmt-bytes actor-mi))))
        (cons 'actor-mn (list (cons 'raw actor-mn) (cons 'formatted (number->string actor-mn))))
        (cons 'key-server-ssci (list (cons 'raw key-server-ssci) (cons 'formatted (fmt-hex key-server-ssci))))
        (cons 'peer-mi (list (cons 'raw peer-mi) (cons 'formatted (fmt-bytes peer-mi))))
        (cons 'peer-mn (list (cons 'raw peer-mn) (cons 'formatted (number->string peer-mn))))
        (cons 'latest-key-an (list (cons 'raw latest-key-an) (cons 'formatted (number->string latest-key-an))))
        (cons 'latest-key-tx (list (cons 'raw latest-key-tx) (cons 'formatted (number->string latest-key-tx))))
        (cons 'latest-key-rx (list (cons 'raw latest-key-rx) (cons 'formatted (number->string latest-key-rx))))
        (cons 'old-key-an (list (cons 'raw old-key-an) (cons 'formatted (number->string old-key-an))))
        (cons 'old-key-tx (list (cons 'raw old-key-tx) (cons 'formatted (number->string old-key-tx))))
        (cons 'old-key-rx (list (cons 'raw old-key-rx) (cons 'formatted (number->string old-key-rx))))
        (cons 'plain-tx (list (cons 'raw plain-tx) (cons 'formatted (number->string plain-tx))))
        (cons 'plain-rx (list (cons 'raw plain-rx) (cons 'formatted (number->string plain-rx))))
        (cons 'delay-protect (list (cons 'raw delay-protect) (cons 'formatted (number->string delay-protect))))
        (cons 'latest-key-server-mi (list (cons 'raw latest-key-server-mi) (cons 'formatted (fmt-bytes latest-key-server-mi))))
        (cons 'latest-key-number (list (cons 'raw latest-key-number) (cons 'formatted (number->string latest-key-number))))
        (cons 'latest-lowest-acceptable-pn (list (cons 'raw latest-lowest-acceptable-pn) (cons 'formatted (number->string latest-lowest-acceptable-pn))))
        (cons 'old-key-server-mi (list (cons 'raw old-key-server-mi) (cons 'formatted (fmt-bytes old-key-server-mi))))
        (cons 'old-key-number (list (cons 'raw old-key-number) (cons 'formatted (number->string old-key-number))))
        (cons 'old-lowest-acceptable-pn (list (cons 'raw old-lowest-acceptable-pn) (cons 'formatted (number->string old-lowest-acceptable-pn))))
        (cons 'distributed-an (list (cons 'raw distributed-an) (cons 'formatted (number->string distributed-an))))
        (cons 'key-number (list (cons 'raw key-number) (cons 'formatted (number->string key-number))))
        (cons 'aes-key-wrap-sak (list (cons 'raw aes-key-wrap-sak) (cons 'formatted (fmt-bytes aes-key-wrap-sak))))
        (cons 'aes-key-wrap-cak (list (cons 'raw aes-key-wrap-cak) (cons 'formatted (fmt-bytes aes-key-wrap-cak))))
        (cons 'cak-name (list (cons 'raw cak-name) (cons 'formatted (fmt-bytes cak-name))))
        (cons 'tlv-info-string-length (list (cons 'raw tlv-info-string-length) (cons 'formatted (number->string tlv-info-string-length))))
        (cons 'kmd (list (cons 'raw kmd) (cons 'formatted (utf8->string kmd))))
        (cons 'tlv-data (list (cons 'raw tlv-data) (cons 'formatted (fmt-bytes tlv-data))))
        (cons 'suspension-time (list (cons 'raw suspension-time) (cons 'formatted (number->string suspension-time))))
        (cons 'latest-lowest-accept-pn-msb (list (cons 'raw latest-lowest-accept-pn-msb) (cons 'formatted (number->string latest-lowest-accept-pn-msb))))
        (cons 'old-lowest-accept-pn-msb (list (cons 'raw old-lowest-accept-pn-msb) (cons 'formatted (number->string old-lowest-accept-pn-msb))))
        (cons 'param-body-length (list (cons 'raw param-body-length) (cons 'formatted (number->string param-body-length))))
        (cons 'unknown-param-set (list (cons 'raw unknown-param-set) (cons 'formatted (fmt-bytes unknown-param-set))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        )))

    (catch (e)
      (err (str "MKA parse error: " e)))))

;; dissect-mka: parse MKA from bytevector
;; Returns (ok fields-alist) or (err message)