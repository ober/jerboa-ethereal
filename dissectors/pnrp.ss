;; packet-pnrp.c
;; Routines for Peer Name Resolution Protocol (PNRP) dissection
;;
;; Copyright 2010, Jan Gerbecks <jan.gerbecks@stud.uni-due.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/pnrp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-pnrp.c

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
(def (dissect-pnrp buffer)
  "pnrp dissector"
  (try
    (let* (
           (fragmented-payload (unwrap (slice buffer 0 1)))
           (message-length (unwrap (read-u16be buffer 0)))
           (message-ipv6EndpointArray-NumberOfEntries (unwrap (read-u16be buffer 0)))
           (message-ipv6EndpointArray-ArrayLength (unwrap (read-u16be buffer 0)))
           (message-ipv6EndpointArray-EntryLength (unwrap (read-u16be buffer 0)))
           (message-data (unwrap (slice buffer 0 1)))
           (header-length (unwrap (read-u16be buffer 2)))
           (header-ident (unwrap (read-u8 buffer 4)))
           (header-versionMajor (unwrap (read-u8 buffer 5)))
           (header-versionMinor (unwrap (read-u8 buffer 6)))
           (header-messageID (unwrap (read-u32be buffer 8)))
           (message-headerack (unwrap (read-u32be buffer 16)))
           (message-inquire-flags (unwrap (read-u16be buffer 16)))
           (message-inquire-flags-reserved1 (extract-bits message-inquire-flags 0x0 0))
           (message-inquire-flags-Abit (extract-bits message-inquire-flags 0x0 0))
           (message-inquire-flags-Xbit (extract-bits message-inquire-flags 0x0 0))
           (message-inquire-flags-Cbit (extract-bits message-inquire-flags 0x0 0))
           (message-inquire-flags-reserved2 (extract-bits message-inquire-flags 0x0 0))
           (padding (unwrap (slice buffer 16 2)))
           (message-authority-flags (unwrap (read-u16be buffer 16)))
           (message-authority-flags-reserved1 (extract-bits message-authority-flags 0x0 0))
           (message-authority-flags-Lbit (extract-bits message-authority-flags 0x0 0))
           (message-authority-flags-reserved2 (extract-bits message-authority-flags 0x0 0))
           (message-authority-flags-Bbit (extract-bits message-authority-flags 0x0 0))
           (message-authority-flags-reserved3 (extract-bits message-authority-flags 0x0 0))
           (message-authority-flags-Nbit (extract-bits message-authority-flags 0x0 0))
           (message-flags (unwrap (read-u32be buffer 16)))
           (reserved8 (unwrap (read-u8 buffer 16)))
           (reserved16 (unwrap (read-u16be buffer 16)))
           (message-lookupControls-flags (unwrap (read-u16be buffer 16)))
           (message-lookupControls-flags-reserved (extract-bits message-lookupControls-flags 0x0 0))
           (message-lookupControls-flags-Abit (extract-bits message-lookupControls-flags 0x0 0))
           (message-lookupControls-flags-0bit (extract-bits message-lookupControls-flags 0x0 0))
           (message-lookupControls-precision (unwrap (read-u16be buffer 16)))
           (message-idArray-NumEntries (unwrap (read-u16be buffer 16)))
           (message-idArray-Length (unwrap (read-u16be buffer 16)))
           (message-idarray-Entrylength (unwrap (read-u16be buffer 16)))
           (message-certChain (unwrap (slice buffer 16 1)))
           (message-classifier-unicodeCount (unwrap (read-u16be buffer 16)))
           (message-classifier-arrayLength (unwrap (read-u16be buffer 16)))
           (message-classifier-entryLength (unwrap (read-u16be buffer 16)))
           (message-classifier-string (unwrap (slice buffer 16 1)))
           (message-hashednonce (unwrap (slice buffer 16 1)))
           (message-nonce (unwrap (slice buffer 16 1)))
           (message-splitControls-authorityBuffer (unwrap (read-u16be buffer 16)))
           (message-offset (unwrap (read-u16be buffer 16)))
           )

      (ok (list
        (cons 'fragmented-payload (list (cons 'raw fragmented-payload) (cons 'formatted (fmt-bytes fragmented-payload))))
        (cons 'message-length (list (cons 'raw message-length) (cons 'formatted (number->string message-length))))
        (cons 'message-ipv6EndpointArray-NumberOfEntries (list (cons 'raw message-ipv6EndpointArray-NumberOfEntries) (cons 'formatted (number->string message-ipv6EndpointArray-NumberOfEntries))))
        (cons 'message-ipv6EndpointArray-ArrayLength (list (cons 'raw message-ipv6EndpointArray-ArrayLength) (cons 'formatted (number->string message-ipv6EndpointArray-ArrayLength))))
        (cons 'message-ipv6EndpointArray-EntryLength (list (cons 'raw message-ipv6EndpointArray-EntryLength) (cons 'formatted (number->string message-ipv6EndpointArray-EntryLength))))
        (cons 'message-data (list (cons 'raw message-data) (cons 'formatted (fmt-bytes message-data))))
        (cons 'header-length (list (cons 'raw header-length) (cons 'formatted (number->string header-length))))
        (cons 'header-ident (list (cons 'raw header-ident) (cons 'formatted (fmt-hex header-ident))))
        (cons 'header-versionMajor (list (cons 'raw header-versionMajor) (cons 'formatted (number->string header-versionMajor))))
        (cons 'header-versionMinor (list (cons 'raw header-versionMinor) (cons 'formatted (number->string header-versionMinor))))
        (cons 'header-messageID (list (cons 'raw header-messageID) (cons 'formatted (fmt-hex header-messageID))))
        (cons 'message-headerack (list (cons 'raw message-headerack) (cons 'formatted (fmt-hex message-headerack))))
        (cons 'message-inquire-flags (list (cons 'raw message-inquire-flags) (cons 'formatted (fmt-hex message-inquire-flags))))
        (cons 'message-inquire-flags-reserved1 (list (cons 'raw message-inquire-flags-reserved1) (cons 'formatted (if (= message-inquire-flags-reserved1 0) "Not set" "Set"))))
        (cons 'message-inquire-flags-Abit (list (cons 'raw message-inquire-flags-Abit) (cons 'formatted (if (= message-inquire-flags-Abit 0) "Not set" "Set"))))
        (cons 'message-inquire-flags-Xbit (list (cons 'raw message-inquire-flags-Xbit) (cons 'formatted (if (= message-inquire-flags-Xbit 0) "Not set" "Set"))))
        (cons 'message-inquire-flags-Cbit (list (cons 'raw message-inquire-flags-Cbit) (cons 'formatted (if (= message-inquire-flags-Cbit 0) "Not set" "Set"))))
        (cons 'message-inquire-flags-reserved2 (list (cons 'raw message-inquire-flags-reserved2) (cons 'formatted (if (= message-inquire-flags-reserved2 0) "Not set" "Set"))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        (cons 'message-authority-flags (list (cons 'raw message-authority-flags) (cons 'formatted (fmt-hex message-authority-flags))))
        (cons 'message-authority-flags-reserved1 (list (cons 'raw message-authority-flags-reserved1) (cons 'formatted (if (= message-authority-flags-reserved1 0) "Not set" "Set"))))
        (cons 'message-authority-flags-Lbit (list (cons 'raw message-authority-flags-Lbit) (cons 'formatted (if (= message-authority-flags-Lbit 0) "Not set" "Set"))))
        (cons 'message-authority-flags-reserved2 (list (cons 'raw message-authority-flags-reserved2) (cons 'formatted (if (= message-authority-flags-reserved2 0) "Not set" "Set"))))
        (cons 'message-authority-flags-Bbit (list (cons 'raw message-authority-flags-Bbit) (cons 'formatted (if (= message-authority-flags-Bbit 0) "Not set" "Set"))))
        (cons 'message-authority-flags-reserved3 (list (cons 'raw message-authority-flags-reserved3) (cons 'formatted (if (= message-authority-flags-reserved3 0) "Not set" "Set"))))
        (cons 'message-authority-flags-Nbit (list (cons 'raw message-authority-flags-Nbit) (cons 'formatted (if (= message-authority-flags-Nbit 0) "Not set" "Set"))))
        (cons 'message-flags (list (cons 'raw message-flags) (cons 'formatted (fmt-hex message-flags))))
        (cons 'reserved8 (list (cons 'raw reserved8) (cons 'formatted (number->string reserved8))))
        (cons 'reserved16 (list (cons 'raw reserved16) (cons 'formatted (number->string reserved16))))
        (cons 'message-lookupControls-flags (list (cons 'raw message-lookupControls-flags) (cons 'formatted (fmt-hex message-lookupControls-flags))))
        (cons 'message-lookupControls-flags-reserved (list (cons 'raw message-lookupControls-flags-reserved) (cons 'formatted (if (= message-lookupControls-flags-reserved 0) "Not set" "Set"))))
        (cons 'message-lookupControls-flags-Abit (list (cons 'raw message-lookupControls-flags-Abit) (cons 'formatted (if (= message-lookupControls-flags-Abit 0) "Not set" "Set"))))
        (cons 'message-lookupControls-flags-0bit (list (cons 'raw message-lookupControls-flags-0bit) (cons 'formatted (if (= message-lookupControls-flags-0bit 0) "Not set" "Set"))))
        (cons 'message-lookupControls-precision (list (cons 'raw message-lookupControls-precision) (cons 'formatted (fmt-hex message-lookupControls-precision))))
        (cons 'message-idArray-NumEntries (list (cons 'raw message-idArray-NumEntries) (cons 'formatted (number->string message-idArray-NumEntries))))
        (cons 'message-idArray-Length (list (cons 'raw message-idArray-Length) (cons 'formatted (number->string message-idArray-Length))))
        (cons 'message-idarray-Entrylength (list (cons 'raw message-idarray-Entrylength) (cons 'formatted (number->string message-idarray-Entrylength))))
        (cons 'message-certChain (list (cons 'raw message-certChain) (cons 'formatted (fmt-bytes message-certChain))))
        (cons 'message-classifier-unicodeCount (list (cons 'raw message-classifier-unicodeCount) (cons 'formatted (number->string message-classifier-unicodeCount))))
        (cons 'message-classifier-arrayLength (list (cons 'raw message-classifier-arrayLength) (cons 'formatted (number->string message-classifier-arrayLength))))
        (cons 'message-classifier-entryLength (list (cons 'raw message-classifier-entryLength) (cons 'formatted (number->string message-classifier-entryLength))))
        (cons 'message-classifier-string (list (cons 'raw message-classifier-string) (cons 'formatted (utf8->string message-classifier-string))))
        (cons 'message-hashednonce (list (cons 'raw message-hashednonce) (cons 'formatted (fmt-bytes message-hashednonce))))
        (cons 'message-nonce (list (cons 'raw message-nonce) (cons 'formatted (fmt-bytes message-nonce))))
        (cons 'message-splitControls-authorityBuffer (list (cons 'raw message-splitControls-authorityBuffer) (cons 'formatted (number->string message-splitControls-authorityBuffer))))
        (cons 'message-offset (list (cons 'raw message-offset) (cons 'formatted (number->string message-offset))))
        )))

    (catch (e)
      (err (str "PNRP parse error: " e)))))

;; dissect-pnrp: parse PNRP from bytevector
;; Returns (ok fields-alist) or (err message)