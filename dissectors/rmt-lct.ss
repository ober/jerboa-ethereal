;; packet-rmt-lct.c
;; Reliable Multicast Transport (RMT)
;; LCT Building Block dissector
;; Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
;; Copyright 2023, Sergey V. Lobanov <sergey@lobanov.in>
;;
;; Layered Coding Transport (LCT):
;; -------------------------------
;;
;; Provides transport level support for reliable content delivery
;; and stream delivery protocols. LCT is specifically designed to
;; support protocols using IP multicast, but also provides support
;; to protocols that use unicast. LCT is compatible with congestion
;; control that provides multiple rate delivery to receivers and
;; is also compatible with coding techniques that provide
;; reliable delivery of content.
;;
;; References:
;; RFC 3451, Layered Coding Transport (LCT) Building Block
;; RFC 5651, Layered Coding Transport (LCT) Building Block
;; RFC 5775, Asynchronous Layered Coding (ALC) Protocol Instantiation
;;
;; ATSC3 Signaling, Delivery, Synchronization, and Error Protection (A/331)
;; https://www.atsc.org/atsc-documents/3312017-signaling-delivery-synchronization-error-protection/
;;
;; IANA Layered Coding Transport (LCT) Header Extension Types
;; https://www.iana.org/assignments/lct-header-extensions/lct-header-extensions.txt
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rmt-lct.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rmt_lct.c
;; RFC 3451

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
(def (dissect-rmt-lct buffer)
  "Layered Coding Transport"
  (try
    (let* (
           (len (unwrap (read-u8 buffer 0)))
           (data (unwrap (slice buffer 0 1)))
           (sequence (unwrap (read-u16be buffer 0)))
           (flags (unwrap (read-u8 buffer 0)))
           (rtt (unwrap (read-u8 buffer 0)))
           (loss (unwrap (read-u64be buffer 0)))
           (tol-48-transfer-len (unwrap (slice buffer 0 6)))
           (rate (unwrap (read-u64be buffer 0)))
           (version (unwrap (read-u32be buffer 0)))
           (instance-id (unwrap (read-u32be buffer 0)))
           (hf-cenc (unwrap (read-u8 buffer 0)))
           (tol-24-transfer-len (unwrap (read-u24be buffer 0)))
           (hf-version (unwrap (read-u16be buffer 0)))
           (hf-psi (unwrap (read-u16be buffer 0)))
           (hf-spi (unwrap (read-u8 buffer 0)))
           (cci (unwrap (read-u16be buffer 0)))
           (tsi (unwrap (read-u16be buffer 0)))
           (toi (unwrap (read-u16be buffer 0)))
           (header (unwrap (read-u16be buffer 0)))
           (sct-present (unwrap (read-u8 buffer 0)))
           (ert-present (unwrap (read-u8 buffer 0)))
           (close-session (unwrap (read-u8 buffer 0)))
           (close-object (unwrap (read-u8 buffer 0)))
           (hf-hlen (unwrap (read-u16be buffer 0)))
           (hf-codepoint (unwrap (read-u8 buffer 0)))
           (hf-cci (unwrap (slice buffer 4 1)))
           (hf-tsi16 (unwrap (read-u16be buffer 4)))
           (hf-tsi32 (unwrap (read-u32be buffer 4)))
           (hf-tsi48 (unwrap (read-u64be buffer 4)))
           (hf-toi16 (unwrap (read-u16be buffer 4)))
           (hf-toi32 (unwrap (read-u32be buffer 4)))
           (hf-toi48 (unwrap (read-u64be buffer 4)))
           (hf-toi64 (unwrap (read-u64be buffer 4)))
           (extended (unwrap (read-u64be buffer 4)))
           )

      (ok (list
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'sequence (list (cons 'raw sequence) (cons 'formatted (number->string sequence))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'rtt (list (cons 'raw rtt) (cons 'formatted (number->string rtt))))
        (cons 'loss (list (cons 'raw loss) (cons 'formatted (number->string loss))))
        (cons 'tol-48-transfer-len (list (cons 'raw tol-48-transfer-len) (cons 'formatted (number->string tol-48-transfer-len))))
        (cons 'rate (list (cons 'raw rate) (cons 'formatted (number->string rate))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'instance-id (list (cons 'raw instance-id) (cons 'formatted (number->string instance-id))))
        (cons 'hf-cenc (list (cons 'raw hf-cenc) (cons 'formatted (number->string hf-cenc))))
        (cons 'tol-24-transfer-len (list (cons 'raw tol-24-transfer-len) (cons 'formatted (number->string tol-24-transfer-len))))
        (cons 'hf-version (list (cons 'raw hf-version) (cons 'formatted (number->string hf-version))))
        (cons 'hf-psi (list (cons 'raw hf-psi) (cons 'formatted (fmt-hex hf-psi))))
        (cons 'hf-spi (list (cons 'raw hf-spi) (cons 'formatted (number->string hf-spi))))
        (cons 'cci (list (cons 'raw cci) (cons 'formatted (number->string cci))))
        (cons 'tsi (list (cons 'raw tsi) (cons 'formatted (number->string tsi))))
        (cons 'toi (list (cons 'raw toi) (cons 'formatted (number->string toi))))
        (cons 'header (list (cons 'raw header) (cons 'formatted (fmt-hex header))))
        (cons 'sct-present (list (cons 'raw sct-present) (cons 'formatted (if (= sct-present 0) "False" "True"))))
        (cons 'ert-present (list (cons 'raw ert-present) (cons 'formatted (if (= ert-present 0) "False" "True"))))
        (cons 'close-session (list (cons 'raw close-session) (cons 'formatted (if (= close-session 0) "False" "True"))))
        (cons 'close-object (list (cons 'raw close-object) (cons 'formatted (if (= close-object 0) "False" "True"))))
        (cons 'hf-hlen (list (cons 'raw hf-hlen) (cons 'formatted (number->string hf-hlen))))
        (cons 'hf-codepoint (list (cons 'raw hf-codepoint) (cons 'formatted (number->string hf-codepoint))))
        (cons 'hf-cci (list (cons 'raw hf-cci) (cons 'formatted (fmt-bytes hf-cci))))
        (cons 'hf-tsi16 (list (cons 'raw hf-tsi16) (cons 'formatted (number->string hf-tsi16))))
        (cons 'hf-tsi32 (list (cons 'raw hf-tsi32) (cons 'formatted (number->string hf-tsi32))))
        (cons 'hf-tsi48 (list (cons 'raw hf-tsi48) (cons 'formatted (number->string hf-tsi48))))
        (cons 'hf-toi16 (list (cons 'raw hf-toi16) (cons 'formatted (number->string hf-toi16))))
        (cons 'hf-toi32 (list (cons 'raw hf-toi32) (cons 'formatted (number->string hf-toi32))))
        (cons 'hf-toi48 (list (cons 'raw hf-toi48) (cons 'formatted (number->string hf-toi48))))
        (cons 'hf-toi64 (list (cons 'raw hf-toi64) (cons 'formatted (number->string hf-toi64))))
        (cons 'extended (list (cons 'raw extended) (cons 'formatted (number->string extended))))
        )))

    (catch (e)
      (err (str "RMT-LCT parse error: " e)))))

;; dissect-rmt-lct: parse RMT-LCT from bytevector
;; Returns (ok fields-alist) or (err message)