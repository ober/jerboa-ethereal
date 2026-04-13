;; packet-ecp.c
;; Routines for Solaris ECP/VDP dissection based on IEEE 802.1Qbg Draft 2.1
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ecp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ecp.c

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
(def (dissect-ecp buffer)
  "Edge Control Protocol"
  (try
    (let* (
           (vidstr-ps (unwrap (read-u16be buffer 0)))
           (vidstr-pcp (unwrap (read-u16be buffer 0)))
           (vidstr-vid (unwrap (read-u16be buffer 0)))
           (tlv-assoc-response-flags (unwrap (read-u8 buffer 0)))
           (tlv-assoc-flag-hard-error (extract-bits tlv-assoc-response-flags 0x10 4))
           (tlv-assoc-flag-keep (extract-bits tlv-assoc-response-flags 0x20 5))
           (tlv-assoc-reason (unwrap (read-u8 buffer 0)))
           (tlv-assoc-request-flags (unwrap (read-u8 buffer 0)))
           (tlv-assoc-flag-mbit (extract-bits tlv-assoc-request-flags 0x10 4))
           (tlv-assoc-flag-sbit (extract-bits tlv-assoc-request-flags 0x20 5))
           (tlv-assoc-flag-req-rsp (extract-bits tlv-assoc-request-flags 0x40 6))
           (vsitypeid (unwrap (read-u24be buffer 0)))
           (tlv-len (unwrap (read-u16be buffer 0)))
           (version (unwrap (read-u16be buffer 0)))
           (data (unwrap (slice buffer 2 1)))
           (seqno (unwrap (read-u16be buffer 2)))
           (vsiversion (unwrap (read-u8 buffer 3)))
           (assoc-mac-id (unwrap (slice buffer 21 6)))
           (manager-id (unwrap (slice buffer 29 16)))
           (tlv-org-oui (unwrap (read-u24be buffer 29)))
           )

      (ok (list
        (cons 'vidstr-ps (list (cons 'raw vidstr-ps) (cons 'formatted (fmt-hex vidstr-ps))))
        (cons 'vidstr-pcp (list (cons 'raw vidstr-pcp) (cons 'formatted (fmt-hex vidstr-pcp))))
        (cons 'vidstr-vid (list (cons 'raw vidstr-vid) (cons 'formatted (fmt-hex vidstr-vid))))
        (cons 'tlv-assoc-response-flags (list (cons 'raw tlv-assoc-response-flags) (cons 'formatted (fmt-hex tlv-assoc-response-flags))))
        (cons 'tlv-assoc-flag-hard-error (list (cons 'raw tlv-assoc-flag-hard-error) (cons 'formatted (if (= tlv-assoc-flag-hard-error 0) "Not set" "Set"))))
        (cons 'tlv-assoc-flag-keep (list (cons 'raw tlv-assoc-flag-keep) (cons 'formatted (if (= tlv-assoc-flag-keep 0) "Not set" "Set"))))
        (cons 'tlv-assoc-reason (list (cons 'raw tlv-assoc-reason) (cons 'formatted (fmt-hex tlv-assoc-reason))))
        (cons 'tlv-assoc-request-flags (list (cons 'raw tlv-assoc-request-flags) (cons 'formatted (fmt-hex tlv-assoc-request-flags))))
        (cons 'tlv-assoc-flag-mbit (list (cons 'raw tlv-assoc-flag-mbit) (cons 'formatted (if (= tlv-assoc-flag-mbit 0) "Not set" "Set"))))
        (cons 'tlv-assoc-flag-sbit (list (cons 'raw tlv-assoc-flag-sbit) (cons 'formatted (if (= tlv-assoc-flag-sbit 0) "Not set" "Set"))))
        (cons 'tlv-assoc-flag-req-rsp (list (cons 'raw tlv-assoc-flag-req-rsp) (cons 'formatted (if (= tlv-assoc-flag-req-rsp 0) "Not set" "Set"))))
        (cons 'vsitypeid (list (cons 'raw vsitypeid) (cons 'formatted (fmt-hex vsitypeid))))
        (cons 'tlv-len (list (cons 'raw tlv-len) (cons 'formatted (number->string tlv-len))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'seqno (list (cons 'raw seqno) (cons 'formatted (number->string seqno))))
        (cons 'vsiversion (list (cons 'raw vsiversion) (cons 'formatted (fmt-hex vsiversion))))
        (cons 'assoc-mac-id (list (cons 'raw assoc-mac-id) (cons 'formatted (fmt-mac assoc-mac-id))))
        (cons 'manager-id (list (cons 'raw manager-id) (cons 'formatted (fmt-ipv6-address manager-id))))
        (cons 'tlv-org-oui (list (cons 'raw tlv-org-oui) (cons 'formatted (number->string tlv-org-oui))))
        )))

    (catch (e)
      (err (str "ECP parse error: " e)))))

;; dissect-ecp: parse ECP from bytevector
;; Returns (ok fields-alist) or (err message)