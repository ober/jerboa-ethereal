;; packet-vmware-hb.c
;; Routines for VMware HeartBeat dissection
;; Copyright 2023, Alexis La Goutte <alexis.lagoutte at gmail dot com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; No spec/doc is available based on reverse/analysis of protocol...
;;
;;

;; jerboa-ethereal/dissectors/vmware-hb.ss
;; Auto-generated from wireshark/epan/dissectors/packet-vmware_hb.c

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
(def (dissect-vmware-hb buffer)
  "VMware - HeartBeat"
  (try
    (let* (
           (hb-magic (unwrap (read-u32be buffer 0)))
           (hb-server-id (unwrap (read-u32be buffer 8)))
           (hb-host-key-length (unwrap (read-u8 buffer 12)))
           (hb-host-key (unwrap (slice buffer 13 1)))
           (hb-change-gen (unwrap (read-u32be buffer 13)))
           (hb-spec-gen (unwrap (read-u32be buffer 17)))
           (hb-bundle-version (unwrap (read-u32be buffer 21)))
           (hb-heartbeat-counter (unwrap (read-u32be buffer 25)))
           (hb-ip4-address-length (unwrap (read-u8 buffer 29)))
           (hb-ip4-address (unwrap (slice buffer 30 1)))
           (hb-verification-signature (unwrap (slice buffer 30 1)))
           )

      (ok (list
        (cons 'hb-magic (list (cons 'raw hb-magic) (cons 'formatted (fmt-hex hb-magic))))
        (cons 'hb-server-id (list (cons 'raw hb-server-id) (cons 'formatted (number->string hb-server-id))))
        (cons 'hb-host-key-length (list (cons 'raw hb-host-key-length) (cons 'formatted (number->string hb-host-key-length))))
        (cons 'hb-host-key (list (cons 'raw hb-host-key) (cons 'formatted (utf8->string hb-host-key))))
        (cons 'hb-change-gen (list (cons 'raw hb-change-gen) (cons 'formatted (number->string hb-change-gen))))
        (cons 'hb-spec-gen (list (cons 'raw hb-spec-gen) (cons 'formatted (number->string hb-spec-gen))))
        (cons 'hb-bundle-version (list (cons 'raw hb-bundle-version) (cons 'formatted (number->string hb-bundle-version))))
        (cons 'hb-heartbeat-counter (list (cons 'raw hb-heartbeat-counter) (cons 'formatted (number->string hb-heartbeat-counter))))
        (cons 'hb-ip4-address-length (list (cons 'raw hb-ip4-address-length) (cons 'formatted (number->string hb-ip4-address-length))))
        (cons 'hb-ip4-address (list (cons 'raw hb-ip4-address) (cons 'formatted (utf8->string hb-ip4-address))))
        (cons 'hb-verification-signature (list (cons 'raw hb-verification-signature) (cons 'formatted (fmt-bytes hb-verification-signature))))
        )))

    (catch (e)
      (err (str "VMWARE-HB parse error: " e)))))

;; dissect-vmware-hb: parse VMWARE-HB from bytevector
;; Returns (ok fields-alist) or (err message)