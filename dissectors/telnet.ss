;; packet-telnet.c
;; Routines for Telnet packet dissection; see RFC 854 and RFC 855
;; Copyright 1999, Richard Sharpe <rsharpe@ns.aus.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/telnet.ss
;; Auto-generated from wireshark/epan/dissectors/packet-telnet.c
;; RFC 854

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
(def (dissect-telnet buffer)
  "Telnet"
  (try
    (let* (
           (subcmd (unwrap (read-u8 buffer 0)))
           (string-subopt-value (unwrap (slice buffer 0 1)))
           (regime-cmd (unwrap (read-u8 buffer 0)))
           (regime-subopt-value (unwrap (slice buffer 0 1)))
           (connect (unwrap (slice buffer 0 1)))
           (is (unwrap (slice buffer 0 1)))
           (request-string (unwrap (slice buffer 0 1)))
           (starttls (unwrap (read-u8 buffer 0)))
           (outmark-subopt-banner (unwrap (slice buffer 0 1)))
           (tabstop (unwrap (read-u8 buffer 0)))
           (naws-subopt-width (unwrap (read-u16be buffer 0)))
           (naws-subopt-height (unwrap (read-u16be buffer 2)))
           (comport-subopt-signature (unwrap (slice buffer 2 1)))
           (comport-subopt-baud-rate (unwrap (read-u32be buffer 2)))
           (comport-subopt-data-size (unwrap (read-u8 buffer 2)))
           (comport-subopt-parity (unwrap (read-u16be buffer 2)))
           (comport-subopt-stop (unwrap (read-u16be buffer 2)))
           (comport-subopt-control (unwrap (read-u16be buffer 2)))
           (comport-subopt-purge (unwrap (read-u16be buffer 2)))
           (auth-data (unwrap (slice buffer 4 1)))
           (auth-name (unwrap (slice buffer 6 1)))
           (enc-type-data (unwrap (slice buffer 6 1)))
           (enc-key-id (unwrap (slice buffer 6 1)))
           (vmware-unknown-subopt-code (unwrap (read-u8 buffer 6)))
           (vmware-vmotion-sequence (unwrap (slice buffer 6 1)))
           (vmware-vmotion-secret (unwrap (slice buffer 6 1)))
           (vmware-proxy-serviceUri (unwrap (slice buffer 6 1)))
           (vmware-vm-name (unwrap (slice buffer 6 1)))
           (vmware-vm-vc-uuid (unwrap (slice buffer 6 1)))
           (vmware-vm-bios-uuid (unwrap (slice buffer 6 1)))
           (vmware-vm-location-uuid (unwrap (slice buffer 6 1)))
           (subcommand-data (unwrap (slice buffer 6 1)))
           (data (unwrap (slice buffer 12 1)))
           )

      (ok (list
        (cons 'subcmd (list (cons 'raw subcmd) (cons 'formatted (number->string subcmd))))
        (cons 'string-subopt-value (list (cons 'raw string-subopt-value) (cons 'formatted (utf8->string string-subopt-value))))
        (cons 'regime-cmd (list (cons 'raw regime-cmd) (cons 'formatted (number->string regime-cmd))))
        (cons 'regime-subopt-value (list (cons 'raw regime-subopt-value) (cons 'formatted (utf8->string regime-subopt-value))))
        (cons 'connect (list (cons 'raw connect) (cons 'formatted (utf8->string connect))))
        (cons 'is (list (cons 'raw is) (cons 'formatted (utf8->string is))))
        (cons 'request-string (list (cons 'raw request-string) (cons 'formatted (utf8->string request-string))))
        (cons 'starttls (list (cons 'raw starttls) (cons 'formatted (number->string starttls))))
        (cons 'outmark-subopt-banner (list (cons 'raw outmark-subopt-banner) (cons 'formatted (utf8->string outmark-subopt-banner))))
        (cons 'tabstop (list (cons 'raw tabstop) (cons 'formatted (number->string tabstop))))
        (cons 'naws-subopt-width (list (cons 'raw naws-subopt-width) (cons 'formatted (number->string naws-subopt-width))))
        (cons 'naws-subopt-height (list (cons 'raw naws-subopt-height) (cons 'formatted (number->string naws-subopt-height))))
        (cons 'comport-subopt-signature (list (cons 'raw comport-subopt-signature) (cons 'formatted (utf8->string comport-subopt-signature))))
        (cons 'comport-subopt-baud-rate (list (cons 'raw comport-subopt-baud-rate) (cons 'formatted (number->string comport-subopt-baud-rate))))
        (cons 'comport-subopt-data-size (list (cons 'raw comport-subopt-data-size) (cons 'formatted (number->string comport-subopt-data-size))))
        (cons 'comport-subopt-parity (list (cons 'raw comport-subopt-parity) (cons 'formatted (number->string comport-subopt-parity))))
        (cons 'comport-subopt-stop (list (cons 'raw comport-subopt-stop) (cons 'formatted (number->string comport-subopt-stop))))
        (cons 'comport-subopt-control (list (cons 'raw comport-subopt-control) (cons 'formatted (number->string comport-subopt-control))))
        (cons 'comport-subopt-purge (list (cons 'raw comport-subopt-purge) (cons 'formatted (number->string comport-subopt-purge))))
        (cons 'auth-data (list (cons 'raw auth-data) (cons 'formatted (fmt-bytes auth-data))))
        (cons 'auth-name (list (cons 'raw auth-name) (cons 'formatted (utf8->string auth-name))))
        (cons 'enc-type-data (list (cons 'raw enc-type-data) (cons 'formatted (fmt-bytes enc-type-data))))
        (cons 'enc-key-id (list (cons 'raw enc-key-id) (cons 'formatted (fmt-bytes enc-key-id))))
        (cons 'vmware-unknown-subopt-code (list (cons 'raw vmware-unknown-subopt-code) (cons 'formatted (number->string vmware-unknown-subopt-code))))
        (cons 'vmware-vmotion-sequence (list (cons 'raw vmware-vmotion-sequence) (cons 'formatted (fmt-bytes vmware-vmotion-sequence))))
        (cons 'vmware-vmotion-secret (list (cons 'raw vmware-vmotion-secret) (cons 'formatted (fmt-bytes vmware-vmotion-secret))))
        (cons 'vmware-proxy-serviceUri (list (cons 'raw vmware-proxy-serviceUri) (cons 'formatted (utf8->string vmware-proxy-serviceUri))))
        (cons 'vmware-vm-name (list (cons 'raw vmware-vm-name) (cons 'formatted (utf8->string vmware-vm-name))))
        (cons 'vmware-vm-vc-uuid (list (cons 'raw vmware-vm-vc-uuid) (cons 'formatted (utf8->string vmware-vm-vc-uuid))))
        (cons 'vmware-vm-bios-uuid (list (cons 'raw vmware-vm-bios-uuid) (cons 'formatted (utf8->string vmware-vm-bios-uuid))))
        (cons 'vmware-vm-location-uuid (list (cons 'raw vmware-vm-location-uuid) (cons 'formatted (utf8->string vmware-vm-location-uuid))))
        (cons 'subcommand-data (list (cons 'raw subcommand-data) (cons 'formatted (fmt-bytes subcommand-data))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (utf8->string data))))
        )))

    (catch (e)
      (err (str "TELNET parse error: " e)))))

;; dissect-telnet: parse TELNET from bytevector
;; Returns (ok fields-alist) or (err message)