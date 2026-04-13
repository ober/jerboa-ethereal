;; packet-wsp.c
;;
;; Routines to dissect WSP component of WAP traffic.
;;
;; Refer to the AUTHORS file or the AUTHORS section in the man page
;; for contacting the author(s) of this file.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; WAP dissector based on original work by Ben Fowler
;; Updated by Neil Hunter.
;;
;; WTLS support by Alexandre P. Ferreira (Splice IP).
;;
;; Openwave header support by Dermot Bradley (Openwave).
;;
;; Code optimizations, header value dissection simplification with parse error
;; notification and macros, extra missing headers, WBXML registration,
;; summary line of WSP PDUs,
;; Session Initiation Request dissection
;; by Olivier Biot.
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/wsp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-wsp.c

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
(def (dissect-wsp buffer)
  "Wireless Session Protocol"
  (try
    (let* (
           (header-tid (unwrap (read-u8 buffer 0)))
           (version (unwrap (read-u8 buffer 0)))
           (charset (unwrap (slice buffer 0 1)))
           (parameter-int-type (unwrap (read-u32be buffer 0)))
           (parameter-upart-type (unwrap (slice buffer 0 1)))
           (parameter-level (unwrap (slice buffer 0 1)))
           (parameter-size (unwrap (read-u32be buffer 0)))
           (redirect-flags (unwrap (read-u8 buffer 0)))
           (redirect-permanent (extract-bits redirect-flags 0x0 0))
           (redirect-reuse-security-session (extract-bits redirect-flags 0x0 0))
           (entry (unwrap (read-u32be buffer 0)))
           (flags-length (unwrap (read-u8 buffer 0)))
           (flags-length-bearer-type-included (extract-bits flags-length 0x0 0))
           (flags-length-port-number-included (extract-bits flags-length 0x0 0))
           (flags-length-address-len (extract-bits flags-length 0x0 0))
           (port-num (unwrap (read-u16be buffer 0)))
           (version-major (unwrap (read-u8 buffer 0)))
           (version-minor (unwrap (read-u8 buffer 0)))
           (server-session-id (unwrap (read-u32be buffer 0)))
           (length (unwrap (read-u32be buffer 0)))
           (header-length (unwrap (read-u32be buffer 0)))
           (client-sdu-size (unwrap (read-u8 buffer 0)))
           (server-sdu-size (unwrap (read-u8 buffer 0)))
           (protocol-options (unwrap (read-u8 buffer 0)))
           (protocol-option-confirmed-push (extract-bits protocol-options 0x80 7))
           (protocol-option-push (extract-bits protocol-options 0x40 6))
           (protocol-option-session-resume (extract-bits protocol-options 0x20 5))
           (protocol-option-ack-headers (extract-bits protocol-options 0x10 4))
           (protocol-option-large-data-transfer (extract-bits protocol-options 0x8 3))
           (method-mor (unwrap (read-u8 buffer 0)))
           (push-mor (unwrap (read-u8 buffer 0)))
           (extended-method (unwrap (read-u8 buffer 0)))
           (header-code-page (unwrap (read-u8 buffer 0)))
           (client-message-size (unwrap (read-u8 buffer 0)))
           (server-message-size (unwrap (read-u8 buffer 0)))
           (app-id-list-len (unwrap (read-u32be buffer 1)))
           (wsp-contact-points-len (unwrap (read-u32be buffer 1)))
           (contact-points-len (unwrap (read-u32be buffer 1)))
           (protocol-options-len (unwrap (read-u32be buffer 1)))
           (prov-url-len (unwrap (read-u32be buffer 1)))
           (prov-url (unwrap (slice buffer 1 1)))
           (cpi-tag-len (unwrap (read-u32be buffer 1)))
           (cpi-tag (unwrap (slice buffer 1 4)))
           (ipv4-addr (unwrap (read-u32be buffer 2)))
           (ipv6-addr (unwrap (slice buffer 2 16)))
           (addr (unwrap (slice buffer 2 1)))
           (header-shift-code (unwrap (read-u16be buffer 2)))
           )

      (ok (list
        (cons 'header-tid (list (cons 'raw header-tid) (cons 'formatted (fmt-hex header-tid))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'charset (list (cons 'raw charset) (cons 'formatted (utf8->string charset))))
        (cons 'parameter-int-type (list (cons 'raw parameter-int-type) (cons 'formatted (number->string parameter-int-type))))
        (cons 'parameter-upart-type (list (cons 'raw parameter-upart-type) (cons 'formatted (utf8->string parameter-upart-type))))
        (cons 'parameter-level (list (cons 'raw parameter-level) (cons 'formatted (utf8->string parameter-level))))
        (cons 'parameter-size (list (cons 'raw parameter-size) (cons 'formatted (number->string parameter-size))))
        (cons 'redirect-flags (list (cons 'raw redirect-flags) (cons 'formatted (fmt-hex redirect-flags))))
        (cons 'redirect-permanent (list (cons 'raw redirect-permanent) (cons 'formatted (if (= redirect-permanent 0) "Not set" "Set"))))
        (cons 'redirect-reuse-security-session (list (cons 'raw redirect-reuse-security-session) (cons 'formatted (if (= redirect-reuse-security-session 0) "Not set" "Set"))))
        (cons 'entry (list (cons 'raw entry) (cons 'formatted (number->string entry))))
        (cons 'flags-length (list (cons 'raw flags-length) (cons 'formatted (fmt-hex flags-length))))
        (cons 'flags-length-bearer-type-included (list (cons 'raw flags-length-bearer-type-included) (cons 'formatted (if (= flags-length-bearer-type-included 0) "Not set" "Set"))))
        (cons 'flags-length-port-number-included (list (cons 'raw flags-length-port-number-included) (cons 'formatted (if (= flags-length-port-number-included 0) "Not set" "Set"))))
        (cons 'flags-length-address-len (list (cons 'raw flags-length-address-len) (cons 'formatted (if (= flags-length-address-len 0) "Not set" "Set"))))
        (cons 'port-num (list (cons 'raw port-num) (cons 'formatted (number->string port-num))))
        (cons 'version-major (list (cons 'raw version-major) (cons 'formatted (number->string version-major))))
        (cons 'version-minor (list (cons 'raw version-minor) (cons 'formatted (number->string version-minor))))
        (cons 'server-session-id (list (cons 'raw server-session-id) (cons 'formatted (number->string server-session-id))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'header-length (list (cons 'raw header-length) (cons 'formatted (number->string header-length))))
        (cons 'client-sdu-size (list (cons 'raw client-sdu-size) (cons 'formatted (number->string client-sdu-size))))
        (cons 'server-sdu-size (list (cons 'raw server-sdu-size) (cons 'formatted (number->string server-sdu-size))))
        (cons 'protocol-options (list (cons 'raw protocol-options) (cons 'formatted (fmt-hex protocol-options))))
        (cons 'protocol-option-confirmed-push (list (cons 'raw protocol-option-confirmed-push) (cons 'formatted (if (= protocol-option-confirmed-push 0) "Not set" "Set"))))
        (cons 'protocol-option-push (list (cons 'raw protocol-option-push) (cons 'formatted (if (= protocol-option-push 0) "Not set" "Set"))))
        (cons 'protocol-option-session-resume (list (cons 'raw protocol-option-session-resume) (cons 'formatted (if (= protocol-option-session-resume 0) "Not set" "Set"))))
        (cons 'protocol-option-ack-headers (list (cons 'raw protocol-option-ack-headers) (cons 'formatted (if (= protocol-option-ack-headers 0) "Not set" "Set"))))
        (cons 'protocol-option-large-data-transfer (list (cons 'raw protocol-option-large-data-transfer) (cons 'formatted (if (= protocol-option-large-data-transfer 0) "Not set" "Set"))))
        (cons 'method-mor (list (cons 'raw method-mor) (cons 'formatted (number->string method-mor))))
        (cons 'push-mor (list (cons 'raw push-mor) (cons 'formatted (number->string push-mor))))
        (cons 'extended-method (list (cons 'raw extended-method) (cons 'formatted (fmt-hex extended-method))))
        (cons 'header-code-page (list (cons 'raw header-code-page) (cons 'formatted (fmt-hex header-code-page))))
        (cons 'client-message-size (list (cons 'raw client-message-size) (cons 'formatted (number->string client-message-size))))
        (cons 'server-message-size (list (cons 'raw server-message-size) (cons 'formatted (number->string server-message-size))))
        (cons 'app-id-list-len (list (cons 'raw app-id-list-len) (cons 'formatted (number->string app-id-list-len))))
        (cons 'wsp-contact-points-len (list (cons 'raw wsp-contact-points-len) (cons 'formatted (number->string wsp-contact-points-len))))
        (cons 'contact-points-len (list (cons 'raw contact-points-len) (cons 'formatted (number->string contact-points-len))))
        (cons 'protocol-options-len (list (cons 'raw protocol-options-len) (cons 'formatted (number->string protocol-options-len))))
        (cons 'prov-url-len (list (cons 'raw prov-url-len) (cons 'formatted (number->string prov-url-len))))
        (cons 'prov-url (list (cons 'raw prov-url) (cons 'formatted (utf8->string prov-url))))
        (cons 'cpi-tag-len (list (cons 'raw cpi-tag-len) (cons 'formatted (number->string cpi-tag-len))))
        (cons 'cpi-tag (list (cons 'raw cpi-tag) (cons 'formatted (fmt-bytes cpi-tag))))
        (cons 'ipv4-addr (list (cons 'raw ipv4-addr) (cons 'formatted (fmt-ipv4 ipv4-addr))))
        (cons 'ipv6-addr (list (cons 'raw ipv6-addr) (cons 'formatted (fmt-ipv6-address ipv6-addr))))
        (cons 'addr (list (cons 'raw addr) (cons 'formatted (fmt-bytes addr))))
        (cons 'header-shift-code (list (cons 'raw header-shift-code) (cons 'formatted (number->string header-shift-code))))
        )))

    (catch (e)
      (err (str "WSP parse error: " e)))))

;; dissect-wsp: parse WSP from bytevector
;; Returns (ok fields-alist) or (err message)