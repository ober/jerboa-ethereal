;; packet-rpcap.c
;;
;; Routines for RPCAP message formats.
;;
;; Copyright 2008, Stig Bjorlykke <stig@bjorlykke.org>, Thales Norway AS
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rpcap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rpcap.c

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
(def (dissect-rpcap buffer)
  "Remote Packet Capture"
  (try
    (let* (
           (hf-version (unwrap (read-u8 buffer 0)))
           (hf-value (unwrap (read-u16be buffer 0)))
           (hf-plen (unwrap (read-u32be buffer 2)))
           (ipv4 (unwrap (read-u32be buffer 4)))
           (flowinfo (unwrap (read-u32be buffer 130)))
           (ipv6 (unwrap (slice buffer 134 16)))
           (scopeid (unwrap (read-u32be buffer 150)))
           (padding (unwrap (slice buffer 154 108)))
           (unknown (unwrap (slice buffer 254 126)))
           (hf-namelen (unwrap (read-u16be buffer 380)))
           (hf-desclen (unwrap (read-u16be buffer 382)))
           (flags (unwrap (read-u32be buffer 384)))
           (hf-naddr (unwrap (read-u16be buffer 388)))
           (name (unwrap (slice buffer 392 1)))
           (desc (unwrap (slice buffer 392 1)))
           (hf-code (unwrap (read-u16be buffer 392)))
           (fields (unwrap (read-u16be buffer 392)))
           (hf-jt (unwrap (read-u8 buffer 394)))
           (hf-jf (unwrap (read-u8 buffer 395)))
           (hf-filtertype (unwrap (read-u16be buffer 400)))
           (hf-nitems (unwrap (read-u32be buffer 404)))
           (slen1 (unwrap (read-u16be buffer 412)))
           (slen2 (unwrap (read-u16be buffer 414)))
           (username (unwrap (slice buffer 416 1)))
           (password (unwrap (slice buffer 416 1)))
           (minvers (unwrap (read-u8 buffer 416)))
           (maxvers (unwrap (read-u8 buffer 417)))
           (request (unwrap (slice buffer 417 1)))
           (hf-tzoff (unwrap (read-u32be buffer 421)))
           (hf-snaplen (unwrap (read-u32be buffer 421)))
           (timeout (unwrap (read-u32be buffer 425)))
           (hf-flags (unwrap (read-u16be buffer 429)))
           (promisc (unwrap (read-u8 buffer 429)))
           (dgram (unwrap (read-u8 buffer 429)))
           (serveropen (unwrap (read-u8 buffer 429)))
           (inbound (unwrap (read-u8 buffer 429)))
           (outbound (unwrap (read-u8 buffer 429)))
           (hf-bufsize (unwrap (read-u32be buffer 433)))
           (port (unwrap (read-u16be buffer 437)))
           (hf-dummy (unwrap (read-u16be buffer 439)))
           (hf-ifrecv (unwrap (read-u32be buffer 439)))
           (hf-ifdrop (unwrap (read-u32be buffer 443)))
           (hf-krnldrop (unwrap (read-u32be buffer 447)))
           (hf-srvcapt (unwrap (read-u32be buffer 451)))
           (dummy1 (unwrap (read-u8 buffer 452)))
           (dummy2 (unwrap (read-u16be buffer 453)))
           (value (unwrap (read-u32be buffer 455)))
           (hf-caplen (unwrap (read-u32be buffer 467)))
           (hf-len (unwrap (read-u32be buffer 471)))
           (hf-npkt (unwrap (read-u32be buffer 475)))
           (hf-error (unwrap (slice buffer 479 1)))
           )

      (ok (list
        (cons 'hf-version (list (cons 'raw hf-version) (cons 'formatted (number->string hf-version))))
        (cons 'hf-value (list (cons 'raw hf-value) (cons 'formatted (number->string hf-value))))
        (cons 'hf-plen (list (cons 'raw hf-plen) (cons 'formatted (number->string hf-plen))))
        (cons 'ipv4 (list (cons 'raw ipv4) (cons 'formatted (fmt-ipv4 ipv4))))
        (cons 'flowinfo (list (cons 'raw flowinfo) (cons 'formatted (fmt-hex flowinfo))))
        (cons 'ipv6 (list (cons 'raw ipv6) (cons 'formatted (fmt-ipv6-address ipv6))))
        (cons 'scopeid (list (cons 'raw scopeid) (cons 'formatted (fmt-hex scopeid))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        (cons 'unknown (list (cons 'raw unknown) (cons 'formatted (fmt-bytes unknown))))
        (cons 'hf-namelen (list (cons 'raw hf-namelen) (cons 'formatted (number->string hf-namelen))))
        (cons 'hf-desclen (list (cons 'raw hf-desclen) (cons 'formatted (number->string hf-desclen))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (number->string flags))))
        (cons 'hf-naddr (list (cons 'raw hf-naddr) (cons 'formatted (number->string hf-naddr))))
        (cons 'name (list (cons 'raw name) (cons 'formatted (utf8->string name))))
        (cons 'desc (list (cons 'raw desc) (cons 'formatted (utf8->string desc))))
        (cons 'hf-code (list (cons 'raw hf-code) (cons 'formatted (fmt-hex hf-code))))
        (cons 'fields (list (cons 'raw fields) (cons 'formatted (fmt-hex fields))))
        (cons 'hf-jt (list (cons 'raw hf-jt) (cons 'formatted (number->string hf-jt))))
        (cons 'hf-jf (list (cons 'raw hf-jf) (cons 'formatted (number->string hf-jf))))
        (cons 'hf-filtertype (list (cons 'raw hf-filtertype) (cons 'formatted (number->string hf-filtertype))))
        (cons 'hf-nitems (list (cons 'raw hf-nitems) (cons 'formatted (number->string hf-nitems))))
        (cons 'slen1 (list (cons 'raw slen1) (cons 'formatted (number->string slen1))))
        (cons 'slen2 (list (cons 'raw slen2) (cons 'formatted (number->string slen2))))
        (cons 'username (list (cons 'raw username) (cons 'formatted (utf8->string username))))
        (cons 'password (list (cons 'raw password) (cons 'formatted (utf8->string password))))
        (cons 'minvers (list (cons 'raw minvers) (cons 'formatted (number->string minvers))))
        (cons 'maxvers (list (cons 'raw maxvers) (cons 'formatted (number->string maxvers))))
        (cons 'request (list (cons 'raw request) (cons 'formatted (utf8->string request))))
        (cons 'hf-tzoff (list (cons 'raw hf-tzoff) (cons 'formatted (number->string hf-tzoff))))
        (cons 'hf-snaplen (list (cons 'raw hf-snaplen) (cons 'formatted (number->string hf-snaplen))))
        (cons 'timeout (list (cons 'raw timeout) (cons 'formatted (number->string timeout))))
        (cons 'hf-flags (list (cons 'raw hf-flags) (cons 'formatted (number->string hf-flags))))
        (cons 'promisc (list (cons 'raw promisc) (cons 'formatted (if (= promisc 0) "False" "True"))))
        (cons 'dgram (list (cons 'raw dgram) (cons 'formatted (if (= dgram 0) "False" "True"))))
        (cons 'serveropen (list (cons 'raw serveropen) (cons 'formatted (if (= serveropen 0) "False" "True"))))
        (cons 'inbound (list (cons 'raw inbound) (cons 'formatted (if (= inbound 0) "False" "True"))))
        (cons 'outbound (list (cons 'raw outbound) (cons 'formatted (if (= outbound 0) "False" "True"))))
        (cons 'hf-bufsize (list (cons 'raw hf-bufsize) (cons 'formatted (number->string hf-bufsize))))
        (cons 'port (list (cons 'raw port) (cons 'formatted (number->string port))))
        (cons 'hf-dummy (list (cons 'raw hf-dummy) (cons 'formatted (number->string hf-dummy))))
        (cons 'hf-ifrecv (list (cons 'raw hf-ifrecv) (cons 'formatted (number->string hf-ifrecv))))
        (cons 'hf-ifdrop (list (cons 'raw hf-ifdrop) (cons 'formatted (number->string hf-ifdrop))))
        (cons 'hf-krnldrop (list (cons 'raw hf-krnldrop) (cons 'formatted (number->string hf-krnldrop))))
        (cons 'hf-srvcapt (list (cons 'raw hf-srvcapt) (cons 'formatted (number->string hf-srvcapt))))
        (cons 'dummy1 (list (cons 'raw dummy1) (cons 'formatted (number->string dummy1))))
        (cons 'dummy2 (list (cons 'raw dummy2) (cons 'formatted (number->string dummy2))))
        (cons 'value (list (cons 'raw value) (cons 'formatted (number->string value))))
        (cons 'hf-caplen (list (cons 'raw hf-caplen) (cons 'formatted (number->string hf-caplen))))
        (cons 'hf-len (list (cons 'raw hf-len) (cons 'formatted (number->string hf-len))))
        (cons 'hf-npkt (list (cons 'raw hf-npkt) (cons 'formatted (number->string hf-npkt))))
        (cons 'hf-error (list (cons 'raw hf-error) (cons 'formatted (utf8->string hf-error))))
        )))

    (catch (e)
      (err (str "RPCAP parse error: " e)))))

;; dissect-rpcap: parse RPCAP from bytevector
;; Returns (ok fields-alist) or (err message)