;; packet-fcdns.c
;; Routines for FC distributed Name Server (dNS)
;; Copyright 2001, Dinesh G Dutt <ddutt@andiamo.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/fcdns.ss
;; Auto-generated from wireshark/epan/dissectors/packet-fcdns.c

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
(def (dissect-fcdns buffer)
  "Fibre Channel Name Server"
  (try
    (let* (
           (fc4type-fcp (unwrap (read-u8 buffer 0)))
           (fc4type-ip (unwrap (read-u8 buffer 0)))
           (fc4type-llcsnap (unwrap (read-u8 buffer 0)))
           (fc4type-swils (unwrap (read-u8 buffer 0)))
           (fc4type-snmp (unwrap (read-u8 buffer 0)))
           (fc4type-gs3 (unwrap (read-u8 buffer 0)))
           (fc4type-vi (unwrap (read-u8 buffer 0)))
           (vendor (unwrap (read-u8 buffer 0)))
           (maxres-size (unwrap (read-u16be buffer 0)))
           (req-domainscope (unwrap (read-u8 buffer 16)))
           (req-areascope (unwrap (read-u8 buffer 16)))
           (req-ip (unwrap (slice buffer 16 16)))
           (req-spnamelen (unwrap (read-u8 buffer 16)))
           (req-spname (unwrap (slice buffer 16 1)))
           (req-snamelen (unwrap (read-u8 buffer 16)))
           (req-sname (unwrap (slice buffer 16 1)))
           (zone-flags (unwrap (read-u8 buffer 16)))
           (id-length (unwrap (read-u8 buffer 16)))
           (zone-mbrid-uint (unwrap (read-u32be buffer 16)))
           (zone-mbrid (unwrap (slice buffer 16 1)))
           (num-entries (unwrap (read-u32be buffer 16)))
           (zonelen (unwrap (read-u8 buffer 16)))
           (zonenm (unwrap (slice buffer 16 1)))
           (portip (unwrap (read-u32be buffer 16)))
           (sw2-objfmt (unwrap (read-u8 buffer 20)))
           (rply-spnamelen (unwrap (read-u8 buffer 36)))
           (rply-spname (unwrap (slice buffer 36 1)))
           (req-fdesclen (unwrap (read-u8 buffer 52)))
           (req-fdesc (unwrap (slice buffer 52 1)))
           (rply-snamelen (unwrap (read-u8 buffer 300)))
           (rply-sname (unwrap (slice buffer 300 1)))
           (rply-ipa (unwrap (slice buffer 556 8)))
           (rply-ipnode (unwrap (slice buffer 556 16)))
           (rply-ipport (unwrap (slice buffer 556 16)))
           (num-fc4desc (unwrap (read-u8 buffer 644)))
           (rply-fc4desclen (unwrap (read-u8 buffer 644)))
           (rply-fc4desc (unwrap (slice buffer 644 1)))
           (fc4features (unwrap (read-u8 buffer 645)))
           )

      (ok (list
        (cons 'fc4type-fcp (list (cons 'raw fc4type-fcp) (cons 'formatted (if (= fc4type-fcp 0) "False" "True"))))
        (cons 'fc4type-ip (list (cons 'raw fc4type-ip) (cons 'formatted (if (= fc4type-ip 0) "False" "True"))))
        (cons 'fc4type-llcsnap (list (cons 'raw fc4type-llcsnap) (cons 'formatted (if (= fc4type-llcsnap 0) "False" "True"))))
        (cons 'fc4type-swils (list (cons 'raw fc4type-swils) (cons 'formatted (if (= fc4type-swils 0) "False" "True"))))
        (cons 'fc4type-snmp (list (cons 'raw fc4type-snmp) (cons 'formatted (if (= fc4type-snmp 0) "False" "True"))))
        (cons 'fc4type-gs3 (list (cons 'raw fc4type-gs3) (cons 'formatted (if (= fc4type-gs3 0) "False" "True"))))
        (cons 'fc4type-vi (list (cons 'raw fc4type-vi) (cons 'formatted (if (= fc4type-vi 0) "False" "True"))))
        (cons 'vendor (list (cons 'raw vendor) (cons 'formatted (fmt-hex vendor))))
        (cons 'maxres-size (list (cons 'raw maxres-size) (cons 'formatted (number->string maxres-size))))
        (cons 'req-domainscope (list (cons 'raw req-domainscope) (cons 'formatted (fmt-hex req-domainscope))))
        (cons 'req-areascope (list (cons 'raw req-areascope) (cons 'formatted (fmt-hex req-areascope))))
        (cons 'req-ip (list (cons 'raw req-ip) (cons 'formatted (fmt-ipv6-address req-ip))))
        (cons 'req-spnamelen (list (cons 'raw req-spnamelen) (cons 'formatted (number->string req-spnamelen))))
        (cons 'req-spname (list (cons 'raw req-spname) (cons 'formatted (utf8->string req-spname))))
        (cons 'req-snamelen (list (cons 'raw req-snamelen) (cons 'formatted (number->string req-snamelen))))
        (cons 'req-sname (list (cons 'raw req-sname) (cons 'formatted (utf8->string req-sname))))
        (cons 'zone-flags (list (cons 'raw zone-flags) (cons 'formatted (fmt-hex zone-flags))))
        (cons 'id-length (list (cons 'raw id-length) (cons 'formatted (number->string id-length))))
        (cons 'zone-mbrid-uint (list (cons 'raw zone-mbrid-uint) (cons 'formatted (fmt-hex zone-mbrid-uint))))
        (cons 'zone-mbrid (list (cons 'raw zone-mbrid) (cons 'formatted (utf8->string zone-mbrid))))
        (cons 'num-entries (list (cons 'raw num-entries) (cons 'formatted (fmt-hex num-entries))))
        (cons 'zonelen (list (cons 'raw zonelen) (cons 'formatted (number->string zonelen))))
        (cons 'zonenm (list (cons 'raw zonenm) (cons 'formatted (utf8->string zonenm))))
        (cons 'portip (list (cons 'raw portip) (cons 'formatted (fmt-ipv4 portip))))
        (cons 'sw2-objfmt (list (cons 'raw sw2-objfmt) (cons 'formatted (fmt-hex sw2-objfmt))))
        (cons 'rply-spnamelen (list (cons 'raw rply-spnamelen) (cons 'formatted (number->string rply-spnamelen))))
        (cons 'rply-spname (list (cons 'raw rply-spname) (cons 'formatted (utf8->string rply-spname))))
        (cons 'req-fdesclen (list (cons 'raw req-fdesclen) (cons 'formatted (number->string req-fdesclen))))
        (cons 'req-fdesc (list (cons 'raw req-fdesc) (cons 'formatted (utf8->string req-fdesc))))
        (cons 'rply-snamelen (list (cons 'raw rply-snamelen) (cons 'formatted (number->string rply-snamelen))))
        (cons 'rply-sname (list (cons 'raw rply-sname) (cons 'formatted (utf8->string rply-sname))))
        (cons 'rply-ipa (list (cons 'raw rply-ipa) (cons 'formatted (fmt-bytes rply-ipa))))
        (cons 'rply-ipnode (list (cons 'raw rply-ipnode) (cons 'formatted (fmt-ipv6-address rply-ipnode))))
        (cons 'rply-ipport (list (cons 'raw rply-ipport) (cons 'formatted (fmt-ipv6-address rply-ipport))))
        (cons 'num-fc4desc (list (cons 'raw num-fc4desc) (cons 'formatted (number->string num-fc4desc))))
        (cons 'rply-fc4desclen (list (cons 'raw rply-fc4desclen) (cons 'formatted (number->string rply-fc4desclen))))
        (cons 'rply-fc4desc (list (cons 'raw rply-fc4desc) (cons 'formatted (fmt-bytes rply-fc4desc))))
        (cons 'fc4features (list (cons 'raw fc4features) (cons 'formatted (fmt-hex fc4features))))
        )))

    (catch (e)
      (err (str "FCDNS parse error: " e)))))

;; dissect-fcdns: parse FCDNS from bytevector
;; Returns (ok fields-alist) or (err message)