;; Do not modify this file. Changes will be overwritten.

;; jerboa-ethereal/dissectors/ldap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ldap.c
;; RFC 3494

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
(def (dissect-ldap buffer)
  "Lightweight Directory Access Protocol"
  (try
    (let* (
           (oid (unwrap (slice buffer 0 1)))
           (ntver-flags (unwrap (read-u32le buffer 0)))
           (netlogon-flags (unwrap (read-u32le buffer 0)))
           (netlogon-flags-fnc (extract-bits netlogon-flags 0x80000000 31))
           (netlogon-flags-dnc (extract-bits netlogon-flags 0x40000000 30))
           (netlogon-flags-dns (extract-bits netlogon-flags 0x20000000 29))
           (netlogon-flags-wdc (extract-bits netlogon-flags 0x1000 12))
           (netlogon-flags-rodc (extract-bits netlogon-flags 0x800 11))
           (netlogon-flags-ndnc (extract-bits netlogon-flags 0x400 10))
           (netlogon-flags-good-timeserv (extract-bits netlogon-flags 0x200 9))
           (netlogon-flags-writable (extract-bits netlogon-flags 0x100 8))
           (netlogon-flags-closest (extract-bits netlogon-flags 0x80 7))
           (netlogon-flags-timeserv (extract-bits netlogon-flags 0x40 6))
           (netlogon-flags-kdc (extract-bits netlogon-flags 0x20 5))
           (netlogon-flags-ds (extract-bits netlogon-flags 0x10 4))
           (netlogon-flags-ldap (extract-bits netlogon-flags 0x8 3))
           (netlogon-flags-gc (extract-bits netlogon-flags 0x4 2))
           (netlogon-flags-pdc (extract-bits netlogon-flags 0x1 0))
           (nb-hostname-z (unwrap (slice buffer 2 1)))
           (username-z (unwrap (slice buffer 2 1)))
           (nb-domain-z (unwrap (slice buffer 2 1)))
           (netlogon-ipaddress (unwrap (read-u32be buffer 34)))
           (domain-guid (unwrap (slice buffer 40 16)))
           (netlogon-ipaddress-family (unwrap (read-u16be buffer 57)))
           (netlogon-ipaddress-port (unwrap (read-u16be buffer 59)))
           (netlogon-ipaddress-ipv4 (unwrap (read-u32be buffer 61)))
           (netlogon-ipaddress-zero (unwrap (slice buffer 65 8)))
           (netlogon-lm-token (unwrap (read-u16be buffer 73)))
           (netlogon-nt-token (unwrap (read-u16be buffer 75)))
           )

      (ok (list
        (cons 'oid (list (cons 'raw oid) (cons 'formatted (utf8->string oid))))
        (cons 'ntver-flags (list (cons 'raw ntver-flags) (cons 'formatted (fmt-hex ntver-flags))))
        (cons 'netlogon-flags (list (cons 'raw netlogon-flags) (cons 'formatted (fmt-hex netlogon-flags))))
        (cons 'netlogon-flags-fnc (list (cons 'raw netlogon-flags-fnc) (cons 'formatted (if (= netlogon-flags-fnc 0) "The NC is not the default forest NC (Windows 2008)" "The NC is the default forest NC(Windows 2008)"))))
        (cons 'netlogon-flags-dnc (list (cons 'raw netlogon-flags-dnc) (cons 'formatted (if (= netlogon-flags-dnc 0) "The NC is not the default NC (Windows 2008)" "The NC is the default NC (Windows 2008)"))))
        (cons 'netlogon-flags-dns (list (cons 'raw netlogon-flags-dns) (cons 'formatted (if (= netlogon-flags-dns 0) "Server name is not in DNS format (Windows 2008)" "Server name is in DNS format (Windows 2008)"))))
        (cons 'netlogon-flags-wdc (list (cons 'raw netlogon-flags-wdc) (cons 'formatted (if (= netlogon-flags-wdc 0) "Domain controller is not a Windows 2008 writable NC" "Domain controller is a Windows 2008 writable NC"))))
        (cons 'netlogon-flags-rodc (list (cons 'raw netlogon-flags-rodc) (cons 'formatted (if (= netlogon-flags-rodc 0) "Domain controller is not a Windows 2008 RODC" "Domain controller is a Windows 2008 RODC"))))
        (cons 'netlogon-flags-ndnc (list (cons 'raw netlogon-flags-ndnc) (cons 'formatted (if (= netlogon-flags-ndnc 0) "Domain is NOT non-domain nc serviced by ldap server" "Domain is NON-DOMAIN NC serviced by ldap server"))))
        (cons 'netlogon-flags-good-timeserv (list (cons 'raw netlogon-flags-good-timeserv) (cons 'formatted (if (= netlogon-flags-good-timeserv 0) "This dc does NOT have a good time service (i.e. no hardware clock)" "This dc has a GOOD TIME SERVICE (i.e. hardware clock)"))))
        (cons 'netlogon-flags-writable (list (cons 'raw netlogon-flags-writable) (cons 'formatted (if (= netlogon-flags-writable 0) "This dc is NOT writable" "This dc is WRITABLE"))))
        (cons 'netlogon-flags-closest (list (cons 'raw netlogon-flags-closest) (cons 'formatted (if (= netlogon-flags-closest 0) "This server is NOT in the same site as the client" "This server is in the same site as the client"))))
        (cons 'netlogon-flags-timeserv (list (cons 'raw netlogon-flags-timeserv) (cons 'formatted (if (= netlogon-flags-timeserv 0) "This dc is NOT running time services (ntp)" "This dc is running TIME SERVICES (ntp)"))))
        (cons 'netlogon-flags-kdc (list (cons 'raw netlogon-flags-kdc) (cons 'formatted (if (= netlogon-flags-kdc 0) "This is NOT a kdc (kerberos)" "This is a KDC (kerberos)"))))
        (cons 'netlogon-flags-ds (list (cons 'raw netlogon-flags-ds) (cons 'formatted (if (= netlogon-flags-ds 0) "This dc does NOT support ds" "This dc supports DS"))))
        (cons 'netlogon-flags-ldap (list (cons 'raw netlogon-flags-ldap) (cons 'formatted (if (= netlogon-flags-ldap 0) "This is NOT an ldap server" "This is an LDAP server"))))
        (cons 'netlogon-flags-gc (list (cons 'raw netlogon-flags-gc) (cons 'formatted (if (= netlogon-flags-gc 0) "This is NOT a global catalog of forest" "This is a GLOBAL CATALOGUE of forest"))))
        (cons 'netlogon-flags-pdc (list (cons 'raw netlogon-flags-pdc) (cons 'formatted (if (= netlogon-flags-pdc 0) "This is NOT a pdc" "This is a PDC"))))
        (cons 'nb-hostname-z (list (cons 'raw nb-hostname-z) (cons 'formatted (utf8->string nb-hostname-z))))
        (cons 'username-z (list (cons 'raw username-z) (cons 'formatted (utf8->string username-z))))
        (cons 'nb-domain-z (list (cons 'raw nb-domain-z) (cons 'formatted (utf8->string nb-domain-z))))
        (cons 'netlogon-ipaddress (list (cons 'raw netlogon-ipaddress) (cons 'formatted (fmt-ipv4 netlogon-ipaddress))))
        (cons 'domain-guid (list (cons 'raw domain-guid) (cons 'formatted (fmt-bytes domain-guid))))
        (cons 'netlogon-ipaddress-family (list (cons 'raw netlogon-ipaddress-family) (cons 'formatted (number->string netlogon-ipaddress-family))))
        (cons 'netlogon-ipaddress-port (list (cons 'raw netlogon-ipaddress-port) (cons 'formatted (number->string netlogon-ipaddress-port))))
        (cons 'netlogon-ipaddress-ipv4 (list (cons 'raw netlogon-ipaddress-ipv4) (cons 'formatted (fmt-ipv4 netlogon-ipaddress-ipv4))))
        (cons 'netlogon-ipaddress-zero (list (cons 'raw netlogon-ipaddress-zero) (cons 'formatted (fmt-bytes netlogon-ipaddress-zero))))
        (cons 'netlogon-lm-token (list (cons 'raw netlogon-lm-token) (cons 'formatted (fmt-hex netlogon-lm-token))))
        (cons 'netlogon-nt-token (list (cons 'raw netlogon-nt-token) (cons 'formatted (fmt-hex netlogon-nt-token))))
        )))

    (catch (e)
      (err (str "LDAP parse error: " e)))))

;; dissect-ldap: parse LDAP from bytevector
;; Returns (ok fields-alist) or (err message)