;; packet-msproxy.c
;; Routines for Microsoft Proxy packet dissection
;; Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; This was derived from the dante socks implementation source code.
;; Most of the information came from common.h and msproxy_clientprotocol.c
;;
;; See http://www.inet.no/dante for more information
;;

;; jerboa-ethereal/dissectors/msproxy.ss
;; Auto-generated from wireshark/epan/dissectors/packet-msproxy.c

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
(def (dissect-msproxy buffer)
  "MS Proxy Protocol"
  (try
    (let* (
           (application (unwrap (slice buffer 0 1)))
           (user-name (unwrap (slice buffer 0 1)))
           (application-name (unwrap (slice buffer 0 1)))
           (client-computer-name (unwrap (slice buffer 0 1)))
           (client-id (unwrap (read-u32be buffer 0)))
           (version (unwrap (read-u32be buffer 4)))
           (server-id (unwrap (read-u32be buffer 8)))
           (server-ack (unwrap (read-u8 buffer 12)))
           (client-ack (unwrap (read-u8 buffer 12)))
           (seq-num (unwrap (read-u8 buffer 16)))
           (rwsp-signature (unwrap (slice buffer 24 4)))
           (cmd (unwrap (read-u16be buffer 72)))
           (serverport (unwrap (read-u16be buffer 98)))
           (serveraddr (unwrap (read-u32be buffer 100)))
           (bindaddr (unwrap (read-u32be buffer 200)))
           (bindport (unwrap (read-u16be buffer 204)))
           (ntlmssp-signature (unwrap (slice buffer 376 7)))
           (nt-domain (unwrap (slice buffer 424 255)))
           (boundport (unwrap (read-u16be buffer 463)))
           (server-int-addr (unwrap (read-u32be buffer 580)))
           (req-resolve-length (unwrap (read-u8 buffer 795)))
           (bind-id (unwrap (read-u32be buffer 800)))
           (host-name (unwrap (slice buffer 812 1)))
           (dstport (unwrap (read-u16be buffer 814)))
           (dstaddr (unwrap (read-u32be buffer 816)))
           (server-int-port (unwrap (read-u16be buffer 828)))
           (server-ext-port (unwrap (read-u16be buffer 832)))
           (server-ext-addr (unwrap (read-u32be buffer 834)))
           (address-offset (unwrap (read-u8 buffer 912)))
           (resolvaddr (unwrap (read-u32be buffer 925)))
           (clntport (unwrap (read-u16be buffer 958)))
           )

      (ok (list
        (cons 'application (list (cons 'raw application) (cons 'formatted (utf8->string application))))
        (cons 'user-name (list (cons 'raw user-name) (cons 'formatted (utf8->string user-name))))
        (cons 'application-name (list (cons 'raw application-name) (cons 'formatted (utf8->string application-name))))
        (cons 'client-computer-name (list (cons 'raw client-computer-name) (cons 'formatted (utf8->string client-computer-name))))
        (cons 'client-id (list (cons 'raw client-id) (cons 'formatted (fmt-hex client-id))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (fmt-hex version))))
        (cons 'server-id (list (cons 'raw server-id) (cons 'formatted (fmt-hex server-id))))
        (cons 'server-ack (list (cons 'raw server-ack) (cons 'formatted (number->string server-ack))))
        (cons 'client-ack (list (cons 'raw client-ack) (cons 'formatted (number->string client-ack))))
        (cons 'seq-num (list (cons 'raw seq-num) (cons 'formatted (number->string seq-num))))
        (cons 'rwsp-signature (list (cons 'raw rwsp-signature) (cons 'formatted (utf8->string rwsp-signature))))
        (cons 'cmd (list (cons 'raw cmd) (cons 'formatted (number->string cmd))))
        (cons 'serverport (list (cons 'raw serverport) (cons 'formatted (number->string serverport))))
        (cons 'serveraddr (list (cons 'raw serveraddr) (cons 'formatted (fmt-ipv4 serveraddr))))
        (cons 'bindaddr (list (cons 'raw bindaddr) (cons 'formatted (fmt-ipv4 bindaddr))))
        (cons 'bindport (list (cons 'raw bindport) (cons 'formatted (number->string bindport))))
        (cons 'ntlmssp-signature (list (cons 'raw ntlmssp-signature) (cons 'formatted (utf8->string ntlmssp-signature))))
        (cons 'nt-domain (list (cons 'raw nt-domain) (cons 'formatted (utf8->string nt-domain))))
        (cons 'boundport (list (cons 'raw boundport) (cons 'formatted (number->string boundport))))
        (cons 'server-int-addr (list (cons 'raw server-int-addr) (cons 'formatted (fmt-ipv4 server-int-addr))))
        (cons 'req-resolve-length (list (cons 'raw req-resolve-length) (cons 'formatted (number->string req-resolve-length))))
        (cons 'bind-id (list (cons 'raw bind-id) (cons 'formatted (fmt-hex bind-id))))
        (cons 'host-name (list (cons 'raw host-name) (cons 'formatted (utf8->string host-name))))
        (cons 'dstport (list (cons 'raw dstport) (cons 'formatted (number->string dstport))))
        (cons 'dstaddr (list (cons 'raw dstaddr) (cons 'formatted (fmt-ipv4 dstaddr))))
        (cons 'server-int-port (list (cons 'raw server-int-port) (cons 'formatted (number->string server-int-port))))
        (cons 'server-ext-port (list (cons 'raw server-ext-port) (cons 'formatted (number->string server-ext-port))))
        (cons 'server-ext-addr (list (cons 'raw server-ext-addr) (cons 'formatted (fmt-ipv4 server-ext-addr))))
        (cons 'address-offset (list (cons 'raw address-offset) (cons 'formatted (number->string address-offset))))
        (cons 'resolvaddr (list (cons 'raw resolvaddr) (cons 'formatted (fmt-ipv4 resolvaddr))))
        (cons 'clntport (list (cons 'raw clntport) (cons 'formatted (number->string clntport))))
        )))

    (catch (e)
      (err (str "MSPROXY parse error: " e)))))

;; dissect-msproxy: parse MSPROXY from bytevector
;; Returns (ok fields-alist) or (err message)