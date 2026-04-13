;; packet-ns-mep.c
;; Routines for netscaler GSLB metric exchange protocol dissection
;; Copyright 2006, Ravi Kondamuru <Ravi.Kondamuru@citrix.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ns-mep.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ns_mep.c

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
(def (dissect-ns-mep buffer)
  "NetScaler Metric Exchange Protocol"
  (try
    (let* (
           (majver (unwrap (read-u8 buffer 0)))
           (minver (unwrap (read-u8 buffer 1)))
           (msglen (unwrap (read-u16be buffer 4)))
           (mfu-reqflag (unwrap (read-u8 buffer 38)))
           (adv-ip (unwrap (read-u32be buffer 42)))
           (mfu-mepflag (unwrap (read-u8 buffer 55)))
           (currentOpenConn (unwrap (read-u32be buffer 62)))
           (currentSurgeCount (unwrap (read-u32be buffer 66)))
           (currentIOHCount (unwrap (read-u32be buffer 70)))
           (currentReusePool (unwrap (read-u32be buffer 74)))
           (currentServerConn (unwrap (read-u32be buffer 78)))
           (currentClientConn (unwrap (read-u32be buffer 82)))
           (TotalReq (unwrap (read-u64be buffer 86)))
           (TotalReqBytes (unwrap (read-u64be buffer 94)))
           (TotalResp (unwrap (read-u64be buffer 102)))
           (TotalRespBytes (unwrap (read-u64be buffer 110)))
           (hops (unwrap (read-u8 buffer 124)))
           (ldns-ip (unwrap (read-u32be buffer 126)))
           (persistenceGslbServIp (unwrap (read-u32be buffer 130)))
           (persistenceGslbServPort (unwrap (read-u16be buffer 134)))
           (persistenceId (unwrap (read-u16be buffer 136)))
           (gslbServPreflen (unwrap (read-u8 buffer 147)))
           (gslbCookieDomNamelen (unwrap (read-u8 buffer 148)))
           (gslbCookieTimeout (unwrap (read-u32be buffer 150)))
           (gslbVidlen (unwrap (read-u32be buffer 154)))
           (gslbFlags (unwrap (read-u8 buffer 158)))
           (gslbCookieDomName (unwrap (slice buffer 161 1)))
           (gslbVs (unwrap (slice buffer 161 1)))
           (gslbPrefix (unwrap (slice buffer 161 1)))
           (mfu-ip (unwrap (read-u32be buffer 187)))
           (mfu-port (unwrap (read-u16be buffer 191)))
           (gslbDomNamelen (unwrap (read-u8 buffer 195)))
           (siteDomTTL (unwrap (read-u32be buffer 196)))
           (gslbDomName (unwrap (slice buffer 200 1)))
           )

      (ok (list
        (cons 'majver (list (cons 'raw majver) (cons 'formatted (number->string majver))))
        (cons 'minver (list (cons 'raw minver) (cons 'formatted (number->string minver))))
        (cons 'msglen (list (cons 'raw msglen) (cons 'formatted (number->string msglen))))
        (cons 'mfu-reqflag (list (cons 'raw mfu-reqflag) (cons 'formatted (fmt-hex mfu-reqflag))))
        (cons 'adv-ip (list (cons 'raw adv-ip) (cons 'formatted (fmt-ipv4 adv-ip))))
        (cons 'mfu-mepflag (list (cons 'raw mfu-mepflag) (cons 'formatted (fmt-hex mfu-mepflag))))
        (cons 'currentOpenConn (list (cons 'raw currentOpenConn) (cons 'formatted (number->string currentOpenConn))))
        (cons 'currentSurgeCount (list (cons 'raw currentSurgeCount) (cons 'formatted (number->string currentSurgeCount))))
        (cons 'currentIOHCount (list (cons 'raw currentIOHCount) (cons 'formatted (number->string currentIOHCount))))
        (cons 'currentReusePool (list (cons 'raw currentReusePool) (cons 'formatted (number->string currentReusePool))))
        (cons 'currentServerConn (list (cons 'raw currentServerConn) (cons 'formatted (number->string currentServerConn))))
        (cons 'currentClientConn (list (cons 'raw currentClientConn) (cons 'formatted (number->string currentClientConn))))
        (cons 'TotalReq (list (cons 'raw TotalReq) (cons 'formatted (number->string TotalReq))))
        (cons 'TotalReqBytes (list (cons 'raw TotalReqBytes) (cons 'formatted (number->string TotalReqBytes))))
        (cons 'TotalResp (list (cons 'raw TotalResp) (cons 'formatted (number->string TotalResp))))
        (cons 'TotalRespBytes (list (cons 'raw TotalRespBytes) (cons 'formatted (number->string TotalRespBytes))))
        (cons 'hops (list (cons 'raw hops) (cons 'formatted (number->string hops))))
        (cons 'ldns-ip (list (cons 'raw ldns-ip) (cons 'formatted (fmt-ipv4 ldns-ip))))
        (cons 'persistenceGslbServIp (list (cons 'raw persistenceGslbServIp) (cons 'formatted (fmt-ipv4 persistenceGslbServIp))))
        (cons 'persistenceGslbServPort (list (cons 'raw persistenceGslbServPort) (cons 'formatted (number->string persistenceGslbServPort))))
        (cons 'persistenceId (list (cons 'raw persistenceId) (cons 'formatted (number->string persistenceId))))
        (cons 'gslbServPreflen (list (cons 'raw gslbServPreflen) (cons 'formatted (number->string gslbServPreflen))))
        (cons 'gslbCookieDomNamelen (list (cons 'raw gslbCookieDomNamelen) (cons 'formatted (number->string gslbCookieDomNamelen))))
        (cons 'gslbCookieTimeout (list (cons 'raw gslbCookieTimeout) (cons 'formatted (number->string gslbCookieTimeout))))
        (cons 'gslbVidlen (list (cons 'raw gslbVidlen) (cons 'formatted (number->string gslbVidlen))))
        (cons 'gslbFlags (list (cons 'raw gslbFlags) (cons 'formatted (fmt-hex gslbFlags))))
        (cons 'gslbCookieDomName (list (cons 'raw gslbCookieDomName) (cons 'formatted (utf8->string gslbCookieDomName))))
        (cons 'gslbVs (list (cons 'raw gslbVs) (cons 'formatted (utf8->string gslbVs))))
        (cons 'gslbPrefix (list (cons 'raw gslbPrefix) (cons 'formatted (utf8->string gslbPrefix))))
        (cons 'mfu-ip (list (cons 'raw mfu-ip) (cons 'formatted (fmt-ipv4 mfu-ip))))
        (cons 'mfu-port (list (cons 'raw mfu-port) (cons 'formatted (number->string mfu-port))))
        (cons 'gslbDomNamelen (list (cons 'raw gslbDomNamelen) (cons 'formatted (number->string gslbDomNamelen))))
        (cons 'siteDomTTL (list (cons 'raw siteDomTTL) (cons 'formatted (number->string siteDomTTL))))
        (cons 'gslbDomName (list (cons 'raw gslbDomName) (cons 'formatted (utf8->string gslbDomName))))
        )))

    (catch (e)
      (err (str "NS-MEP parse error: " e)))))

;; dissect-ns-mep: parse NS-MEP from bytevector
;; Returns (ok fields-alist) or (err message)