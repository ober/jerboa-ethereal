;; packet-bluecom.c
;;
;; Routines and register functions of bluecom dissector
;;
;; Bachmann bluecom Protocol
;; Packet dissector based on Ethernet
;;
;; COPYRIGHT BY BACHMANN ELECTRONIC GmbH 2016
;; Contact: Gerhard Khueny <g.khueny@bachmann.info>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bluecom.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bluecom.c

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
(def (dissect-bluecom buffer)
  "bluecom Protocol"
  (try
    (let* (
           (userdata (unwrap (slice buffer 0 1)))
           (connectreq-lenin (unwrap (read-u16be buffer 0)))
           (searchreq-addrtype (unwrap (read-u32be buffer 0)))
           (identify-error (unwrap (read-u32be buffer 0)))
           (sync-starttime (unwrap (read-u32be buffer 0)))
           (connectreq-lenout (unwrap (read-u16be buffer 2)))
           (connectreq-cycletime (unwrap (read-u32be buffer 4)))
           (searchreq-reserved (unwrap (read-u32be buffer 4)))
           (identify-starttime (unwrap (read-u32be buffer 4)))
           (sync-cycletime (unwrap (read-u32be buffer 4)))
           (connectreq-offlinefactor (unwrap (read-u16be buffer 8)))
           (searchreq-ipaddrfirst (unwrap (read-u32be buffer 8)))
           (searchreq-ipaddrlast (unwrap (read-u32be buffer 8)))
           (searchreq-name (unwrap (slice buffer 8 1)))
           (searchreq-addrdata (unwrap (slice buffer 8 1)))
           (searchrsp-error (unwrap (read-u32be buffer 8)))
           (identify-ipaddr (unwrap (read-u32be buffer 8)))
           (sync-dataratio (unwrap (read-u8 buffer 8)))
           (sync-identify (unwrap (read-u8 buffer 9)))
           (sync-vlantag (unwrap (read-u16be buffer 10)))
           (connectreq-ipaddr (unwrap (read-u32be buffer 12)))
           (searchrsp-starttime (unwrap (read-u32be buffer 12)))
           (identify-name (unwrap (slice buffer 12 1)))
           (identify-ethaddr (unwrap (slice buffer 12 6)))
           (identify-ethaddr2 (unwrap (slice buffer 12 6)))
           (sync-ethaddr (unwrap (slice buffer 12 6)))
           (sync-ethaddr2 (unwrap (slice buffer 12 6)))
           (hdr-sourceid (unwrap (read-u16be buffer 12)))
           (hdr-destid (unwrap (read-u16be buffer 14)))
           (connectreq-name (unwrap (slice buffer 16 1)))
           (connectreq-ethaddr (unwrap (slice buffer 16 6)))
           (connectreq-ethaddr2 (unwrap (slice buffer 16 6)))
           (connectrsp-error (unwrap (read-u32be buffer 16)))
           (searchrsp-lenin (unwrap (read-u16be buffer 16)))
           (hdr-transid (unwrap (read-u16be buffer 16)))
           (searchrsp-lenout (unwrap (read-u16be buffer 18)))
           (hdr-slavestate (unwrap (read-u8 buffer 19)))
           (connectrsp-lenin (unwrap (read-u16be buffer 20)))
           (searchrsp-ipaddr (unwrap (read-u32be buffer 20)))
           (hdr-blockflags (unwrap (read-u8 buffer 20)))
           (connectrsp-lenout (unwrap (read-u16be buffer 22)))
           (searchrsp-name (unwrap (slice buffer 24 1)))
           (searchrsp-ethaddr (unwrap (slice buffer 24 6)))
           (searchrsp-ethaddr2 (unwrap (slice buffer 24 6)))
           (hdr-len (unwrap (read-u16be buffer 24)))
           (hdr-fragoffset (unwrap (read-u16be buffer 26)))
           (hdr-version (unwrap (read-u8 buffer 36)))
           (hdr-format (unwrap (read-u8 buffer 37)))
           (hdr-protflags (unwrap (read-u8 buffer 38)))
           (hdr-blocknb (unwrap (read-u8 buffer 39)))
           (hdr-segcode (unwrap (read-u16be buffer 40)))
           (hdr-auth (unwrap (read-u32be buffer 42)))
           )

      (ok (list
        (cons 'userdata (list (cons 'raw userdata) (cons 'formatted (fmt-bytes userdata))))
        (cons 'connectreq-lenin (list (cons 'raw connectreq-lenin) (cons 'formatted (number->string connectreq-lenin))))
        (cons 'searchreq-addrtype (list (cons 'raw searchreq-addrtype) (cons 'formatted (number->string searchreq-addrtype))))
        (cons 'identify-error (list (cons 'raw identify-error) (cons 'formatted (number->string identify-error))))
        (cons 'sync-starttime (list (cons 'raw sync-starttime) (cons 'formatted (number->string sync-starttime))))
        (cons 'connectreq-lenout (list (cons 'raw connectreq-lenout) (cons 'formatted (number->string connectreq-lenout))))
        (cons 'connectreq-cycletime (list (cons 'raw connectreq-cycletime) (cons 'formatted (number->string connectreq-cycletime))))
        (cons 'searchreq-reserved (list (cons 'raw searchreq-reserved) (cons 'formatted (number->string searchreq-reserved))))
        (cons 'identify-starttime (list (cons 'raw identify-starttime) (cons 'formatted (number->string identify-starttime))))
        (cons 'sync-cycletime (list (cons 'raw sync-cycletime) (cons 'formatted (number->string sync-cycletime))))
        (cons 'connectreq-offlinefactor (list (cons 'raw connectreq-offlinefactor) (cons 'formatted (number->string connectreq-offlinefactor))))
        (cons 'searchreq-ipaddrfirst (list (cons 'raw searchreq-ipaddrfirst) (cons 'formatted (fmt-ipv4 searchreq-ipaddrfirst))))
        (cons 'searchreq-ipaddrlast (list (cons 'raw searchreq-ipaddrlast) (cons 'formatted (fmt-ipv4 searchreq-ipaddrlast))))
        (cons 'searchreq-name (list (cons 'raw searchreq-name) (cons 'formatted (utf8->string searchreq-name))))
        (cons 'searchreq-addrdata (list (cons 'raw searchreq-addrdata) (cons 'formatted (fmt-bytes searchreq-addrdata))))
        (cons 'searchrsp-error (list (cons 'raw searchrsp-error) (cons 'formatted (number->string searchrsp-error))))
        (cons 'identify-ipaddr (list (cons 'raw identify-ipaddr) (cons 'formatted (fmt-ipv4 identify-ipaddr))))
        (cons 'sync-dataratio (list (cons 'raw sync-dataratio) (cons 'formatted (number->string sync-dataratio))))
        (cons 'sync-identify (list (cons 'raw sync-identify) (cons 'formatted (number->string sync-identify))))
        (cons 'sync-vlantag (list (cons 'raw sync-vlantag) (cons 'formatted (number->string sync-vlantag))))
        (cons 'connectreq-ipaddr (list (cons 'raw connectreq-ipaddr) (cons 'formatted (fmt-ipv4 connectreq-ipaddr))))
        (cons 'searchrsp-starttime (list (cons 'raw searchrsp-starttime) (cons 'formatted (number->string searchrsp-starttime))))
        (cons 'identify-name (list (cons 'raw identify-name) (cons 'formatted (utf8->string identify-name))))
        (cons 'identify-ethaddr (list (cons 'raw identify-ethaddr) (cons 'formatted (fmt-mac identify-ethaddr))))
        (cons 'identify-ethaddr2 (list (cons 'raw identify-ethaddr2) (cons 'formatted (fmt-mac identify-ethaddr2))))
        (cons 'sync-ethaddr (list (cons 'raw sync-ethaddr) (cons 'formatted (fmt-mac sync-ethaddr))))
        (cons 'sync-ethaddr2 (list (cons 'raw sync-ethaddr2) (cons 'formatted (fmt-mac sync-ethaddr2))))
        (cons 'hdr-sourceid (list (cons 'raw hdr-sourceid) (cons 'formatted (number->string hdr-sourceid))))
        (cons 'hdr-destid (list (cons 'raw hdr-destid) (cons 'formatted (number->string hdr-destid))))
        (cons 'connectreq-name (list (cons 'raw connectreq-name) (cons 'formatted (utf8->string connectreq-name))))
        (cons 'connectreq-ethaddr (list (cons 'raw connectreq-ethaddr) (cons 'formatted (fmt-mac connectreq-ethaddr))))
        (cons 'connectreq-ethaddr2 (list (cons 'raw connectreq-ethaddr2) (cons 'formatted (fmt-mac connectreq-ethaddr2))))
        (cons 'connectrsp-error (list (cons 'raw connectrsp-error) (cons 'formatted (number->string connectrsp-error))))
        (cons 'searchrsp-lenin (list (cons 'raw searchrsp-lenin) (cons 'formatted (number->string searchrsp-lenin))))
        (cons 'hdr-transid (list (cons 'raw hdr-transid) (cons 'formatted (number->string hdr-transid))))
        (cons 'searchrsp-lenout (list (cons 'raw searchrsp-lenout) (cons 'formatted (number->string searchrsp-lenout))))
        (cons 'hdr-slavestate (list (cons 'raw hdr-slavestate) (cons 'formatted (number->string hdr-slavestate))))
        (cons 'connectrsp-lenin (list (cons 'raw connectrsp-lenin) (cons 'formatted (number->string connectrsp-lenin))))
        (cons 'searchrsp-ipaddr (list (cons 'raw searchrsp-ipaddr) (cons 'formatted (fmt-ipv4 searchrsp-ipaddr))))
        (cons 'hdr-blockflags (list (cons 'raw hdr-blockflags) (cons 'formatted (number->string hdr-blockflags))))
        (cons 'connectrsp-lenout (list (cons 'raw connectrsp-lenout) (cons 'formatted (number->string connectrsp-lenout))))
        (cons 'searchrsp-name (list (cons 'raw searchrsp-name) (cons 'formatted (utf8->string searchrsp-name))))
        (cons 'searchrsp-ethaddr (list (cons 'raw searchrsp-ethaddr) (cons 'formatted (fmt-mac searchrsp-ethaddr))))
        (cons 'searchrsp-ethaddr2 (list (cons 'raw searchrsp-ethaddr2) (cons 'formatted (fmt-mac searchrsp-ethaddr2))))
        (cons 'hdr-len (list (cons 'raw hdr-len) (cons 'formatted (number->string hdr-len))))
        (cons 'hdr-fragoffset (list (cons 'raw hdr-fragoffset) (cons 'formatted (number->string hdr-fragoffset))))
        (cons 'hdr-version (list (cons 'raw hdr-version) (cons 'formatted (number->string hdr-version))))
        (cons 'hdr-format (list (cons 'raw hdr-format) (cons 'formatted (number->string hdr-format))))
        (cons 'hdr-protflags (list (cons 'raw hdr-protflags) (cons 'formatted (number->string hdr-protflags))))
        (cons 'hdr-blocknb (list (cons 'raw hdr-blocknb) (cons 'formatted (number->string hdr-blocknb))))
        (cons 'hdr-segcode (list (cons 'raw hdr-segcode) (cons 'formatted (number->string hdr-segcode))))
        (cons 'hdr-auth (list (cons 'raw hdr-auth) (cons 'formatted (number->string hdr-auth))))
        )))

    (catch (e)
      (err (str "BLUECOM parse error: " e)))))

;; dissect-bluecom: parse BLUECOM from bytevector
;; Returns (ok fields-alist) or (err message)