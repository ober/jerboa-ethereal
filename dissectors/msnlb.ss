;; packet-msnlb.c
;; Routines for MS NLB dissection
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/msnlb.ss
;; Auto-generated from wireshark/epan/dissectors/packet-msnlb.c

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
(def (dissect-msnlb buffer)
  "MS Network Load Balancing"
  (try
    (let* (
           (uniquehostid (unwrap (read-u32be buffer 8)))
           (clusterip (unwrap (read-u32be buffer 12)))
           (dedicatedip (unwrap (read-u32be buffer 16)))
           (myhostid (unwrap (read-u16be buffer 20)))
           (defaulthostid (unwrap (read-u16be buffer 22)))
           (convergencestate (unwrap (read-u16be buffer 24)))
           (numberofportrules (unwrap (read-u16be buffer 26)))
           (uniquehostcode (unwrap (read-u32be buffer 28)))
           (packetshandled (unwrap (read-u32be buffer 32)))
           (teamingcfg (unwrap (read-u32be buffer 36)))
           (teamingcfg-reserved (unwrap (read-u32be buffer 36)))
           (teamingcfg-xorclusterip (unwrap (read-u32be buffer 36)))
           (teamingcfg-numberofparticipants (unwrap (read-u32be buffer 36)))
           (teamingcfg-hashing (unwrap (read-u8 buffer 36)))
           (teamingcfg-master (unwrap (read-u8 buffer 36)))
           (teamingcfg-active (unwrap (read-u8 buffer 36)))
           (portruleconfiguration-data (unwrap (read-u32be buffer 44)))
           (currentmap-data (unwrap (read-u64be buffer 48)))
           (newmap-data (unwrap (read-u64be buffer 56)))
           (idlemap-data (unwrap (read-u64be buffer 64)))
           (readymap-data (unwrap (read-u64be buffer 72)))
           (loadweights-data (unwrap (read-u32be buffer 80)))
           (reserved2-data (unwrap (read-u32be buffer 84)))
           (length (unwrap (read-u8 buffer 102)))
           (reserved (unwrap (slice buffer 105 4)))
           (host-ipv4 (unwrap (read-u32be buffer 111)))
           (host-ipv6 (unwrap (slice buffer 115 16)))
           (host-unknown (unwrap (slice buffer 131 1)))
           (padding (unwrap (slice buffer 131 1)))
           (extended-hb-unknown (unwrap (slice buffer 131 1)))
           )

      (ok (list
        (cons 'uniquehostid (list (cons 'raw uniquehostid) (cons 'formatted (number->string uniquehostid))))
        (cons 'clusterip (list (cons 'raw clusterip) (cons 'formatted (fmt-ipv4 clusterip))))
        (cons 'dedicatedip (list (cons 'raw dedicatedip) (cons 'formatted (fmt-ipv4 dedicatedip))))
        (cons 'myhostid (list (cons 'raw myhostid) (cons 'formatted (number->string myhostid))))
        (cons 'defaulthostid (list (cons 'raw defaulthostid) (cons 'formatted (number->string defaulthostid))))
        (cons 'convergencestate (list (cons 'raw convergencestate) (cons 'formatted (number->string convergencestate))))
        (cons 'numberofportrules (list (cons 'raw numberofportrules) (cons 'formatted (number->string numberofportrules))))
        (cons 'uniquehostcode (list (cons 'raw uniquehostcode) (cons 'formatted (number->string uniquehostcode))))
        (cons 'packetshandled (list (cons 'raw packetshandled) (cons 'formatted (number->string packetshandled))))
        (cons 'teamingcfg (list (cons 'raw teamingcfg) (cons 'formatted (fmt-hex teamingcfg))))
        (cons 'teamingcfg-reserved (list (cons 'raw teamingcfg-reserved) (cons 'formatted (fmt-hex teamingcfg-reserved))))
        (cons 'teamingcfg-xorclusterip (list (cons 'raw teamingcfg-xorclusterip) (cons 'formatted (fmt-hex teamingcfg-xorclusterip))))
        (cons 'teamingcfg-numberofparticipants (list (cons 'raw teamingcfg-numberofparticipants) (cons 'formatted (fmt-hex teamingcfg-numberofparticipants))))
        (cons 'teamingcfg-hashing (list (cons 'raw teamingcfg-hashing) (cons 'formatted (if (= teamingcfg-hashing 0) "False" "True"))))
        (cons 'teamingcfg-master (list (cons 'raw teamingcfg-master) (cons 'formatted (number->string teamingcfg-master))))
        (cons 'teamingcfg-active (list (cons 'raw teamingcfg-active) (cons 'formatted (number->string teamingcfg-active))))
        (cons 'portruleconfiguration-data (list (cons 'raw portruleconfiguration-data) (cons 'formatted (number->string portruleconfiguration-data))))
        (cons 'currentmap-data (list (cons 'raw currentmap-data) (cons 'formatted (number->string currentmap-data))))
        (cons 'newmap-data (list (cons 'raw newmap-data) (cons 'formatted (number->string newmap-data))))
        (cons 'idlemap-data (list (cons 'raw idlemap-data) (cons 'formatted (number->string idlemap-data))))
        (cons 'readymap-data (list (cons 'raw readymap-data) (cons 'formatted (number->string readymap-data))))
        (cons 'loadweights-data (list (cons 'raw loadweights-data) (cons 'formatted (number->string loadweights-data))))
        (cons 'reserved2-data (list (cons 'raw reserved2-data) (cons 'formatted (number->string reserved2-data))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'host-ipv4 (list (cons 'raw host-ipv4) (cons 'formatted (fmt-ipv4 host-ipv4))))
        (cons 'host-ipv6 (list (cons 'raw host-ipv6) (cons 'formatted (fmt-ipv6-address host-ipv6))))
        (cons 'host-unknown (list (cons 'raw host-unknown) (cons 'formatted (fmt-bytes host-unknown))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        (cons 'extended-hb-unknown (list (cons 'raw extended-hb-unknown) (cons 'formatted (fmt-bytes extended-hb-unknown))))
        )))

    (catch (e)
      (err (str "MSNLB parse error: " e)))))

;; dissect-msnlb: parse MSNLB from bytevector
;; Returns (ok fields-alist) or (err message)