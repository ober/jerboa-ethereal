;; packet-dvmrp.c   2001 Ronnie Sahlberg <See AUTHORS for email>
;; Routines for IGMP/DVMRP packet disassembly
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dvmrp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dvmrp.c
;; RFC 1075

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
(def (dissect-dvmrp buffer)
  "Distance Vector Multicast Routing Protocol"
  (try
    (let* (
           (hf-version (unwrap (read-u8 buffer 0)))
           (hf-reserved (unwrap (read-u16be buffer 12)))
           (hf-capabilities (unwrap (read-u8 buffer 13)))
           (netmask (extract-bits hf-capabilities 0x0 0))
           (snmp (extract-bits hf-capabilities 0x0 0))
           (mtrace (extract-bits hf-capabilities 0x0 0))
           (genid (extract-bits hf-capabilities 0x0 0))
           (prune (extract-bits hf-capabilities 0x0 0))
           (ver (unwrap (read-u8 buffer 15)))
           (hf-genid (unwrap (read-u32be buffer 16)))
           (hf-life (unwrap (read-u32be buffer 32)))
           (hf-saddr (unwrap (read-u32be buffer 52)))
           (hf-local (unwrap (read-u32be buffer 64)))
           (hf-threshold (unwrap (read-u8 buffer 69)))
           (tunnel (unwrap (read-u8 buffer 70)))
           (srcroute (unwrap (read-u8 buffer 70)))
           (down (unwrap (read-u8 buffer 70)))
           (disabled (unwrap (read-u8 buffer 70)))
           (querier (unwrap (read-u8 buffer 70)))
           (leaf (unwrap (read-u8 buffer 70)))
           (hf-ncount (unwrap (read-u8 buffer 71)))
           (hf-neighbor (unwrap (read-u32be buffer 72)))
           (hf-netmask (unwrap (read-u32be buffer 84)))
           (hf-metric (unwrap (read-u8 buffer 88)))
           (unr (unwrap (read-u8 buffer 89)))
           (horiz (unwrap (read-u8 buffer 89)))
           (hf-infinity (unwrap (read-u8 buffer 90)))
           (hf-daddr (unwrap (read-u32be buffer 92)))
           (hf-hold (unwrap (read-u32be buffer 101)))
           (hf-count (unwrap (read-u8 buffer 105)))
           (hf-maddr (unwrap (read-u32be buffer 106)))
           )

      (ok (list
        (cons 'hf-version (list (cons 'raw hf-version) (cons 'formatted (number->string hf-version))))
        (cons 'hf-reserved (list (cons 'raw hf-reserved) (cons 'formatted (fmt-hex hf-reserved))))
        (cons 'hf-capabilities (list (cons 'raw hf-capabilities) (cons 'formatted (fmt-hex hf-capabilities))))
        (cons 'netmask (list (cons 'raw netmask) (cons 'formatted (if (= netmask 0) "NOT Netmask capable" "Netmask capable"))))
        (cons 'snmp (list (cons 'raw snmp) (cons 'formatted (if (= snmp 0) "NOT SNMP capable" "SNMP capable"))))
        (cons 'mtrace (list (cons 'raw mtrace) (cons 'formatted (if (= mtrace 0) "NOT Multicast Traceroute capable" "Multicast Traceroute capable"))))
        (cons 'genid (list (cons 'raw genid) (cons 'formatted (if (= genid 0) "NOT Genid capable" "Genid capable"))))
        (cons 'prune (list (cons 'raw prune) (cons 'formatted (if (= prune 0) "NOT Prune capable" "Prune capable"))))
        (cons 'ver (list (cons 'raw ver) (cons 'formatted (fmt-hex ver))))
        (cons 'hf-genid (list (cons 'raw hf-genid) (cons 'formatted (number->string hf-genid))))
        (cons 'hf-life (list (cons 'raw hf-life) (cons 'formatted (number->string hf-life))))
        (cons 'hf-saddr (list (cons 'raw hf-saddr) (cons 'formatted (fmt-ipv4 hf-saddr))))
        (cons 'hf-local (list (cons 'raw hf-local) (cons 'formatted (fmt-ipv4 hf-local))))
        (cons 'hf-threshold (list (cons 'raw hf-threshold) (cons 'formatted (number->string hf-threshold))))
        (cons 'tunnel (list (cons 'raw tunnel) (cons 'formatted (number->string tunnel))))
        (cons 'srcroute (list (cons 'raw srcroute) (cons 'formatted (number->string srcroute))))
        (cons 'down (list (cons 'raw down) (cons 'formatted (number->string down))))
        (cons 'disabled (list (cons 'raw disabled) (cons 'formatted (number->string disabled))))
        (cons 'querier (list (cons 'raw querier) (cons 'formatted (number->string querier))))
        (cons 'leaf (list (cons 'raw leaf) (cons 'formatted (number->string leaf))))
        (cons 'hf-ncount (list (cons 'raw hf-ncount) (cons 'formatted (number->string hf-ncount))))
        (cons 'hf-neighbor (list (cons 'raw hf-neighbor) (cons 'formatted (fmt-ipv4 hf-neighbor))))
        (cons 'hf-netmask (list (cons 'raw hf-netmask) (cons 'formatted (fmt-ipv4 hf-netmask))))
        (cons 'hf-metric (list (cons 'raw hf-metric) (cons 'formatted (number->string hf-metric))))
        (cons 'unr (list (cons 'raw unr) (cons 'formatted (if (= unr 0) "NOT Destination Unreachable" "Destination Unreachable"))))
        (cons 'horiz (list (cons 'raw horiz) (cons 'formatted (if (= horiz 0) "NOT Split Horizon concealed route" "Split Horizon concealed route"))))
        (cons 'hf-infinity (list (cons 'raw hf-infinity) (cons 'formatted (number->string hf-infinity))))
        (cons 'hf-daddr (list (cons 'raw hf-daddr) (cons 'formatted (fmt-ipv4 hf-daddr))))
        (cons 'hf-hold (list (cons 'raw hf-hold) (cons 'formatted (number->string hf-hold))))
        (cons 'hf-count (list (cons 'raw hf-count) (cons 'formatted (fmt-hex hf-count))))
        (cons 'hf-maddr (list (cons 'raw hf-maddr) (cons 'formatted (fmt-ipv4 hf-maddr))))
        )))

    (catch (e)
      (err (str "DVMRP parse error: " e)))))

;; dissect-dvmrp: parse DVMRP from bytevector
;; Returns (ok fields-alist) or (err message)