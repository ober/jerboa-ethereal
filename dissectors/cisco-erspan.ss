;; packet-cisco-erspan.c
;; Routines for the disassembly of Cisco's ERSPAN protocol
;;
;; Copyright 2005 Joerg Mayer (see AUTHORS file)
;; Updates for newer versions by Jason Masker <jason at masker.net>
;; Updates to support ERSPAN3 by Peter Membrey <peter@membrey.hk>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Protocol Spec:
;; https://tools.ietf.org/html/draft-foschiano-erspan-03
;;
;; For ERSPAN packets, the "protocol type" field value in the GRE header
;; is 0x88BE (types I and II) or 0x22EB (type III).
;;
;; For 0x88BE, if the GRE header doesn't have the "sequence number present"
;; flag set, it's type I, with no ERSPAN header, otherwise it has an
;; ERSPAN header (it's supposed to be type II, but we look at the version
;; in the ERSPAN header; should we report an error if it's not version 1?).
;;
;; For 0x22EB, it always has an ERSPAN header (it's supposed to be type III,
;; but we look at the version in the ERSPAN header; should we report an
;; error if it's not version 2?).
;;

;; jerboa-ethereal/dissectors/cisco-erspan.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cisco_erspan.c

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
(def (dissect-cisco-erspan buffer)
  "Encapsulated Remote Switch Packet ANalysis"
  (try
    (let* (
           (reserved (unwrap (read-u32be buffer 4)))
           (index (unwrap (read-u32be buffer 4)))
           (vlan (unwrap (read-u16be buffer 8)))
           (cos (unwrap (read-u16be buffer 10)))
           (spanid (unwrap (read-u16be buffer 10)))
           (timestamp (unwrap (read-u32be buffer 12)))
           (sgt (unwrap (read-u16be buffer 16)))
           (p (unwrap (read-u16be buffer 18)))
           (hw (unwrap (read-u16be buffer 18)))
           (direction (unwrap (read-u8 buffer 18)))
           (o (unwrap (read-u16be buffer 18)))
           (platid (unwrap (read-u32be buffer 20)))
           (pid1-rsvd1 (unwrap (read-u32be buffer 20)))
           (pid1-domain-id (unwrap (read-u32be buffer 20)))
           (pid1-port-index (unwrap (read-u32be buffer 24)))
           (pid3-rsvd1 (unwrap (read-u32be buffer 28)))
           (pid3-port-index (unwrap (read-u32be buffer 28)))
           (pid3-timestamp (unwrap (read-u32be buffer 32)))
           (pid4-rsvd1 (unwrap (read-u32be buffer 36)))
           (pid4-rsvd2 (unwrap (read-u32be buffer 36)))
           (pid4-rsvd3 (unwrap (read-u32be buffer 40)))
           (pid5-switchid (unwrap (read-u32be buffer 44)))
           (pid5-port-index (unwrap (read-u32be buffer 44)))
           (pid5-timestamp (unwrap (read-u32be buffer 48)))
           (pid7-rsvd1 (unwrap (read-u32be buffer 52)))
           (pid7-source-index (unwrap (read-u32be buffer 52)))
           (pid7-timestamp (unwrap (read-u32be buffer 56)))
           (pid-rsvd (unwrap (read-u64be buffer 60)))
           )

      (ok (list
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (number->string reserved))))
        (cons 'index (list (cons 'raw index) (cons 'formatted (number->string index))))
        (cons 'vlan (list (cons 'raw vlan) (cons 'formatted (number->string vlan))))
        (cons 'cos (list (cons 'raw cos) (cons 'formatted (number->string cos))))
        (cons 'spanid (list (cons 'raw spanid) (cons 'formatted (number->string spanid))))
        (cons 'timestamp (list (cons 'raw timestamp) (cons 'formatted (number->string timestamp))))
        (cons 'sgt (list (cons 'raw sgt) (cons 'formatted (number->string sgt))))
        (cons 'p (list (cons 'raw p) (cons 'formatted (number->string p))))
        (cons 'hw (list (cons 'raw hw) (cons 'formatted (number->string hw))))
        (cons 'direction (list (cons 'raw direction) (cons 'formatted (if (= direction 0) "Ingress" "Egress"))))
        (cons 'o (list (cons 'raw o) (cons 'formatted (number->string o))))
        (cons 'platid (list (cons 'raw platid) (cons 'formatted (number->string platid))))
        (cons 'pid1-rsvd1 (list (cons 'raw pid1-rsvd1) (cons 'formatted (number->string pid1-rsvd1))))
        (cons 'pid1-domain-id (list (cons 'raw pid1-domain-id) (cons 'formatted (number->string pid1-domain-id))))
        (cons 'pid1-port-index (list (cons 'raw pid1-port-index) (cons 'formatted (number->string pid1-port-index))))
        (cons 'pid3-rsvd1 (list (cons 'raw pid3-rsvd1) (cons 'formatted (number->string pid3-rsvd1))))
        (cons 'pid3-port-index (list (cons 'raw pid3-port-index) (cons 'formatted (number->string pid3-port-index))))
        (cons 'pid3-timestamp (list (cons 'raw pid3-timestamp) (cons 'formatted (number->string pid3-timestamp))))
        (cons 'pid4-rsvd1 (list (cons 'raw pid4-rsvd1) (cons 'formatted (number->string pid4-rsvd1))))
        (cons 'pid4-rsvd2 (list (cons 'raw pid4-rsvd2) (cons 'formatted (number->string pid4-rsvd2))))
        (cons 'pid4-rsvd3 (list (cons 'raw pid4-rsvd3) (cons 'formatted (number->string pid4-rsvd3))))
        (cons 'pid5-switchid (list (cons 'raw pid5-switchid) (cons 'formatted (number->string pid5-switchid))))
        (cons 'pid5-port-index (list (cons 'raw pid5-port-index) (cons 'formatted (number->string pid5-port-index))))
        (cons 'pid5-timestamp (list (cons 'raw pid5-timestamp) (cons 'formatted (number->string pid5-timestamp))))
        (cons 'pid7-rsvd1 (list (cons 'raw pid7-rsvd1) (cons 'formatted (number->string pid7-rsvd1))))
        (cons 'pid7-source-index (list (cons 'raw pid7-source-index) (cons 'formatted (number->string pid7-source-index))))
        (cons 'pid7-timestamp (list (cons 'raw pid7-timestamp) (cons 'formatted (number->string pid7-timestamp))))
        (cons 'pid-rsvd (list (cons 'raw pid-rsvd) (cons 'formatted (number->string pid-rsvd))))
        )))

    (catch (e)
      (err (str "CISCO-ERSPAN parse error: " e)))))

;; dissect-cisco-erspan: parse CISCO-ERSPAN from bytevector
;; Returns (ok fields-alist) or (err message)