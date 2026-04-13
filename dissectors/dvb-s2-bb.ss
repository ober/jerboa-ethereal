;; packet-dvb-s2-bb.c
;; Routines for DVB Dynamic Mode Adaptation dissection
;; refer to
;; https://web.archive.org/web/20170226064346/http://satlabs.org/pdf/sl_561_Mode_Adaptation_Input_and_Output_Interfaces_for_DVB-S2_Equipment_v1.3.pdf
;;
;; (http://satlabs.org/pdf/sl_561_Mode_Adaptation_Input_and_Output_Interfaces_for_DVB-S2_Equipment_v1.3.pdf
;; is no longer available)
;;
;; Standards:
;; ETSI EN 302 307-1 - Digital Video Broadcasting (DVB) - Framing Structure Part 1: DVB-S2
;; ETSI EN 302 307-2 - Digital Video Broadcasting (DVB) - Framing Structure Part 2: DVB-S2X
;; ETSI TS 102 606-1 - Digital Video Broadcasting (DVB) - Generic Stream Encapsulation (GSE) Part 1: Protocol
;; ETSI TS 102 771 - Digital Video Broadcasting (DVB) - GSE implementation guidelines
;; SatLabs sl_561 - Mode Adaptation Interfaces for DVB-S2 equipment
;; ETSI EN 302 769 - Digital Video Broadcasting (DVB) - Framing Structure DVB-C2
;; ETSI EN 302 755 - Digital Video Broadcasting (DVB) - Framing Structure DVB-T2
;; ETSI EN 301 545 - Digital Video Broadcasting (DVB) - Second Generation DVB Interactive Satellite System (DVB-RCS2)
;; RFC 4326 - Unidirectional Lightweight Encapsulation (ULE) for Transmission of IP Datagrams over an MPEG-2 Transport Stream (TS)
;; IANA registries:
;;
;; Mandatory Extension Headers (or link-dependent type fields) for ULE (Range 0-255 decimal):
;;
;; https://www.iana.org/assignments/ule-next-headers/ule-next-headers.xhtml#ule-next-headers-1
;;
;; and
;;
;; Optional Extension Headers for ULE (Range 256-511 decimal):
;;
;; https://www.iana.org/assignments/ule-next-headers/ule-next-headers.xhtml#ule-next-headers-2
;;
;; Copyright 2012, Tobias Rutz <tobias.rutz@work-microwave.de>
;; Copyright 2013-2020, Thales Alenia Space
;; Copyright 2013-2021, Viveris Technologies <adrien.destugues@opensource.viveris.fr>
;; Copyright 2021, John Thacker <johnthacker@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dvb-s2-bb.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dvb_s2_bb.c
;; RFC 4326

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
(def (dissect-dvb-s2-bb buffer)
  "DVB-S2 Mode Adaptation Header"
  (try
    ;; TODO: no extractable fields found for dvb-s2-bb
    (ok '())

    (catch (e)
      (err (str "DVB-S2-BB parse error: " e)))))

;; dissect-dvb-s2-bb: parse DVB-S2-BB from bytevector
;; Returns (ok fields-alist) or (err message)