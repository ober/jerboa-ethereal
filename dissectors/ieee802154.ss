;; packet-ieee802154.c
;;
;; Multipurpose frame support
;; By Devan Lai <devanl@davisinstruments.com>
;; Copyright 2019 Davis Instruments
;;
;; IEEE 802.15.4-2015 CCM* nonce for TSCH mode
;; By Maxime Brunelle <Maxime.Brunelle@trilliant.com>
;; Copyright 2019 Trilliant Inc.
;;
;; IEEE802154 TAP link type
;; By James Ko <jck@exegin.com>
;; Copyright 2019 Exegin Technologies Limited
;;
;; 4-byte FCS support and ACK tracking
;; By Carl Levesque Imbeault <carl.levesque@trilliant.com>
;; Copyright 2018 Trilliant Inc.
;; Integrated and added FCS type enum
;; by James Ko <jck@exegin.com>
;; Copyright 2019 Exegin Technologies Limited
;;
;; Auxiliary Security Header support and
;; option to force TI CC24xx FCS format
;; By Jean-Francois Wauthy <jfw@info.fundp.ac.be>
;; Copyright 2009 The University of Namur, Belgium
;;
;; IEEE 802.15.4 Dissectors for Wireshark
;; By Owen Kirby <osk@exegin.com>
;; Copyright 2007 Exegin Technologies Limited
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;; ------------------------------------------------------------
;;
;; In IEEE 802.15.4 packets, all fields are little endian. And
;; Each byte is transmitted least significant bit first (reflected
;; bit ordering).
;; ------------------------------------------------------------
;;
;; Most IEEE 802.15.4 Packets have the following format:
;; |  FCF  |Seq No|  Addressing |         Data          |   FCS   |
;; |2 bytes|1 byte|0 to 20 bytes|Length-(Overhead) bytes|2/4 Bytes|
;; ------------------------------------------------------------
;;
;; Multipurpose frame packets have the following format:
;; |   FCF   | Seq No  |  Addressing |         Data          |  FCS  |
;; |1/2 bytes|0/1 bytes|0 to 20 bytes|Length-(Overhead) bytes|2 bytes|
;; ------------------------------------------------------------
;;
;; CRC16 is calculated using the x^16 + x^12 + x^5 + 1 polynomial
;; as specified by ITU-T, and is calculated over the IEEE 802.15.4
;; packet (excluding the FCS) as transmitted over the air. Note,
;; that because the least significant bits are transmitted first, this
;; will require reversing the bit-order in each byte. Also, unlike
;; most CRC algorithms, IEEE 802.15.4 uses an initial and final value
;; of 0x0000, instead of 0xffff (which is used by the ITU-T).
;;
;; For a 4-byte FCS, CRC32 is calculated using the ITU-T CRC32.
;;
;; (Fun fact: the reference to "a 32-bit CRC equivalent to ANSI X3.66-1979"
;; in IEEE Std 802.15.4-2015 nonwithstanding, ANSI X3.66-1979 does not
;; describe any 32-bit CRC, only a 16-bit CRC from ITU-T V.41.  ITU-T
;; V.42 describes both a 16-bit and 32-bit CRC; all the 16-bit CRCs
;; floating around seem to use the same generator polynomial,
;; x^16 + x^12 + x^5 + 1, but have different initial conditions and
;; no-error final remainder; the 32-bit CRC from V.42 and the one
;; described in IEEE Std 802.15.4-2015 also use the same generator
;; polynomial.)
;; ------------------------------------------------------------
;;
;; This dissector supports both link-layer IEEE 802.15.4 captures
;; and IEEE 802.15.4 packets encapsulated within other layers.
;; Additionally, support has been provided for 16-bit and 32-bit
;; FCS, as well as for frames with no FCS but with a 16-bit
;; ChipCon/Texas Instruments CC24xx-style metadata field.
;; ------------------------------------------------------------
;;

;; jerboa-ethereal/dissectors/ieee802154.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ieee802154.c

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
(def (dissect-ieee802154 buffer)
  "IEEE 802.15.4 Low-Rate Wireless PAN"
  (try
    (let* (
           (header-ie-tlv (unwrap (read-u16le buffer 0)))
           (psie (unwrap (read-u16le buffer 0)))
           (psie-length-long (extract-bits psie 0x0 0))
           (payload-ie-tlv (unwrap (read-u16le buffer 0)))
           (header-ie-length (extract-bits payload-ie-tlv 0x0 0))
           (cmd-vendor-oui (unwrap (read-u24be buffer 0)))
           (disassoc-reason (unwrap (read-u8 buffer 0)))
           (src64-origin (unwrap (read-u32be buffer 0)))
           (tap-version (unwrap (read-u8 buffer 0)))
           (key-number (unwrap (read-u8 buffer 0)))
           (seqno (unwrap (read-u8 buffer 0)))
           (assoc-addr (unwrap (read-u16be buffer 0)))
           (realign-pan (unwrap (read-u16be buffer 0)))
           (tap-reserved (unwrap (read-u8 buffer 1)))
           (dst-panID (unwrap (read-u16be buffer 1)))
           (hie-time-correction-time-sync-info (unwrap (read-u16le buffer 2)))
           (hie-csl-rendezvous-time (unwrap (read-u16be buffer 2)))
           (hie-csl-phase (unwrap (read-u16be buffer 2)))
           (tsch-timeslot-id (unwrap (read-u8 buffer 2)))
           (tsch-asn (unwrap (slice buffer 2 5)))
           (tsch-hopping-sequence-id (unwrap (read-u8 buffer 2)))
           (tap-length (unwrap (read-u16be buffer 2)))
           (tsch-slotf-link-nb-slotf (unwrap (read-u8 buffer 2)))
           (p-ie-ietf-sub-id (unwrap (read-u8 buffer 2)))
           (6top-version (unwrap (read-u8 buffer 2)))
           (6top-flags-reserved (unwrap (read-u8 buffer 2)))
           (6top-code (unwrap (read-u8 buffer 2)))
           (6top-sfid (unwrap (read-u8 buffer 2)))
           (6top-seqnum (unwrap (read-u8 buffer 2)))
           (hie-vendor-specific-vendor-oui (unwrap (read-u24be buffer 2)))
           (pie-vendor-oui (unwrap (read-u24be buffer 2)))
           (psie-eb-filter (unwrap (read-u8 buffer 2)))
           (psie-eb-filter-pjoin (extract-bits psie-eb-filter 0x0 0))
           (psie-eb-filter-lqi (extract-bits psie-eb-filter 0x0 0))
           (psie-eb-filter-percent (extract-bits psie-eb-filter 0x0 0))
           (psie-eb-filter-attr-id (extract-bits psie-eb-filter 0x0 0))
           (psie-eb-filter-lqi-min (unwrap (read-u8 buffer 2)))
           (psie-eb-filter-percent-prob (unwrap (read-u8 buffer 2)))
           (psie-eb-filter-attr-id-bitmap (unwrap (read-u24be buffer 2)))
           (mpx-transaction-control (unwrap (read-u8 buffer 2)))
           (assoc-status (unwrap (read-u8 buffer 2)))
           (realign-caddr (unwrap (read-u16be buffer 2)))
           (mlme-ie-data (unwrap (slice buffer 3 1)))
           (dst16 (unwrap (read-u16be buffer 3)))
           (tsch-slotf-link-slotf-handle (unwrap (read-u8 buffer 3)))
           (tsch-slotf-size (unwrap (read-u16be buffer 3)))
           (tsch-slotf-link-nb-links (unwrap (read-u8 buffer 3)))
           (hie-rdv-wakeup-interval (unwrap (read-u16be buffer 4)))
           (hie-csl-period (unwrap (read-u16be buffer 4)))
           (ch-num (unwrap (read-u16be buffer 4)))
           (asn (unwrap (read-u64be buffer 4)))
           (tap-lqi (unwrap (read-u8 buffer 4)))
           (chplan-channels (unwrap (read-u16be buffer 4)))
           (tap-tlv-unknown (unwrap (slice buffer 4 1)))
           (tap-tlv-padding (unwrap (slice buffer 4 1)))
           (realign-channel (unwrap (read-u8 buffer 4)))
           (pie-vendor-variable (unwrap (slice buffer 5 1)))
           (realign-addr (unwrap (read-u16be buffer 5)))
           (tsch-join-metric (unwrap (read-u8 buffer 7)))
           (tsch-slotf-link-timeslot (unwrap (read-u16be buffer 7)))
           (tsch-slotf-link-channel-offset (unwrap (read-u16be buffer 7)))
           (tsch-slotf-link-options (unwrap (read-u8 buffer 7)))
           (6top-num-cells (unwrap (read-u8 buffer 7)))
           (realign-channel-page (unwrap (read-u8 buffer 7)))
           (mpx-multiplex-id (unwrap (read-u16be buffer 8)))
           (tsch-timeslot-max-tx (unwrap (read-u24be buffer 10)))
           (mpx-fragment-number (unwrap (read-u8 buffer 10)))
           (mpx-total-frame-size (unwrap (read-u16be buffer 11)))
           (tsch-timeslot-length (unwrap (read-u24be buffer 12)))
           (src-panID (unwrap (read-u16be buffer 13)))
           (6top-reserved (unwrap (read-u8 buffer 14)))
           (6top-offset (unwrap (read-u16be buffer 14)))
           (6top-max-num-cells (unwrap (read-u16be buffer 14)))
           (mpx-kmp-vendor-oui (unwrap (read-u24be buffer 14)))
           (src16 (unwrap (read-u16be buffer 15)))
           (addr16 (unwrap (read-u16be buffer 15)))
           (6top-metadata (unwrap (read-u16be buffer 22)))
           (6top-total-num-cells (unwrap (read-u16be buffer 24)))
           (fcs (unwrap (read-u16be buffer 25)))
           (fcs-ok (unwrap (read-u8 buffer 25)))
           (fcs32 (unwrap (read-u32be buffer 25)))
           (correlation (unwrap (read-u8 buffer 25)))
           (sun-mode (unwrap (read-u8 buffer 25)))
           (tap-phr-bits (unwrap (read-u16be buffer 25)))
           (tap-wisun-ms-phr (unwrap (read-u16le buffer 25)))
           (tap-phr-wisun-fsk-ms-reserved (extract-bits tap-wisun-ms-phr 0x0 0))
           (tap-phr-fsk-ms-checksum (extract-bits tap-wisun-ms-phr 0x0 0))
           (tap-phr-fsk-ms-parity (extract-bits tap-wisun-ms-phr 0x0 0))
           (tap-fsk-ms-phr (unwrap (read-u16le buffer 25)))
           (mpx-transaction-id (extract-bits tap-fsk-ms-phr 0x0 0))
           (tap-phr-fsk (unwrap (read-u16le buffer 25)))
           (tap-phr-fsk-ms (extract-bits tap-phr-fsk 0x0 0))
           (tap-phr-fsk-fcs (extract-bits tap-phr-fsk 0x0 0))
           (tap-phr-fsk-dw (extract-bits tap-phr-fsk 0x0 0))
           (tap-phr-fsk-length (extract-bits tap-phr-fsk 0x0 0))
           (tap-phr-data (unwrap (slice buffer 25 1)))
           (tap-tlv-length (unwrap (read-u16be buffer 25)))
           (6top-payload (unwrap (slice buffer 26 1)))
           (6top-cell (unwrap (slice buffer 38 4)))
           (6top-slot-offset (unwrap (read-u16be buffer 38)))
           (6top-channel-offset (unwrap (read-u16be buffer 38)))
           )

      (ok (list
        (cons 'header-ie-tlv (list (cons 'raw header-ie-tlv) (cons 'formatted (fmt-hex header-ie-tlv))))
        (cons 'psie (list (cons 'raw psie) (cons 'formatted (fmt-hex psie))))
        (cons 'psie-length-long (list (cons 'raw psie-length-long) (cons 'formatted (if (= psie-length-long 0) "Not set" "Set"))))
        (cons 'payload-ie-tlv (list (cons 'raw payload-ie-tlv) (cons 'formatted (fmt-hex payload-ie-tlv))))
        (cons 'header-ie-length (list (cons 'raw header-ie-length) (cons 'formatted (if (= header-ie-length 0) "Not set" "Set"))))
        (cons 'cmd-vendor-oui (list (cons 'raw cmd-vendor-oui) (cons 'formatted (number->string cmd-vendor-oui))))
        (cons 'disassoc-reason (list (cons 'raw disassoc-reason) (cons 'formatted (fmt-hex disassoc-reason))))
        (cons 'src64-origin (list (cons 'raw src64-origin) (cons 'formatted (number->string src64-origin))))
        (cons 'tap-version (list (cons 'raw tap-version) (cons 'formatted (number->string tap-version))))
        (cons 'key-number (list (cons 'raw key-number) (cons 'formatted (number->string key-number))))
        (cons 'seqno (list (cons 'raw seqno) (cons 'formatted (number->string seqno))))
        (cons 'assoc-addr (list (cons 'raw assoc-addr) (cons 'formatted (fmt-hex assoc-addr))))
        (cons 'realign-pan (list (cons 'raw realign-pan) (cons 'formatted (fmt-hex realign-pan))))
        (cons 'tap-reserved (list (cons 'raw tap-reserved) (cons 'formatted (number->string tap-reserved))))
        (cons 'dst-panID (list (cons 'raw dst-panID) (cons 'formatted (fmt-hex dst-panID))))
        (cons 'hie-time-correction-time-sync-info (list (cons 'raw hie-time-correction-time-sync-info) (cons 'formatted (fmt-hex hie-time-correction-time-sync-info))))
        (cons 'hie-csl-rendezvous-time (list (cons 'raw hie-csl-rendezvous-time) (cons 'formatted (number->string hie-csl-rendezvous-time))))
        (cons 'hie-csl-phase (list (cons 'raw hie-csl-phase) (cons 'formatted (number->string hie-csl-phase))))
        (cons 'tsch-timeslot-id (list (cons 'raw tsch-timeslot-id) (cons 'formatted (fmt-hex tsch-timeslot-id))))
        (cons 'tsch-asn (list (cons 'raw tsch-asn) (cons 'formatted (number->string tsch-asn))))
        (cons 'tsch-hopping-sequence-id (list (cons 'raw tsch-hopping-sequence-id) (cons 'formatted (fmt-hex tsch-hopping-sequence-id))))
        (cons 'tap-length (list (cons 'raw tap-length) (cons 'formatted (number->string tap-length))))
        (cons 'tsch-slotf-link-nb-slotf (list (cons 'raw tsch-slotf-link-nb-slotf) (cons 'formatted (number->string tsch-slotf-link-nb-slotf))))
        (cons 'p-ie-ietf-sub-id (list (cons 'raw p-ie-ietf-sub-id) (cons 'formatted (number->string p-ie-ietf-sub-id))))
        (cons '6top-version (list (cons 'raw 6top-version) (cons 'formatted (number->string 6top-version))))
        (cons '6top-flags-reserved (list (cons 'raw 6top-flags-reserved) (cons 'formatted (fmt-hex 6top-flags-reserved))))
        (cons '6top-code (list (cons 'raw 6top-code) (cons 'formatted (fmt-hex 6top-code))))
        (cons '6top-sfid (list (cons 'raw 6top-sfid) (cons 'formatted (fmt-hex 6top-sfid))))
        (cons '6top-seqnum (list (cons 'raw 6top-seqnum) (cons 'formatted (number->string 6top-seqnum))))
        (cons 'hie-vendor-specific-vendor-oui (list (cons 'raw hie-vendor-specific-vendor-oui) (cons 'formatted (number->string hie-vendor-specific-vendor-oui))))
        (cons 'pie-vendor-oui (list (cons 'raw pie-vendor-oui) (cons 'formatted (number->string pie-vendor-oui))))
        (cons 'psie-eb-filter (list (cons 'raw psie-eb-filter) (cons 'formatted (fmt-hex psie-eb-filter))))
        (cons 'psie-eb-filter-pjoin (list (cons 'raw psie-eb-filter-pjoin) (cons 'formatted (if (= psie-eb-filter-pjoin 0) "Not set" "Set"))))
        (cons 'psie-eb-filter-lqi (list (cons 'raw psie-eb-filter-lqi) (cons 'formatted (if (= psie-eb-filter-lqi 0) "Not set" "Set"))))
        (cons 'psie-eb-filter-percent (list (cons 'raw psie-eb-filter-percent) (cons 'formatted (if (= psie-eb-filter-percent 0) "Not set" "Set"))))
        (cons 'psie-eb-filter-attr-id (list (cons 'raw psie-eb-filter-attr-id) (cons 'formatted (if (= psie-eb-filter-attr-id 0) "Not set" "Set"))))
        (cons 'psie-eb-filter-lqi-min (list (cons 'raw psie-eb-filter-lqi-min) (cons 'formatted (number->string psie-eb-filter-lqi-min))))
        (cons 'psie-eb-filter-percent-prob (list (cons 'raw psie-eb-filter-percent-prob) (cons 'formatted (number->string psie-eb-filter-percent-prob))))
        (cons 'psie-eb-filter-attr-id-bitmap (list (cons 'raw psie-eb-filter-attr-id-bitmap) (cons 'formatted (fmt-hex psie-eb-filter-attr-id-bitmap))))
        (cons 'mpx-transaction-control (list (cons 'raw mpx-transaction-control) (cons 'formatted (fmt-hex mpx-transaction-control))))
        (cons 'assoc-status (list (cons 'raw assoc-status) (cons 'formatted (fmt-hex assoc-status))))
        (cons 'realign-caddr (list (cons 'raw realign-caddr) (cons 'formatted (fmt-hex realign-caddr))))
        (cons 'mlme-ie-data (list (cons 'raw mlme-ie-data) (cons 'formatted (fmt-bytes mlme-ie-data))))
        (cons 'dst16 (list (cons 'raw dst16) (cons 'formatted (fmt-hex dst16))))
        (cons 'tsch-slotf-link-slotf-handle (list (cons 'raw tsch-slotf-link-slotf-handle) (cons 'formatted (number->string tsch-slotf-link-slotf-handle))))
        (cons 'tsch-slotf-size (list (cons 'raw tsch-slotf-size) (cons 'formatted (number->string tsch-slotf-size))))
        (cons 'tsch-slotf-link-nb-links (list (cons 'raw tsch-slotf-link-nb-links) (cons 'formatted (number->string tsch-slotf-link-nb-links))))
        (cons 'hie-rdv-wakeup-interval (list (cons 'raw hie-rdv-wakeup-interval) (cons 'formatted (number->string hie-rdv-wakeup-interval))))
        (cons 'hie-csl-period (list (cons 'raw hie-csl-period) (cons 'formatted (number->string hie-csl-period))))
        (cons 'ch-num (list (cons 'raw ch-num) (cons 'formatted (number->string ch-num))))
        (cons 'asn (list (cons 'raw asn) (cons 'formatted (number->string asn))))
        (cons 'tap-lqi (list (cons 'raw tap-lqi) (cons 'formatted (number->string tap-lqi))))
        (cons 'chplan-channels (list (cons 'raw chplan-channels) (cons 'formatted (number->string chplan-channels))))
        (cons 'tap-tlv-unknown (list (cons 'raw tap-tlv-unknown) (cons 'formatted (fmt-bytes tap-tlv-unknown))))
        (cons 'tap-tlv-padding (list (cons 'raw tap-tlv-padding) (cons 'formatted (fmt-bytes tap-tlv-padding))))
        (cons 'realign-channel (list (cons 'raw realign-channel) (cons 'formatted (number->string realign-channel))))
        (cons 'pie-vendor-variable (list (cons 'raw pie-vendor-variable) (cons 'formatted (fmt-bytes pie-vendor-variable))))
        (cons 'realign-addr (list (cons 'raw realign-addr) (cons 'formatted (fmt-hex realign-addr))))
        (cons 'tsch-join-metric (list (cons 'raw tsch-join-metric) (cons 'formatted (number->string tsch-join-metric))))
        (cons 'tsch-slotf-link-timeslot (list (cons 'raw tsch-slotf-link-timeslot) (cons 'formatted (number->string tsch-slotf-link-timeslot))))
        (cons 'tsch-slotf-link-channel-offset (list (cons 'raw tsch-slotf-link-channel-offset) (cons 'formatted (number->string tsch-slotf-link-channel-offset))))
        (cons 'tsch-slotf-link-options (list (cons 'raw tsch-slotf-link-options) (cons 'formatted (fmt-hex tsch-slotf-link-options))))
        (cons '6top-num-cells (list (cons 'raw 6top-num-cells) (cons 'formatted (number->string 6top-num-cells))))
        (cons 'realign-channel-page (list (cons 'raw realign-channel-page) (cons 'formatted (number->string realign-channel-page))))
        (cons 'mpx-multiplex-id (list (cons 'raw mpx-multiplex-id) (cons 'formatted (fmt-hex mpx-multiplex-id))))
        (cons 'tsch-timeslot-max-tx (list (cons 'raw tsch-timeslot-max-tx) (cons 'formatted (number->string tsch-timeslot-max-tx))))
        (cons 'mpx-fragment-number (list (cons 'raw mpx-fragment-number) (cons 'formatted (number->string mpx-fragment-number))))
        (cons 'mpx-total-frame-size (list (cons 'raw mpx-total-frame-size) (cons 'formatted (number->string mpx-total-frame-size))))
        (cons 'tsch-timeslot-length (list (cons 'raw tsch-timeslot-length) (cons 'formatted (number->string tsch-timeslot-length))))
        (cons 'src-panID (list (cons 'raw src-panID) (cons 'formatted (fmt-hex src-panID))))
        (cons '6top-reserved (list (cons 'raw 6top-reserved) (cons 'formatted (fmt-hex 6top-reserved))))
        (cons '6top-offset (list (cons 'raw 6top-offset) (cons 'formatted (number->string 6top-offset))))
        (cons '6top-max-num-cells (list (cons 'raw 6top-max-num-cells) (cons 'formatted (number->string 6top-max-num-cells))))
        (cons 'mpx-kmp-vendor-oui (list (cons 'raw mpx-kmp-vendor-oui) (cons 'formatted (number->string mpx-kmp-vendor-oui))))
        (cons 'src16 (list (cons 'raw src16) (cons 'formatted (fmt-hex src16))))
        (cons 'addr16 (list (cons 'raw addr16) (cons 'formatted (fmt-hex addr16))))
        (cons '6top-metadata (list (cons 'raw 6top-metadata) (cons 'formatted (fmt-hex 6top-metadata))))
        (cons '6top-total-num-cells (list (cons 'raw 6top-total-num-cells) (cons 'formatted (number->string 6top-total-num-cells))))
        (cons 'fcs (list (cons 'raw fcs) (cons 'formatted (fmt-hex fcs))))
        (cons 'fcs-ok (list (cons 'raw fcs-ok) (cons 'formatted (number->string fcs-ok))))
        (cons 'fcs32 (list (cons 'raw fcs32) (cons 'formatted (fmt-hex fcs32))))
        (cons 'correlation (list (cons 'raw correlation) (cons 'formatted (number->string correlation))))
        (cons 'sun-mode (list (cons 'raw sun-mode) (cons 'formatted (number->string sun-mode))))
        (cons 'tap-phr-bits (list (cons 'raw tap-phr-bits) (cons 'formatted (number->string tap-phr-bits))))
        (cons 'tap-wisun-ms-phr (list (cons 'raw tap-wisun-ms-phr) (cons 'formatted (fmt-hex tap-wisun-ms-phr))))
        (cons 'tap-phr-wisun-fsk-ms-reserved (list (cons 'raw tap-phr-wisun-fsk-ms-reserved) (cons 'formatted (if (= tap-phr-wisun-fsk-ms-reserved 0) "Not set" "Set"))))
        (cons 'tap-phr-fsk-ms-checksum (list (cons 'raw tap-phr-fsk-ms-checksum) (cons 'formatted (if (= tap-phr-fsk-ms-checksum 0) "Not set" "Set"))))
        (cons 'tap-phr-fsk-ms-parity (list (cons 'raw tap-phr-fsk-ms-parity) (cons 'formatted (if (= tap-phr-fsk-ms-parity 0) "Not set" "Set"))))
        (cons 'tap-fsk-ms-phr (list (cons 'raw tap-fsk-ms-phr) (cons 'formatted (fmt-hex tap-fsk-ms-phr))))
        (cons 'mpx-transaction-id (list (cons 'raw mpx-transaction-id) (cons 'formatted (if (= mpx-transaction-id 0) "Not set" "Set"))))
        (cons 'tap-phr-fsk (list (cons 'raw tap-phr-fsk) (cons 'formatted (fmt-hex tap-phr-fsk))))
        (cons 'tap-phr-fsk-ms (list (cons 'raw tap-phr-fsk-ms) (cons 'formatted (if (= tap-phr-fsk-ms 0) "Not set" "Set"))))
        (cons 'tap-phr-fsk-fcs (list (cons 'raw tap-phr-fsk-fcs) (cons 'formatted (if (= tap-phr-fsk-fcs 0) "4-octet FCS" "2-octet FCS"))))
        (cons 'tap-phr-fsk-dw (list (cons 'raw tap-phr-fsk-dw) (cons 'formatted (if (= tap-phr-fsk-dw 0) "Not set" "Set"))))
        (cons 'tap-phr-fsk-length (list (cons 'raw tap-phr-fsk-length) (cons 'formatted (if (= tap-phr-fsk-length 0) "Not set" "Set"))))
        (cons 'tap-phr-data (list (cons 'raw tap-phr-data) (cons 'formatted (fmt-bytes tap-phr-data))))
        (cons 'tap-tlv-length (list (cons 'raw tap-tlv-length) (cons 'formatted (number->string tap-tlv-length))))
        (cons '6top-payload (list (cons 'raw 6top-payload) (cons 'formatted (fmt-bytes 6top-payload))))
        (cons '6top-cell (list (cons 'raw 6top-cell) (cons 'formatted (fmt-bytes 6top-cell))))
        (cons '6top-slot-offset (list (cons 'raw 6top-slot-offset) (cons 'formatted (fmt-hex 6top-slot-offset))))
        (cons '6top-channel-offset (list (cons 'raw 6top-channel-offset) (cons 'formatted (fmt-hex 6top-channel-offset))))
        )))

    (catch (e)
      (err (str "IEEE802154 parse error: " e)))))

;; dissect-ieee802154: parse IEEE802154 from bytevector
;; Returns (ok fields-alist) or (err message)