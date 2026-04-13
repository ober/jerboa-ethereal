;; packet-docsis-macmgmt.c
;;
;; Relevant DOCSIS specifications:
;; - DOCSIS MAC and Upper Layer Protocols Interface:
;; - CM-SP-MULPIv4.0: https://www.cablelabs.com/specifications/CM-SP-MULPIv4.0
;; - CM-SP-MULPIv3.1: https://www.cablelabs.com/specifications/CM-SP-MULPIv3.1
;; - CM-SP-MULPIv3.0: https://www.cablelabs.com/specifications/CM-SP-MULPIv3.0
;; - CM-SP-RFIv2.0  : https://www.cablelabs.com/specifications/radio-frequency-interface-specification-2
;; - CM-SP-RFIv1.1  : https://www.cablelabs.com/specifications/radio-frequency-interface-specification
;; - SP-RFI         : https://www.cablelabs.com/specifications/radio-frequency-interface-specification-3
;;
;; - DOCSIS Security (BPKM):
;; - CM-SP-SECv4.0: https://www.cablelabs.com/specifications/CM-SP-SECv4.0
;; - CM-SP-SECv3.1: https://www.cablelabs.com/specifications/CM-SP-SECv3.1
;; - CM-SP-SECv3.0: https://www.cablelabs.com/specifications/CM-SP-SECv3.0
;; - CM-SP-BPI+   : https://www.cablelabs.com/specifications/baseline-privacy-plus-interface-specification
;;
;; Routines for DOCSIS MAC Management Header dissection
;; Routines for Upstream Channel Change dissection
;; Routines for Ranging Message dissection
;; Routines for Registration Message dissection
;; Routines for Baseline Privacy Key Management Message dissection
;; Routines for Dynamic Service Addition Message dissection
;; Routines for Dynamic Service Change Request dissection
;; Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
;;
;; Routines for Type 2 UCD Message dissection
;; Copyright 2015, Adrian Simionov <daniel.simionov@gmail.com>
;; Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
;;
;; Routines for Sync Message dissection
;; Routines for REG-REQ-MP dissection
;; Copyright 2007, Bruno Verstuyft  <bruno.verstuyft@excentis.com>
;;
;; Routines for DOCSIS 3.1 OFDM Channel Descriptor dissection.
;; Routines for DOCSIS 3.1 Downstream Profile Descriptor dissection.
;; Routines for Type 51 UCD - DOCSIS 3.1 only - Message dissection
;; Copyright 2016, Bruno Verstuyft <bruno.verstuyft@excentis.com>
;;
;; Routines for DCC Message dissection
;; Routines for DCD Message dissection
;; Copyright 2004, Darryl Hymel <darryl.hymel[AT]arrisi.com>
;;
;; Routines for Type 29 UCD - DOCSIS 2.0 only - Message dissection
;; Copyright 2015, Adrian Simionov <daniel.simionov@gmail.com>
;; Copyright 2003, Brian Wheeler <brian.wheeler[AT]arrisi.com>
;;
;; Routines for Initial Ranging Request Message dissection
;; Copyright 2003, Brian Wheeler <brian.wheeler[AT]arrisi.com>
;;
;; Routines for Baseline Privacy Key Management Attributes dissection
;; Copyright 2017, Adrian Simionov <daniel.simionov@gmail.com>
;; Copyright 2002, Anand V. Narwani <anand[AT]narwani.org>
;;
;; Routines for MDD Message dissection
;; Copyright 2014, Adrian Simionov <adrian.simionov@arrisi.com>
;; Copyright 2007, Bruno Verstuyft <bruno.verstuyft@excentis.com>
;;
;; Routines for DOCSIS 3.0 Bonded Initial Ranging Request Message dissection.
;; Copyright 2009, Geoffrey Kimball <gekimbal[AT]cisco.com>
;;
;; Routines for Type 35 UCD - DOCSIS 3.0 only - Message dissection
;; Copyright 2015, Adrian Simionov <daniel.simionov@gmail.com>
;;
;; Routines for DOCSIS 3.0 Dynamic Bonding Change Message dissection.
;; Routines for DOCSIS 3.0 DOCSIS Path Verify Message dissection.
;; Routines for DOCSIS 3.0 CM Control Message dissection.
;; Copyright 2010, Guido Reismueller <g.reismueller[AT]avm.de>
;;
;; Routines for DOCSIS 4.0 TLVs dissection
;; Copyright 2023, Andrii Vladyka <andrii.vladyka@harmonicinc.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/docsis-macmgmt.ss
;; Auto-generated from wireshark/epan/dissectors/packet-docsis_macmgmt.c

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
(def (dissect-docsis-macmgmt buffer)
  "DOCSIS MAC Management"
  (try
    (let* (
           (mgt-dst-addr (unwrap (slice buffer 0 6)))
           (dpr-carrier (unwrap (read-u8 buffer 0)))
           (cwt-trans-id (unwrap (read-u8 buffer 0)))
           (rba-tg-id (unwrap (read-u8 buffer 0)))
           (optack-reserved (unwrap (read-u16be buffer 0)))
           (optrsp-reserved (unwrap (read-u16be buffer 0)))
           (optreq-reserved (unwrap (read-u16be buffer 0)))
           (optreq-tlv-data (unwrap (slice buffer 0 1)))
           (optreq-tlv-trigger-definition-data (unwrap (slice buffer 0 1)))
           (optreq-tlv-rxmer-thresh-data (unwrap (slice buffer 0 1)))
           (dpd-tlv-data (unwrap (slice buffer 0 1)))
           (ocd-tlv-data (unwrap (slice buffer 0 1)))
           (emrsp-tlv-data (unwrap (slice buffer 0 1)))
           (regrspmp-sid (unwrap (read-u16be buffer 0)))
           (regreqmp-sid (unwrap (read-u16be buffer 0)))
           (cmctrlreq-tlv-data (unwrap (slice buffer 0 1)))
           (cmstatus-tlv-data (unwrap (slice buffer 0 1)))
           (cmstatus-status-event-tlv-data (unwrap (slice buffer 0 1)))
           (tlv-reassembled (unwrap (slice buffer 0 1)))
           (mdd-ccc (unwrap (read-u8 buffer 0)))
           (dcd-config-ch-cnt (unwrap (read-u8 buffer 0)))
           (intrngreq-sid (unwrap (read-u16be buffer 0)))
           (dccreq-tran-id (unwrap (read-u16be buffer 0)))
           (mgt-tranid (unwrap (read-u16be buffer 0)))
           (regack-sid (unwrap (read-u16be buffer 0)))
           (regrsp-sid (unwrap (read-u16be buffer 0)))
           (regreq-sid (unwrap (read-u16be buffer 0)))
           (rngrsp-sid (unwrap (read-u16be buffer 0)))
           (rngreq-sid (unwrap (read-u16be buffer 0)))
           (rngreq-sid-field-bit14 (unwrap (read-u8 buffer 0)))
           (rngreq-sid-field-bit15 (unwrap (read-u8 buffer 0)))
           (mgt-upstream-chid (unwrap (read-u8 buffer 0)))
           (sync-cmts-timestamp (unwrap (read-u32be buffer 0)))
           (bintrngreq-capflags (unwrap (read-u8 buffer 0)))
           (bintrngreq-mddsgid (unwrap (read-u8 buffer 0)))
           (dpr-dcid (unwrap (read-u8 buffer 1)))
           (cwt-sub-band-id (unwrap (read-u8 buffer 1)))
           (rba-ccc (unwrap (read-u8 buffer 1)))
           (dpd-prof-id (unwrap (read-u8 buffer 1)))
           (ocd-ccc (unwrap (read-u8 buffer 1)))
           (mdd-number-of-fragments (unwrap (read-u8 buffer 1)))
           (dcd-num-of-frag (unwrap (read-u8 buffer 1)))
           (bpkm-ident (unwrap (read-u8 buffer 1)))
           (map-ucd-count (unwrap (read-u8 buffer 1)))
           (ucd-config-ch-cnt (unwrap (read-u8 buffer 1)))
           (rba-dcid (unwrap (read-u8 buffer 2)))
           (dpd-ccc (unwrap (read-u8 buffer 2)))
           (regrspmp-response (unwrap (read-u8 buffer 2)))
           (regreqmp-number-of-fragments (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-unknown (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-map-storage-almost-full-indicator (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-map-storage-overflow-indicator (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-ofdma-profile-failure (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-ofdm-profile-recovery (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-plc-recovery (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-ncp-profile-recovery (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-plc-failure (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-ncp-profile-failure (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-dpd-mismatch (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-prim-ds-change (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-ds-ofdm-profile-failure (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-mac-removal (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-cm-a (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-cm-b (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-rng-s (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-t3-e (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-t4-t (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-qfl-r (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-mdd-r (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-s-o (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-qfl-f (unwrap (read-u8 buffer 2)))
           (cmstatus-e-t-mdd-t (unwrap (read-u8 buffer 2)))
           (dbcreq-number-of-fragments (unwrap (read-u8 buffer 2)))
           (mdd-fragment-sequence-number (unwrap (read-u8 buffer 2)))
           (dcd-frag-sequence-num (unwrap (read-u8 buffer 2)))
           (dsdreq-rsvd (unwrap (read-u16be buffer 2)))
           (bpkm-length (unwrap (read-u16be buffer 2)))
           (map-numie-v5 (unwrap (read-u16be buffer 2)))
           (map-numie (unwrap (read-u8 buffer 2)))
           (ucd-mini-slot-size (unwrap (read-u8 buffer 2)))
           (rba-control-byte-bitmask (unwrap (read-u8 buffer 3)))
           (rba-resource-block-change-bit (extract-bits rba-control-byte-bitmask 0x1 0))
           (rba-expiration-time-valid-bit (extract-bits rba-control-byte-bitmask 0x2 1))
           (rba-control-byte-bitmask-rsvd (extract-bits rba-control-byte-bitmask 0xFC 2))
           (dpr-reserved (unwrap (read-u8 buffer 3)))
           (emrsp-reserved (unwrap (read-u8 buffer 3)))
           (emreq-reserved (unwrap (read-u8 buffer 3)))
           (regrspmp-number-of-fragments (unwrap (read-u8 buffer 3)))
           (regreqmp-fragment-sequence-number (unwrap (read-u8 buffer 3)))
           (dpv-flags (unwrap (read-u8 buffer 3)))
           (dbcreq-fragment-sequence-number (unwrap (read-u8 buffer 3)))
           (mdd-current-channel-dcid (unwrap (read-u8 buffer 3)))
           (dsdrsp-rsvd (unwrap (read-u8 buffer 3)))
           (rngreq-pend-compl (unwrap (read-u8 buffer 3)))
           (map-cat (unwrap (read-u8 buffer 3)))
           (map-rsvd-v5 (unwrap (read-u8 buffer 3)))
           (map-rsvd (unwrap (read-u8 buffer 3)))
           (mgt-down-chid (unwrap (read-u8 buffer 3)))
           (rba-rba-time (unwrap (read-u32be buffer 4)))
           (regrspmp-fragment-sequence-number (unwrap (read-u8 buffer 4)))
           (dpv-us-sf (unwrap (read-u32be buffer 4)))
           (dsdreq-sfid (unwrap (read-u32be buffer 4)))
           (map-alloc-start (unwrap (read-u32be buffer 4)))
           (mgt-src-addr (unwrap (slice buffer 6 6)))
           (rba-rba-expiration-time (unwrap (read-u32be buffer 8)))
           (dpv-n (unwrap (read-u16be buffer 8)))
           (map-ack-time (unwrap (read-u32be buffer 8)))
           (dpv-start (unwrap (read-u8 buffer 10)))
           (dpv-end (unwrap (read-u8 buffer 11)))
           (mgt-msg-len (unwrap (read-u16be buffer 12)))
           (rba-number-of-subbands (unwrap (read-u8 buffer 12)))
           (dpv-ts-start (unwrap (read-u32be buffer 12)))
           (map-rng-start (unwrap (read-u8 buffer 12)))
           (map-rng-end (unwrap (read-u8 buffer 13)))
           (mgt-dsap (unwrap (read-u8 buffer 14)))
           (map-data-start (unwrap (read-u8 buffer 14)))
           (mgt-ssap (unwrap (read-u8 buffer 15)))
           (map-data-end (unwrap (read-u8 buffer 15)))
           (mgt-control (unwrap (read-u8 buffer 16)))
           (dpv-ts-end (unwrap (read-u32be buffer 16)))
           (mgt-version (unwrap (read-u8 buffer 17)))
           (mgt-multipart (unwrap (read-u8 buffer 19)))
           (mgt-multipart-fragment-sequence-number (extract-bits mgt-multipart 0xF 0))
           (mgt-rsvd (unwrap (read-u8 buffer 19)))
           )

      (ok (list
        (cons 'mgt-dst-addr (list (cons 'raw mgt-dst-addr) (cons 'formatted (fmt-mac mgt-dst-addr))))
        (cons 'dpr-carrier (list (cons 'raw dpr-carrier) (cons 'formatted (number->string dpr-carrier))))
        (cons 'cwt-trans-id (list (cons 'raw cwt-trans-id) (cons 'formatted (number->string cwt-trans-id))))
        (cons 'rba-tg-id (list (cons 'raw rba-tg-id) (cons 'formatted (number->string rba-tg-id))))
        (cons 'optack-reserved (list (cons 'raw optack-reserved) (cons 'formatted (number->string optack-reserved))))
        (cons 'optrsp-reserved (list (cons 'raw optrsp-reserved) (cons 'formatted (fmt-hex optrsp-reserved))))
        (cons 'optreq-reserved (list (cons 'raw optreq-reserved) (cons 'formatted (fmt-hex optreq-reserved))))
        (cons 'optreq-tlv-data (list (cons 'raw optreq-tlv-data) (cons 'formatted (fmt-bytes optreq-tlv-data))))
        (cons 'optreq-tlv-trigger-definition-data (list (cons 'raw optreq-tlv-trigger-definition-data) (cons 'formatted (fmt-bytes optreq-tlv-trigger-definition-data))))
        (cons 'optreq-tlv-rxmer-thresh-data (list (cons 'raw optreq-tlv-rxmer-thresh-data) (cons 'formatted (fmt-bytes optreq-tlv-rxmer-thresh-data))))
        (cons 'dpd-tlv-data (list (cons 'raw dpd-tlv-data) (cons 'formatted (fmt-bytes dpd-tlv-data))))
        (cons 'ocd-tlv-data (list (cons 'raw ocd-tlv-data) (cons 'formatted (fmt-bytes ocd-tlv-data))))
        (cons 'emrsp-tlv-data (list (cons 'raw emrsp-tlv-data) (cons 'formatted (fmt-bytes emrsp-tlv-data))))
        (cons 'regrspmp-sid (list (cons 'raw regrspmp-sid) (cons 'formatted (number->string regrspmp-sid))))
        (cons 'regreqmp-sid (list (cons 'raw regreqmp-sid) (cons 'formatted (number->string regreqmp-sid))))
        (cons 'cmctrlreq-tlv-data (list (cons 'raw cmctrlreq-tlv-data) (cons 'formatted (fmt-bytes cmctrlreq-tlv-data))))
        (cons 'cmstatus-tlv-data (list (cons 'raw cmstatus-tlv-data) (cons 'formatted (fmt-bytes cmstatus-tlv-data))))
        (cons 'cmstatus-status-event-tlv-data (list (cons 'raw cmstatus-status-event-tlv-data) (cons 'formatted (fmt-bytes cmstatus-status-event-tlv-data))))
        (cons 'tlv-reassembled (list (cons 'raw tlv-reassembled) (cons 'formatted (fmt-bytes tlv-reassembled))))
        (cons 'mdd-ccc (list (cons 'raw mdd-ccc) (cons 'formatted (number->string mdd-ccc))))
        (cons 'dcd-config-ch-cnt (list (cons 'raw dcd-config-ch-cnt) (cons 'formatted (number->string dcd-config-ch-cnt))))
        (cons 'intrngreq-sid (list (cons 'raw intrngreq-sid) (cons 'formatted (number->string intrngreq-sid))))
        (cons 'dccreq-tran-id (list (cons 'raw dccreq-tran-id) (cons 'formatted (number->string dccreq-tran-id))))
        (cons 'mgt-tranid (list (cons 'raw mgt-tranid) (cons 'formatted (number->string mgt-tranid))))
        (cons 'regack-sid (list (cons 'raw regack-sid) (cons 'formatted (number->string regack-sid))))
        (cons 'regrsp-sid (list (cons 'raw regrsp-sid) (cons 'formatted (number->string regrsp-sid))))
        (cons 'regreq-sid (list (cons 'raw regreq-sid) (cons 'formatted (number->string regreq-sid))))
        (cons 'rngrsp-sid (list (cons 'raw rngrsp-sid) (cons 'formatted (number->string rngrsp-sid))))
        (cons 'rngreq-sid (list (cons 'raw rngreq-sid) (cons 'formatted (number->string rngreq-sid))))
        (cons 'rngreq-sid-field-bit14 (list (cons 'raw rngreq-sid-field-bit14) (cons 'formatted (if (= rngreq-sid-field-bit14 0) "The commanded power level P1.6r_n is not in excess of 6 dB below the value corresponding to the top of the DRW." "The commanded power level P1.6r_n is in excess of 6 dB below the value corresponding to the top of the DRW."))))
        (cons 'rngreq-sid-field-bit15 (list (cons 'raw rngreq-sid-field-bit15) (cons 'formatted (if (= rngreq-sid-field-bit15 0) "The commanded power level P1.6r_n is not higher than the value corresponding to the top of the DRW." "The commanded power level P1.6r_n is higher than the value corresponding to the top of the DRW."))))
        (cons 'mgt-upstream-chid (list (cons 'raw mgt-upstream-chid) (cons 'formatted (number->string mgt-upstream-chid))))
        (cons 'sync-cmts-timestamp (list (cons 'raw sync-cmts-timestamp) (cons 'formatted (number->string sync-cmts-timestamp))))
        (cons 'bintrngreq-capflags (list (cons 'raw bintrngreq-capflags) (cons 'formatted (fmt-hex bintrngreq-capflags))))
        (cons 'bintrngreq-mddsgid (list (cons 'raw bintrngreq-mddsgid) (cons 'formatted (fmt-hex bintrngreq-mddsgid))))
        (cons 'dpr-dcid (list (cons 'raw dpr-dcid) (cons 'formatted (number->string dpr-dcid))))
        (cons 'cwt-sub-band-id (list (cons 'raw cwt-sub-band-id) (cons 'formatted (number->string cwt-sub-band-id))))
        (cons 'rba-ccc (list (cons 'raw rba-ccc) (cons 'formatted (number->string rba-ccc))))
        (cons 'dpd-prof-id (list (cons 'raw dpd-prof-id) (cons 'formatted (number->string dpd-prof-id))))
        (cons 'ocd-ccc (list (cons 'raw ocd-ccc) (cons 'formatted (number->string ocd-ccc))))
        (cons 'mdd-number-of-fragments (list (cons 'raw mdd-number-of-fragments) (cons 'formatted (number->string mdd-number-of-fragments))))
        (cons 'dcd-num-of-frag (list (cons 'raw dcd-num-of-frag) (cons 'formatted (number->string dcd-num-of-frag))))
        (cons 'bpkm-ident (list (cons 'raw bpkm-ident) (cons 'formatted (number->string bpkm-ident))))
        (cons 'map-ucd-count (list (cons 'raw map-ucd-count) (cons 'formatted (number->string map-ucd-count))))
        (cons 'ucd-config-ch-cnt (list (cons 'raw ucd-config-ch-cnt) (cons 'formatted (number->string ucd-config-ch-cnt))))
        (cons 'rba-dcid (list (cons 'raw rba-dcid) (cons 'formatted (number->string rba-dcid))))
        (cons 'dpd-ccc (list (cons 'raw dpd-ccc) (cons 'formatted (number->string dpd-ccc))))
        (cons 'regrspmp-response (list (cons 'raw regrspmp-response) (cons 'formatted (number->string regrspmp-response))))
        (cons 'regreqmp-number-of-fragments (list (cons 'raw regreqmp-number-of-fragments) (cons 'formatted (number->string regreqmp-number-of-fragments))))
        (cons 'cmstatus-e-t-unknown (list (cons 'raw cmstatus-e-t-unknown) (cons 'formatted (number->string cmstatus-e-t-unknown))))
        (cons 'cmstatus-e-t-map-storage-almost-full-indicator (list (cons 'raw cmstatus-e-t-map-storage-almost-full-indicator) (cons 'formatted (number->string cmstatus-e-t-map-storage-almost-full-indicator))))
        (cons 'cmstatus-e-t-map-storage-overflow-indicator (list (cons 'raw cmstatus-e-t-map-storage-overflow-indicator) (cons 'formatted (number->string cmstatus-e-t-map-storage-overflow-indicator))))
        (cons 'cmstatus-e-t-ofdma-profile-failure (list (cons 'raw cmstatus-e-t-ofdma-profile-failure) (cons 'formatted (number->string cmstatus-e-t-ofdma-profile-failure))))
        (cons 'cmstatus-e-t-ofdm-profile-recovery (list (cons 'raw cmstatus-e-t-ofdm-profile-recovery) (cons 'formatted (number->string cmstatus-e-t-ofdm-profile-recovery))))
        (cons 'cmstatus-e-t-plc-recovery (list (cons 'raw cmstatus-e-t-plc-recovery) (cons 'formatted (number->string cmstatus-e-t-plc-recovery))))
        (cons 'cmstatus-e-t-ncp-profile-recovery (list (cons 'raw cmstatus-e-t-ncp-profile-recovery) (cons 'formatted (number->string cmstatus-e-t-ncp-profile-recovery))))
        (cons 'cmstatus-e-t-plc-failure (list (cons 'raw cmstatus-e-t-plc-failure) (cons 'formatted (number->string cmstatus-e-t-plc-failure))))
        (cons 'cmstatus-e-t-ncp-profile-failure (list (cons 'raw cmstatus-e-t-ncp-profile-failure) (cons 'formatted (number->string cmstatus-e-t-ncp-profile-failure))))
        (cons 'cmstatus-e-t-dpd-mismatch (list (cons 'raw cmstatus-e-t-dpd-mismatch) (cons 'formatted (number->string cmstatus-e-t-dpd-mismatch))))
        (cons 'cmstatus-e-t-prim-ds-change (list (cons 'raw cmstatus-e-t-prim-ds-change) (cons 'formatted (number->string cmstatus-e-t-prim-ds-change))))
        (cons 'cmstatus-e-t-ds-ofdm-profile-failure (list (cons 'raw cmstatus-e-t-ds-ofdm-profile-failure) (cons 'formatted (number->string cmstatus-e-t-ds-ofdm-profile-failure))))
        (cons 'cmstatus-e-t-mac-removal (list (cons 'raw cmstatus-e-t-mac-removal) (cons 'formatted (number->string cmstatus-e-t-mac-removal))))
        (cons 'cmstatus-e-t-cm-a (list (cons 'raw cmstatus-e-t-cm-a) (cons 'formatted (number->string cmstatus-e-t-cm-a))))
        (cons 'cmstatus-e-t-cm-b (list (cons 'raw cmstatus-e-t-cm-b) (cons 'formatted (number->string cmstatus-e-t-cm-b))))
        (cons 'cmstatus-e-t-rng-s (list (cons 'raw cmstatus-e-t-rng-s) (cons 'formatted (number->string cmstatus-e-t-rng-s))))
        (cons 'cmstatus-e-t-t3-e (list (cons 'raw cmstatus-e-t-t3-e) (cons 'formatted (number->string cmstatus-e-t-t3-e))))
        (cons 'cmstatus-e-t-t4-t (list (cons 'raw cmstatus-e-t-t4-t) (cons 'formatted (number->string cmstatus-e-t-t4-t))))
        (cons 'cmstatus-e-t-qfl-r (list (cons 'raw cmstatus-e-t-qfl-r) (cons 'formatted (number->string cmstatus-e-t-qfl-r))))
        (cons 'cmstatus-e-t-mdd-r (list (cons 'raw cmstatus-e-t-mdd-r) (cons 'formatted (number->string cmstatus-e-t-mdd-r))))
        (cons 'cmstatus-e-t-s-o (list (cons 'raw cmstatus-e-t-s-o) (cons 'formatted (number->string cmstatus-e-t-s-o))))
        (cons 'cmstatus-e-t-qfl-f (list (cons 'raw cmstatus-e-t-qfl-f) (cons 'formatted (number->string cmstatus-e-t-qfl-f))))
        (cons 'cmstatus-e-t-mdd-t (list (cons 'raw cmstatus-e-t-mdd-t) (cons 'formatted (number->string cmstatus-e-t-mdd-t))))
        (cons 'dbcreq-number-of-fragments (list (cons 'raw dbcreq-number-of-fragments) (cons 'formatted (fmt-hex dbcreq-number-of-fragments))))
        (cons 'mdd-fragment-sequence-number (list (cons 'raw mdd-fragment-sequence-number) (cons 'formatted (number->string mdd-fragment-sequence-number))))
        (cons 'dcd-frag-sequence-num (list (cons 'raw dcd-frag-sequence-num) (cons 'formatted (number->string dcd-frag-sequence-num))))
        (cons 'dsdreq-rsvd (list (cons 'raw dsdreq-rsvd) (cons 'formatted (fmt-hex dsdreq-rsvd))))
        (cons 'bpkm-length (list (cons 'raw bpkm-length) (cons 'formatted (number->string bpkm-length))))
        (cons 'map-numie-v5 (list (cons 'raw map-numie-v5) (cons 'formatted (number->string map-numie-v5))))
        (cons 'map-numie (list (cons 'raw map-numie) (cons 'formatted (number->string map-numie))))
        (cons 'ucd-mini-slot-size (list (cons 'raw ucd-mini-slot-size) (cons 'formatted (number->string ucd-mini-slot-size))))
        (cons 'rba-control-byte-bitmask (list (cons 'raw rba-control-byte-bitmask) (cons 'formatted (fmt-hex rba-control-byte-bitmask))))
        (cons 'rba-resource-block-change-bit (list (cons 'raw rba-resource-block-change-bit) (cons 'formatted (if (= rba-resource-block-change-bit 0) "Not set" "Set"))))
        (cons 'rba-expiration-time-valid-bit (list (cons 'raw rba-expiration-time-valid-bit) (cons 'formatted (if (= rba-expiration-time-valid-bit 0) "Not set" "Set"))))
        (cons 'rba-control-byte-bitmask-rsvd (list (cons 'raw rba-control-byte-bitmask-rsvd) (cons 'formatted (if (= rba-control-byte-bitmask-rsvd 0) "Not set" "Set"))))
        (cons 'dpr-reserved (list (cons 'raw dpr-reserved) (cons 'formatted (fmt-hex dpr-reserved))))
        (cons 'emrsp-reserved (list (cons 'raw emrsp-reserved) (cons 'formatted (fmt-hex emrsp-reserved))))
        (cons 'emreq-reserved (list (cons 'raw emreq-reserved) (cons 'formatted (fmt-hex emreq-reserved))))
        (cons 'regrspmp-number-of-fragments (list (cons 'raw regrspmp-number-of-fragments) (cons 'formatted (number->string regrspmp-number-of-fragments))))
        (cons 'regreqmp-fragment-sequence-number (list (cons 'raw regreqmp-fragment-sequence-number) (cons 'formatted (number->string regreqmp-fragment-sequence-number))))
        (cons 'dpv-flags (list (cons 'raw dpv-flags) (cons 'formatted (number->string dpv-flags))))
        (cons 'dbcreq-fragment-sequence-number (list (cons 'raw dbcreq-fragment-sequence-number) (cons 'formatted (fmt-hex dbcreq-fragment-sequence-number))))
        (cons 'mdd-current-channel-dcid (list (cons 'raw mdd-current-channel-dcid) (cons 'formatted (number->string mdd-current-channel-dcid))))
        (cons 'dsdrsp-rsvd (list (cons 'raw dsdrsp-rsvd) (cons 'formatted (number->string dsdrsp-rsvd))))
        (cons 'rngreq-pend-compl (list (cons 'raw rngreq-pend-compl) (cons 'formatted (number->string rngreq-pend-compl))))
        (cons 'map-cat (list (cons 'raw map-cat) (cons 'formatted (fmt-hex map-cat))))
        (cons 'map-rsvd-v5 (list (cons 'raw map-rsvd-v5) (cons 'formatted (fmt-hex map-rsvd-v5))))
        (cons 'map-rsvd (list (cons 'raw map-rsvd) (cons 'formatted (fmt-hex map-rsvd))))
        (cons 'mgt-down-chid (list (cons 'raw mgt-down-chid) (cons 'formatted (number->string mgt-down-chid))))
        (cons 'rba-rba-time (list (cons 'raw rba-rba-time) (cons 'formatted (fmt-hex rba-rba-time))))
        (cons 'regrspmp-fragment-sequence-number (list (cons 'raw regrspmp-fragment-sequence-number) (cons 'formatted (number->string regrspmp-fragment-sequence-number))))
        (cons 'dpv-us-sf (list (cons 'raw dpv-us-sf) (cons 'formatted (number->string dpv-us-sf))))
        (cons 'dsdreq-sfid (list (cons 'raw dsdreq-sfid) (cons 'formatted (number->string dsdreq-sfid))))
        (cons 'map-alloc-start (list (cons 'raw map-alloc-start) (cons 'formatted (number->string map-alloc-start))))
        (cons 'mgt-src-addr (list (cons 'raw mgt-src-addr) (cons 'formatted (fmt-mac mgt-src-addr))))
        (cons 'rba-rba-expiration-time (list (cons 'raw rba-rba-expiration-time) (cons 'formatted (fmt-hex rba-rba-expiration-time))))
        (cons 'dpv-n (list (cons 'raw dpv-n) (cons 'formatted (number->string dpv-n))))
        (cons 'map-ack-time (list (cons 'raw map-ack-time) (cons 'formatted (number->string map-ack-time))))
        (cons 'dpv-start (list (cons 'raw dpv-start) (cons 'formatted (number->string dpv-start))))
        (cons 'dpv-end (list (cons 'raw dpv-end) (cons 'formatted (number->string dpv-end))))
        (cons 'mgt-msg-len (list (cons 'raw mgt-msg-len) (cons 'formatted (number->string mgt-msg-len))))
        (cons 'rba-number-of-subbands (list (cons 'raw rba-number-of-subbands) (cons 'formatted (number->string rba-number-of-subbands))))
        (cons 'dpv-ts-start (list (cons 'raw dpv-ts-start) (cons 'formatted (number->string dpv-ts-start))))
        (cons 'map-rng-start (list (cons 'raw map-rng-start) (cons 'formatted (number->string map-rng-start))))
        (cons 'map-rng-end (list (cons 'raw map-rng-end) (cons 'formatted (number->string map-rng-end))))
        (cons 'mgt-dsap (list (cons 'raw mgt-dsap) (cons 'formatted (fmt-hex mgt-dsap))))
        (cons 'map-data-start (list (cons 'raw map-data-start) (cons 'formatted (number->string map-data-start))))
        (cons 'mgt-ssap (list (cons 'raw mgt-ssap) (cons 'formatted (fmt-hex mgt-ssap))))
        (cons 'map-data-end (list (cons 'raw map-data-end) (cons 'formatted (number->string map-data-end))))
        (cons 'mgt-control (list (cons 'raw mgt-control) (cons 'formatted (fmt-hex mgt-control))))
        (cons 'dpv-ts-end (list (cons 'raw dpv-ts-end) (cons 'formatted (number->string dpv-ts-end))))
        (cons 'mgt-version (list (cons 'raw mgt-version) (cons 'formatted (number->string mgt-version))))
        (cons 'mgt-multipart (list (cons 'raw mgt-multipart) (cons 'formatted (fmt-hex mgt-multipart))))
        (cons 'mgt-multipart-fragment-sequence-number (list (cons 'raw mgt-multipart-fragment-sequence-number) (cons 'formatted (if (= mgt-multipart-fragment-sequence-number 0) "Not set" "Set"))))
        (cons 'mgt-rsvd (list (cons 'raw mgt-rsvd) (cons 'formatted (number->string mgt-rsvd))))
        )))

    (catch (e)
      (err (str "DOCSIS-MACMGMT parse error: " e)))))

;; dissect-docsis-macmgmt: parse DOCSIS-MACMGMT from bytevector
;; Returns (ok fields-alist) or (err message)