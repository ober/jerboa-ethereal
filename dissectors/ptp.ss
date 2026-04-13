;; packet-ptp.c
;; Routines for PTP (Precision Time Protocol) dissection
;; Copyright 2004, Auges Tchouante <tchouante2001@yahoo.fr>
;; Copyright 2004, Dominic Bechaz <bdo@zhwin.ch> , ZHW/InES
;; Copyright 2004, Markus Seehofer <mseehofe@nt.hirschmann.de>
;; Copyright 2006, Christian Schaer <scc@zhwin.ch>
;; Copyright 2007, Markus Renz <Markus.Renz@hirschmann.de>
;; Copyright 2010, Torrey Atcitty <torrey.atcitty@harman.com>
;; Dave Olsen <dave.olsen@harman.com>
;; Copyright 2013, Andreas Bachmann <bacr@zhaw.ch>, ZHAW/InES
;; Copyright 2016, Uli Heilmeier <uh@heilmeier.eu>
;; Copyright 2017, Adam Wujek <adam.wujek@cern.ch>
;; Copyright 2022, Dr. Lars Völker <lars.voelker@technica-engineering.de>
;; Copyright 2023, Adam Wujek <dev_public@wujek.eu> for CERN
;; Copyright 2024, Patrik Thunström <patrik.thunstroem@technica-engineering.de>
;; Copyright 2024, Dr. Lars Völker <lars.voelker@technica-engineering.de>
;; Copyright 2024, Martin Ostertag <martin.ostertag@zhaw.ch>
;; Aurel Hess <hesu@zhaw.ch>
;; Copyright 2025, Alex Gebhard <alexander.gebhard@marquette.edu>
;; Copyright 2025, Prashant Tripathi <prashant.tripathi@selinc.com>
;; Copyright 2025, Martin Mayer <martin.mayer@m2-it-solutions.de>
;;
;; Revisions:
;; - Markus Seehofer 09.08.2005 <mseehofe@nt.hirschmann.de>
;; - Included the "startingBoundaryHops" field in
;; ptp_management messages.
;; - Christian Schaer 07.07.2006 <scc@zhwin.ch>
;; - Added support for PTP version 2
;; - Markus Renz 2007-06-01
;; - updated support for PTPv2
;; - Markus Renz added Management for PTPv2, update to Draft 2.2
;; - Torrey Atcitty & Dave Olsen 05.14.2010
;; - Added support for 802.1AS D7.0
;; - Andreas Bachmann 08.07.2013 <bacr@zhaw.ch>
;; - allow multiple TLVs
;; - bugfix in logInterMessagePeriod uint8_t -> int8_t
;; - Uli Heilmeier 21.03.2016 <uh@heilmeier.eu>
;; - Added support for SMPTE TLV
;; - Adam Wujek 17.10.2017 <adam.wujek@cern.ch>
;; - Added support for White Rabbit TLV
;; - Prashant Tripathi 19-02-2021 <prashant_tripathi@selinc.com>
;; - Added support for C37.238-2017
;; - Dr. Lars Völker 05-01-2022 <lars.voelker@technica-engineering.de>
;; - Added analysis support
;; - Adam Wujek 28.08.2023 <dev_public@wujek.eu>
;; - Added support for L1Sync
;; - Patrik Thunström 27.01.2024 <patrik.thunstroem@technica-engineering.de>
;; - Improvements/corrections for cumulativeScaledRateOffset
;; - Prashant Tripathi 31-07-2024 <prashant_tripathi@selinc.com>
;; - Corrections to timeOfNextJump field in ATOI TLV
;; - Patrik Thunström 24.09.2024 <patrik.thunstroem@technica-engineering.de>
;; - Fix analysis association (Sync to Follow_Up etc.) in case of sequenceId resets
;; - Dr. Lars Völker 28.11.2024 <lars.voelker@technica-engineering.de>
;; - TLV rework
;; - Martin Ostertag & Aurel Hess 09-12-2024 <martin.ostertag@zhaw.ch> & <hesu@zhaw.ch>
;; - Added support for drift_tracking TLV (802.1ASdm)
;; - Alex Gebhard 04-09-2025 <alexander.gebhard@marquette.edu>
;; - Added support for authentication TLV
;; - Erez Geva 30-04-2025 <ErezGeva2@gmail.com>
;; - Fix wrong PTPv2 Management IDs
;; - Add missing PTPv2 Management TLVs dissection
;; - Prashant Tripathi 23-10-2025 <prashant_tripathi@selinc.com>
;; - Fix the parsing of organizationSubType field in C37_238 2017 TLV
;; - Martin Mayer 06.12.2025 <martin.mayer@m2-it-solutions.de>
;; - NTP-over-PTP
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ptp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ptp.c

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
(def (dissect-ptp buffer)
  "Precision Time Protocol (IEEE1588)"
  (try
    (let* (
           (v2-mm-data (unwrap (slice buffer 2 1)))
           (v2-mm-clockType (unwrap (read-u16be buffer 2)))
           (v2-mm-clockType-ordinaryClock (unwrap (read-u8 buffer 2)))
           (v2-mm-clockType-boundaryClock (unwrap (read-u8 buffer 2)))
           (v2-mm-clockType-p2p-transparentClock (unwrap (read-u8 buffer 2)))
           (v2-mm-clockType-e2e-transparentClock (unwrap (read-u8 buffer 2)))
           (v2-mm-clockType-managementNode (unwrap (read-u8 buffer 2)))
           (v2-mm-clockType-reserved (unwrap (read-u8 buffer 2)))
           (v2-mm-physicalAddressLength (unwrap (read-u16be buffer 4)))
           (v2-mm-physicalAddress (unwrap (slice buffer 6 1)))
           (v2-mm-manufacturerIdentity (unwrap (slice buffer 6 3)))
           (v2-mm-profileIdentity (unwrap (slice buffer 10 6)))
           (v2-mm-initializationKey (unwrap (read-u16be buffer 18)))
           (v2-mm-numberOfFaultRecords (unwrap (read-u16be buffer 20)))
           (v2-mm-faultRecordLength (unwrap (read-u16be buffer 22)))
           (v2-mm-faultTime-s (unwrap (read-u64be buffer 24)))
           (v2-mm-faultTime-ns (unwrap (read-u32be buffer 30)))
           (v2-mm-TSC (unwrap (read-u8 buffer 36)))
           (v2-mm-dds-SO (unwrap (read-u8 buffer 36)))
           (v2-mm-clockclass (unwrap (read-u8 buffer 41)))
           (v2-mm-clockvariance (unwrap (read-u16be buffer 43)))
           (v2-mm-stepsRemoved (unwrap (read-u16be buffer 56)))
           (v2-mm-parentIdentity (unwrap (read-u64be buffer 58)))
           (v2-mm-parentPort (unwrap (read-u16be buffer 66)))
           (v2-mm-parentStats (unwrap (read-u8 buffer 68)))
           (v2-mm-observedParentOffsetScaledLogVariance (unwrap (read-u16be buffer 70)))
           (v2-mm-observedParentClockPhaseChangeRate (unwrap (read-u32be buffer 72)))
           (v2-mm-grandmasterPriority1 (unwrap (read-u8 buffer 76)))
           (v2-mm-grandmasterclockclass (unwrap (read-u8 buffer 77)))
           (v2-mm-grandmasterclockvariance (unwrap (read-u16be buffer 79)))
           (v2-mm-grandmasterPriority2 (unwrap (read-u8 buffer 81)))
           (v2-mm-grandmasterIdentity (unwrap (read-u64be buffer 82)))
           (v2-mm-logMinDelayReqInterval (unwrap (read-u8 buffer 105)))
           (v2-mm-priority1 (unwrap (read-u8 buffer 112)))
           (v2-mm-priority2 (unwrap (read-u8 buffer 114)))
           (v2-mm-domainNumber (unwrap (read-u8 buffer 116)))
           (v2-mm-SO (unwrap (read-u8 buffer 118)))
           (v2-mm-logAnnounceInterval (unwrap (read-u8 buffer 120)))
           (v2-mm-announceReceiptTimeout (unwrap (read-u8 buffer 122)))
           (v2-mm-logSyncInterval (unwrap (read-u8 buffer 124)))
           (v2-mm-versionNumber (unwrap (read-u8 buffer 126)))
           (v2-mm-currentTime-s (unwrap (read-u64be buffer 128)))
           (v2-mm-currentTime-ns (unwrap (read-u32be buffer 134)))
           (v2-mm-currentUtcOffset (unwrap (read-u16be buffer 140)))
           (v2-mm-LI-61 (unwrap (read-u8 buffer 142)))
           (v2-mm-LI-59 (unwrap (read-u8 buffer 142)))
           (v2-mm-UTCV (unwrap (read-u8 buffer 142)))
           (v2-mm-TTRA (unwrap (read-u8 buffer 144)))
           (v2-mm-FTRA (unwrap (read-u8 buffer 144)))
           (v2-mm-PTP (unwrap (read-u8 buffer 146)))
           (v2-mm-ucEN (unwrap (read-u8 buffer 148)))
           (v2-mm-ptEN (unwrap (read-u8 buffer 158)))
           (v2-mm-GrandmasterActualTableSize (unwrap (read-u8 buffer 161)))
           (v2-mm-logQueryInterval (unwrap (read-u8 buffer 162)))
           (v2-mm-protocolAddressStruct (unwrap (slice buffer 165 1)))
           (v2-mm-protocolAddress-length (unwrap (read-u16be buffer 165)))
           (v2-mm-protocolAddress (unwrap (slice buffer 165 1)))
           (v2-mm-actualTableSize (unwrap (read-u16be buffer 168)))
           (v2-mm-alternatePriority1 (unwrap (read-u8 buffer 180)))
           (v2-mm-maxTableSize (unwrap (read-u16be buffer 184)))
           (v2-mm-atEN (unwrap (read-u8 buffer 187)))
           (v2-mm-maxKey (unwrap (read-u8 buffer 190)))
           (v2-mm-transmitAlternateMulticastSync (unwrap (read-u8 buffer 192)))
           (v2-mm-numberOfAlternateMasters (unwrap (read-u8 buffer 193)))
           (v2-mm-logAlternateMulticastSyncInterval (unwrap (read-u8 buffer 194)))
           (v2-mm-keyField (unwrap (read-u8 buffer 196)))
           (v2-mm-currentOffset (unwrap (read-u32be buffer 197)))
           (v2-mm-jumpSeconds (unwrap (read-u32be buffer 201)))
           (v2-mm-nextjumpSeconds (unwrap (read-u64be buffer 205)))
           (v2-mm-externalPortConfigurationEnabled (unwrap (read-u8 buffer 212)))
           (v2-mm-MO (unwrap (read-u8 buffer 214)))
           (v2-mm-holdoverUpgradeEnable (unwrap (read-u8 buffer 216)))
           (v2-mm-acceptableMasterPortDS (unwrap (read-u8 buffer 218)))
           (v2-mm-numberPorts (unwrap (read-u16be buffer 228)))
           (v2-mm-clockidentity (unwrap (read-u64be buffer 232)))
           (v2-mm-PortNumber (unwrap (read-u16be buffer 240)))
           (v2-mm-faultyFlag (unwrap (read-u8 buffer 242)))
           (v2-mm-primaryDomain (unwrap (read-u8 buffer 244)))
           (v2-mm-logMinPdelayReqInterval (unwrap (read-u8 buffer 248)))
           (v2-mm-reserved (unwrap (slice buffer 254 4)))
           (v2-mm-pad (unwrap (slice buffer 258 1)))
           (as-fu-tlv-cumulative-scaled-rate-offset (unwrap (read-u32be buffer 259)))
           (as-fu-tlv-cumulative-rate-ratio (unwrap (read-u64be buffer 259)))
           (as-fu-tlv-gm-base-indicator (unwrap (read-u16be buffer 263)))
           (as-fu-tlv-last-gm-phase-change (unwrap (slice buffer 265 12)))
           (as-fu-tlv-scaled-last-gm-freq-change (unwrap (read-u32be buffer 277)))
           (as-sig-tlv-link-delay-interval (unwrap (read-u8 buffer 281)))
           (as-sig-tlv-time-sync-interval (unwrap (read-u8 buffer 282)))
           (as-sig-tlv-announce-interval (unwrap (read-u8 buffer 283)))
           (as-sig-tlv-reserved (unwrap (slice buffer 285 2)))
           (as-csn-upstream-tx-time (unwrap (slice buffer 287 12)))
           (as-csn-neighbor-rate-ratio (unwrap (read-u32be buffer 299)))
           (as-csn-mean-link-delay (unwrap (slice buffer 303 12)))
           (as-csn-delay-asymmetry (unwrap (slice buffer 315 12)))
           (as-csn-domain-number (unwrap (read-u8 buffer 327)))
           (as-dt-tlv-sync-egress-timestamp-seconds (unwrap (slice buffer 328 6)))
           (as-dt-tlv-sync-egress-timestamp-fractional-nanoseconds (unwrap (read-u64be buffer 334)))
           (as-dt-tlv-sync-steps-removed (unwrap (read-u16be buffer 348)))
           (as-dt-tlv-rate-ratio-drift (unwrap (read-u32be buffer 350)))
           (as-dt-tlv-rate-ratio-drift-ppm (unwrap (read-u64be buffer 350)))
           (v2-oe-tlv-subtype-c37238tlv-grandmastertimeinaccuracy (unwrap (read-u32be buffer 356)))
           (v2-oe-tlv-subtype-c37238tlv-networktimeinaccuracy (unwrap (read-u32be buffer 360)))
           (v2-oe-tlv-subtype-c37238tlv-grandmasterid (unwrap (read-u16be buffer 366)))
           (v2-oe-tlv-subtype-c372382017tlv-reserved (unwrap (read-u32be buffer 368)))
           (v2-oe-tlv-subtype-c37238tlv-totaltimeinaccuracy (unwrap (read-u32be buffer 372)))
           (v2-oe-tlv-subtype-c37238tlv-reserved (unwrap (read-u16be buffer 376)))
           (v2-oe-tlv-subtype-smpte-defaultsystemframerate (unwrap (slice buffer 378 8)))
           (v2-oe-tlv-subtype-smpte-defaultsystemframerate-numerator (unwrap (read-u32be buffer 378)))
           (v2-oe-tlv-subtype-smpte-defaultsystemframerate-denominator (unwrap (read-u32be buffer 378)))
           (v2-oe-tlv-subtype-smpte-timeaddressflags (unwrap (read-u8 buffer 387)))
           (v2-oe-tlv-subtype-smpte-timeaddressflags-drop (unwrap (read-u8 buffer 387)))
           (v2-oe-tlv-subtype-smpte-timeaddressflags-color (unwrap (read-u8 buffer 387)))
           (v2-oe-tlv-subtype-smpte-currentlocaloffset (unwrap (read-u32be buffer 388)))
           (v2-oe-tlv-subtype-smpte-jumpseconds (unwrap (read-u32be buffer 392)))
           (v2-oe-tlv-subtype-smpte-timeofnextjump (unwrap (slice buffer 396 6)))
           (v2-oe-tlv-subtype-smpte-timeofnextjam (unwrap (slice buffer 402 6)))
           (v2-oe-tlv-subtype-smpte-timeofpreviousjam (unwrap (slice buffer 408 6)))
           (v2-oe-tlv-subtype-smpte-previousjamlocaloffset (unwrap (read-u32be buffer 414)))
           (v2-oe-tlv-subtype-smpte-daylightsaving (unwrap (read-u8 buffer 418)))
           (v2-oe-tlv-subtype-smpte-daylightsaving-current (unwrap (read-u8 buffer 418)))
           (v2-oe-tlv-subtype-smpte-daylightsaving-next (unwrap (read-u8 buffer 418)))
           (v2-oe-tlv-subtype-smpte-daylightsaving-previous (unwrap (read-u8 buffer 418)))
           (v2-oe-tlv-subtype-smpte-leapsecondjump (unwrap (read-u8 buffer 419)))
           (v2-oe-tlv-subtype-smpte-leapsecondjump-change (unwrap (read-u8 buffer 419)))
           (v2-an-tlv-oe-cern-wrFlags (unwrap (read-u16be buffer 422)))
           (v2-an-tlv-oe-cern-wrFlags-wrModeOn (extract-bits v2-an-tlv-oe-cern-wrFlags 0x0 0))
           (v2-an-tlv-oe-cern-wrFlags-calibrated (extract-bits v2-an-tlv-oe-cern-wrFlags 0x0 0))
           (v2-sig-oe-tlv-cern-calSendPattern (unwrap (read-u8 buffer 424)))
           (v2-sig-oe-tlv-cern-calRety (unwrap (read-u8 buffer 425)))
           (v2-sig-oe-tlv-cern-calPeriod (unwrap (read-u32be buffer 426)))
           (v2-sig-tlv-numberbits-before-timestamp (unwrap (read-u16be buffer 454)))
           (v2-sig-tlv-numberbits-after-timestamp (unwrap (read-u16be buffer 456)))
           (v2-sig-tlv-logInterMessagePeriod (unwrap (read-u8 buffer 459)))
           (v2-sig-tlv-logInterMessagePeriod-period (unwrap (read-u8 buffer 459)))
           (v2-sig-tlv-logInterMessagePeriod-rate (unwrap (read-u8 buffer 459)))
           (v2-sig-tlv-renewalInvited (unwrap (read-u8 buffer 465)))
           (v2-sig-tlv-maintainRequest (unwrap (read-u8 buffer 466)))
           (v2-sig-tlv-maintainGrant (unwrap (read-u8 buffer 466)))
           (v2-sig-tlv-reserved (unwrap (slice buffer 467 1)))
           (v2-an-tlv-pathsequence (unwrap (read-u64be buffer 468)))
           (v2-atoi-tlv-keyfield (unwrap (read-u8 buffer 476)))
           (v2-atoi-tlv-currentoffset (unwrap (read-u32be buffer 477)))
           (v2-atoi-tlv-jumpseconds (unwrap (read-u32be buffer 481)))
           (as-sig-tlv-flags (unwrap (read-u8 buffer 492)))
           (as-sig-tlv-gptp-capable-message-interval (unwrap (read-u8 buffer 497)))
           (as-sig-tlv-gptp-capable-reserved (unwrap (slice buffer 498 3)))
           (v2-sig-tlv-flags2 (unwrap (read-u16be buffer 501)))
           (v2-sig-tlv-l1sync-flags2-reserved (extract-bits v2-sig-tlv-flags2 0x0 0))
           (v2-sig-tlv-flags3 (unwrap (read-u24be buffer 501)))
           (v2-sig-tlv-l1sync-flags3-fov (extract-bits v2-sig-tlv-flags3 0x0 0))
           (v2-sig-tlv-l1sync-flags3-pov (extract-bits v2-sig-tlv-flags3 0x0 0))
           (v2-sig-tlv-l1sync-flags3-tct (extract-bits v2-sig-tlv-flags3 0x0 0))
           (v2-sig-tlv-l1sync-flags3-reserved (extract-bits v2-sig-tlv-flags3 0x0 0))
           (v2-auth-tlv-spp (unwrap (read-u8 buffer 501)))
           (v2-auth-tlv-sec-param-indicator (unwrap (read-u8 buffer 502)))
           (v2-auth-tlv-key-id (unwrap (read-u32be buffer 503)))
           (tlv-unparsed-payload (unwrap (slice buffer 507 1)))
           )

      (ok (list
        (cons 'v2-mm-data (list (cons 'raw v2-mm-data) (cons 'formatted (fmt-bytes v2-mm-data))))
        (cons 'v2-mm-clockType (list (cons 'raw v2-mm-clockType) (cons 'formatted (fmt-hex v2-mm-clockType))))
        (cons 'v2-mm-clockType-ordinaryClock (list (cons 'raw v2-mm-clockType-ordinaryClock) (cons 'formatted (number->string v2-mm-clockType-ordinaryClock))))
        (cons 'v2-mm-clockType-boundaryClock (list (cons 'raw v2-mm-clockType-boundaryClock) (cons 'formatted (number->string v2-mm-clockType-boundaryClock))))
        (cons 'v2-mm-clockType-p2p-transparentClock (list (cons 'raw v2-mm-clockType-p2p-transparentClock) (cons 'formatted (number->string v2-mm-clockType-p2p-transparentClock))))
        (cons 'v2-mm-clockType-e2e-transparentClock (list (cons 'raw v2-mm-clockType-e2e-transparentClock) (cons 'formatted (number->string v2-mm-clockType-e2e-transparentClock))))
        (cons 'v2-mm-clockType-managementNode (list (cons 'raw v2-mm-clockType-managementNode) (cons 'formatted (number->string v2-mm-clockType-managementNode))))
        (cons 'v2-mm-clockType-reserved (list (cons 'raw v2-mm-clockType-reserved) (cons 'formatted (number->string v2-mm-clockType-reserved))))
        (cons 'v2-mm-physicalAddressLength (list (cons 'raw v2-mm-physicalAddressLength) (cons 'formatted (number->string v2-mm-physicalAddressLength))))
        (cons 'v2-mm-physicalAddress (list (cons 'raw v2-mm-physicalAddress) (cons 'formatted (fmt-bytes v2-mm-physicalAddress))))
        (cons 'v2-mm-manufacturerIdentity (list (cons 'raw v2-mm-manufacturerIdentity) (cons 'formatted (fmt-bytes v2-mm-manufacturerIdentity))))
        (cons 'v2-mm-profileIdentity (list (cons 'raw v2-mm-profileIdentity) (cons 'formatted (fmt-bytes v2-mm-profileIdentity))))
        (cons 'v2-mm-initializationKey (list (cons 'raw v2-mm-initializationKey) (cons 'formatted (number->string v2-mm-initializationKey))))
        (cons 'v2-mm-numberOfFaultRecords (list (cons 'raw v2-mm-numberOfFaultRecords) (cons 'formatted (number->string v2-mm-numberOfFaultRecords))))
        (cons 'v2-mm-faultRecordLength (list (cons 'raw v2-mm-faultRecordLength) (cons 'formatted (number->string v2-mm-faultRecordLength))))
        (cons 'v2-mm-faultTime-s (list (cons 'raw v2-mm-faultTime-s) (cons 'formatted (number->string v2-mm-faultTime-s))))
        (cons 'v2-mm-faultTime-ns (list (cons 'raw v2-mm-faultTime-ns) (cons 'formatted (number->string v2-mm-faultTime-ns))))
        (cons 'v2-mm-TSC (list (cons 'raw v2-mm-TSC) (cons 'formatted (number->string v2-mm-TSC))))
        (cons 'v2-mm-dds-SO (list (cons 'raw v2-mm-dds-SO) (cons 'formatted (number->string v2-mm-dds-SO))))
        (cons 'v2-mm-clockclass (list (cons 'raw v2-mm-clockclass) (cons 'formatted (number->string v2-mm-clockclass))))
        (cons 'v2-mm-clockvariance (list (cons 'raw v2-mm-clockvariance) (cons 'formatted (number->string v2-mm-clockvariance))))
        (cons 'v2-mm-stepsRemoved (list (cons 'raw v2-mm-stepsRemoved) (cons 'formatted (number->string v2-mm-stepsRemoved))))
        (cons 'v2-mm-parentIdentity (list (cons 'raw v2-mm-parentIdentity) (cons 'formatted (fmt-hex v2-mm-parentIdentity))))
        (cons 'v2-mm-parentPort (list (cons 'raw v2-mm-parentPort) (cons 'formatted (number->string v2-mm-parentPort))))
        (cons 'v2-mm-parentStats (list (cons 'raw v2-mm-parentStats) (cons 'formatted (number->string v2-mm-parentStats))))
        (cons 'v2-mm-observedParentOffsetScaledLogVariance (list (cons 'raw v2-mm-observedParentOffsetScaledLogVariance) (cons 'formatted (number->string v2-mm-observedParentOffsetScaledLogVariance))))
        (cons 'v2-mm-observedParentClockPhaseChangeRate (list (cons 'raw v2-mm-observedParentClockPhaseChangeRate) (cons 'formatted (number->string v2-mm-observedParentClockPhaseChangeRate))))
        (cons 'v2-mm-grandmasterPriority1 (list (cons 'raw v2-mm-grandmasterPriority1) (cons 'formatted (number->string v2-mm-grandmasterPriority1))))
        (cons 'v2-mm-grandmasterclockclass (list (cons 'raw v2-mm-grandmasterclockclass) (cons 'formatted (number->string v2-mm-grandmasterclockclass))))
        (cons 'v2-mm-grandmasterclockvariance (list (cons 'raw v2-mm-grandmasterclockvariance) (cons 'formatted (number->string v2-mm-grandmasterclockvariance))))
        (cons 'v2-mm-grandmasterPriority2 (list (cons 'raw v2-mm-grandmasterPriority2) (cons 'formatted (number->string v2-mm-grandmasterPriority2))))
        (cons 'v2-mm-grandmasterIdentity (list (cons 'raw v2-mm-grandmasterIdentity) (cons 'formatted (fmt-hex v2-mm-grandmasterIdentity))))
        (cons 'v2-mm-logMinDelayReqInterval (list (cons 'raw v2-mm-logMinDelayReqInterval) (cons 'formatted (number->string v2-mm-logMinDelayReqInterval))))
        (cons 'v2-mm-priority1 (list (cons 'raw v2-mm-priority1) (cons 'formatted (number->string v2-mm-priority1))))
        (cons 'v2-mm-priority2 (list (cons 'raw v2-mm-priority2) (cons 'formatted (number->string v2-mm-priority2))))
        (cons 'v2-mm-domainNumber (list (cons 'raw v2-mm-domainNumber) (cons 'formatted (number->string v2-mm-domainNumber))))
        (cons 'v2-mm-SO (list (cons 'raw v2-mm-SO) (cons 'formatted (number->string v2-mm-SO))))
        (cons 'v2-mm-logAnnounceInterval (list (cons 'raw v2-mm-logAnnounceInterval) (cons 'formatted (number->string v2-mm-logAnnounceInterval))))
        (cons 'v2-mm-announceReceiptTimeout (list (cons 'raw v2-mm-announceReceiptTimeout) (cons 'formatted (number->string v2-mm-announceReceiptTimeout))))
        (cons 'v2-mm-logSyncInterval (list (cons 'raw v2-mm-logSyncInterval) (cons 'formatted (number->string v2-mm-logSyncInterval))))
        (cons 'v2-mm-versionNumber (list (cons 'raw v2-mm-versionNumber) (cons 'formatted (number->string v2-mm-versionNumber))))
        (cons 'v2-mm-currentTime-s (list (cons 'raw v2-mm-currentTime-s) (cons 'formatted (number->string v2-mm-currentTime-s))))
        (cons 'v2-mm-currentTime-ns (list (cons 'raw v2-mm-currentTime-ns) (cons 'formatted (number->string v2-mm-currentTime-ns))))
        (cons 'v2-mm-currentUtcOffset (list (cons 'raw v2-mm-currentUtcOffset) (cons 'formatted (number->string v2-mm-currentUtcOffset))))
        (cons 'v2-mm-LI-61 (list (cons 'raw v2-mm-LI-61) (cons 'formatted (number->string v2-mm-LI-61))))
        (cons 'v2-mm-LI-59 (list (cons 'raw v2-mm-LI-59) (cons 'formatted (number->string v2-mm-LI-59))))
        (cons 'v2-mm-UTCV (list (cons 'raw v2-mm-UTCV) (cons 'formatted (number->string v2-mm-UTCV))))
        (cons 'v2-mm-TTRA (list (cons 'raw v2-mm-TTRA) (cons 'formatted (number->string v2-mm-TTRA))))
        (cons 'v2-mm-FTRA (list (cons 'raw v2-mm-FTRA) (cons 'formatted (number->string v2-mm-FTRA))))
        (cons 'v2-mm-PTP (list (cons 'raw v2-mm-PTP) (cons 'formatted (number->string v2-mm-PTP))))
        (cons 'v2-mm-ucEN (list (cons 'raw v2-mm-ucEN) (cons 'formatted (number->string v2-mm-ucEN))))
        (cons 'v2-mm-ptEN (list (cons 'raw v2-mm-ptEN) (cons 'formatted (number->string v2-mm-ptEN))))
        (cons 'v2-mm-GrandmasterActualTableSize (list (cons 'raw v2-mm-GrandmasterActualTableSize) (cons 'formatted (number->string v2-mm-GrandmasterActualTableSize))))
        (cons 'v2-mm-logQueryInterval (list (cons 'raw v2-mm-logQueryInterval) (cons 'formatted (number->string v2-mm-logQueryInterval))))
        (cons 'v2-mm-protocolAddressStruct (list (cons 'raw v2-mm-protocolAddressStruct) (cons 'formatted (fmt-bytes v2-mm-protocolAddressStruct))))
        (cons 'v2-mm-protocolAddress-length (list (cons 'raw v2-mm-protocolAddress-length) (cons 'formatted (number->string v2-mm-protocolAddress-length))))
        (cons 'v2-mm-protocolAddress (list (cons 'raw v2-mm-protocolAddress) (cons 'formatted (fmt-bytes v2-mm-protocolAddress))))
        (cons 'v2-mm-actualTableSize (list (cons 'raw v2-mm-actualTableSize) (cons 'formatted (number->string v2-mm-actualTableSize))))
        (cons 'v2-mm-alternatePriority1 (list (cons 'raw v2-mm-alternatePriority1) (cons 'formatted (number->string v2-mm-alternatePriority1))))
        (cons 'v2-mm-maxTableSize (list (cons 'raw v2-mm-maxTableSize) (cons 'formatted (number->string v2-mm-maxTableSize))))
        (cons 'v2-mm-atEN (list (cons 'raw v2-mm-atEN) (cons 'formatted (number->string v2-mm-atEN))))
        (cons 'v2-mm-maxKey (list (cons 'raw v2-mm-maxKey) (cons 'formatted (number->string v2-mm-maxKey))))
        (cons 'v2-mm-transmitAlternateMulticastSync (list (cons 'raw v2-mm-transmitAlternateMulticastSync) (cons 'formatted (number->string v2-mm-transmitAlternateMulticastSync))))
        (cons 'v2-mm-numberOfAlternateMasters (list (cons 'raw v2-mm-numberOfAlternateMasters) (cons 'formatted (number->string v2-mm-numberOfAlternateMasters))))
        (cons 'v2-mm-logAlternateMulticastSyncInterval (list (cons 'raw v2-mm-logAlternateMulticastSyncInterval) (cons 'formatted (number->string v2-mm-logAlternateMulticastSyncInterval))))
        (cons 'v2-mm-keyField (list (cons 'raw v2-mm-keyField) (cons 'formatted (number->string v2-mm-keyField))))
        (cons 'v2-mm-currentOffset (list (cons 'raw v2-mm-currentOffset) (cons 'formatted (number->string v2-mm-currentOffset))))
        (cons 'v2-mm-jumpSeconds (list (cons 'raw v2-mm-jumpSeconds) (cons 'formatted (number->string v2-mm-jumpSeconds))))
        (cons 'v2-mm-nextjumpSeconds (list (cons 'raw v2-mm-nextjumpSeconds) (cons 'formatted (number->string v2-mm-nextjumpSeconds))))
        (cons 'v2-mm-externalPortConfigurationEnabled (list (cons 'raw v2-mm-externalPortConfigurationEnabled) (cons 'formatted (number->string v2-mm-externalPortConfigurationEnabled))))
        (cons 'v2-mm-MO (list (cons 'raw v2-mm-MO) (cons 'formatted (number->string v2-mm-MO))))
        (cons 'v2-mm-holdoverUpgradeEnable (list (cons 'raw v2-mm-holdoverUpgradeEnable) (cons 'formatted (number->string v2-mm-holdoverUpgradeEnable))))
        (cons 'v2-mm-acceptableMasterPortDS (list (cons 'raw v2-mm-acceptableMasterPortDS) (cons 'formatted (number->string v2-mm-acceptableMasterPortDS))))
        (cons 'v2-mm-numberPorts (list (cons 'raw v2-mm-numberPorts) (cons 'formatted (number->string v2-mm-numberPorts))))
        (cons 'v2-mm-clockidentity (list (cons 'raw v2-mm-clockidentity) (cons 'formatted (fmt-hex v2-mm-clockidentity))))
        (cons 'v2-mm-PortNumber (list (cons 'raw v2-mm-PortNumber) (cons 'formatted (number->string v2-mm-PortNumber))))
        (cons 'v2-mm-faultyFlag (list (cons 'raw v2-mm-faultyFlag) (cons 'formatted (number->string v2-mm-faultyFlag))))
        (cons 'v2-mm-primaryDomain (list (cons 'raw v2-mm-primaryDomain) (cons 'formatted (number->string v2-mm-primaryDomain))))
        (cons 'v2-mm-logMinPdelayReqInterval (list (cons 'raw v2-mm-logMinPdelayReqInterval) (cons 'formatted (number->string v2-mm-logMinPdelayReqInterval))))
        (cons 'v2-mm-reserved (list (cons 'raw v2-mm-reserved) (cons 'formatted (fmt-bytes v2-mm-reserved))))
        (cons 'v2-mm-pad (list (cons 'raw v2-mm-pad) (cons 'formatted (fmt-bytes v2-mm-pad))))
        (cons 'as-fu-tlv-cumulative-scaled-rate-offset (list (cons 'raw as-fu-tlv-cumulative-scaled-rate-offset) (cons 'formatted (number->string as-fu-tlv-cumulative-scaled-rate-offset))))
        (cons 'as-fu-tlv-cumulative-rate-ratio (list (cons 'raw as-fu-tlv-cumulative-rate-ratio) (cons 'formatted (number->string as-fu-tlv-cumulative-rate-ratio))))
        (cons 'as-fu-tlv-gm-base-indicator (list (cons 'raw as-fu-tlv-gm-base-indicator) (cons 'formatted (number->string as-fu-tlv-gm-base-indicator))))
        (cons 'as-fu-tlv-last-gm-phase-change (list (cons 'raw as-fu-tlv-last-gm-phase-change) (cons 'formatted (fmt-bytes as-fu-tlv-last-gm-phase-change))))
        (cons 'as-fu-tlv-scaled-last-gm-freq-change (list (cons 'raw as-fu-tlv-scaled-last-gm-freq-change) (cons 'formatted (number->string as-fu-tlv-scaled-last-gm-freq-change))))
        (cons 'as-sig-tlv-link-delay-interval (list (cons 'raw as-sig-tlv-link-delay-interval) (cons 'formatted (number->string as-sig-tlv-link-delay-interval))))
        (cons 'as-sig-tlv-time-sync-interval (list (cons 'raw as-sig-tlv-time-sync-interval) (cons 'formatted (number->string as-sig-tlv-time-sync-interval))))
        (cons 'as-sig-tlv-announce-interval (list (cons 'raw as-sig-tlv-announce-interval) (cons 'formatted (number->string as-sig-tlv-announce-interval))))
        (cons 'as-sig-tlv-reserved (list (cons 'raw as-sig-tlv-reserved) (cons 'formatted (fmt-bytes as-sig-tlv-reserved))))
        (cons 'as-csn-upstream-tx-time (list (cons 'raw as-csn-upstream-tx-time) (cons 'formatted (fmt-bytes as-csn-upstream-tx-time))))
        (cons 'as-csn-neighbor-rate-ratio (list (cons 'raw as-csn-neighbor-rate-ratio) (cons 'formatted (number->string as-csn-neighbor-rate-ratio))))
        (cons 'as-csn-mean-link-delay (list (cons 'raw as-csn-mean-link-delay) (cons 'formatted (fmt-bytes as-csn-mean-link-delay))))
        (cons 'as-csn-delay-asymmetry (list (cons 'raw as-csn-delay-asymmetry) (cons 'formatted (fmt-bytes as-csn-delay-asymmetry))))
        (cons 'as-csn-domain-number (list (cons 'raw as-csn-domain-number) (cons 'formatted (number->string as-csn-domain-number))))
        (cons 'as-dt-tlv-sync-egress-timestamp-seconds (list (cons 'raw as-dt-tlv-sync-egress-timestamp-seconds) (cons 'formatted (number->string as-dt-tlv-sync-egress-timestamp-seconds))))
        (cons 'as-dt-tlv-sync-egress-timestamp-fractional-nanoseconds (list (cons 'raw as-dt-tlv-sync-egress-timestamp-fractional-nanoseconds) (cons 'formatted (number->string as-dt-tlv-sync-egress-timestamp-fractional-nanoseconds))))
        (cons 'as-dt-tlv-sync-steps-removed (list (cons 'raw as-dt-tlv-sync-steps-removed) (cons 'formatted (number->string as-dt-tlv-sync-steps-removed))))
        (cons 'as-dt-tlv-rate-ratio-drift (list (cons 'raw as-dt-tlv-rate-ratio-drift) (cons 'formatted (number->string as-dt-tlv-rate-ratio-drift))))
        (cons 'as-dt-tlv-rate-ratio-drift-ppm (list (cons 'raw as-dt-tlv-rate-ratio-drift-ppm) (cons 'formatted (number->string as-dt-tlv-rate-ratio-drift-ppm))))
        (cons 'v2-oe-tlv-subtype-c37238tlv-grandmastertimeinaccuracy (list (cons 'raw v2-oe-tlv-subtype-c37238tlv-grandmastertimeinaccuracy) (cons 'formatted (number->string v2-oe-tlv-subtype-c37238tlv-grandmastertimeinaccuracy))))
        (cons 'v2-oe-tlv-subtype-c37238tlv-networktimeinaccuracy (list (cons 'raw v2-oe-tlv-subtype-c37238tlv-networktimeinaccuracy) (cons 'formatted (number->string v2-oe-tlv-subtype-c37238tlv-networktimeinaccuracy))))
        (cons 'v2-oe-tlv-subtype-c37238tlv-grandmasterid (list (cons 'raw v2-oe-tlv-subtype-c37238tlv-grandmasterid) (cons 'formatted (number->string v2-oe-tlv-subtype-c37238tlv-grandmasterid))))
        (cons 'v2-oe-tlv-subtype-c372382017tlv-reserved (list (cons 'raw v2-oe-tlv-subtype-c372382017tlv-reserved) (cons 'formatted (fmt-hex v2-oe-tlv-subtype-c372382017tlv-reserved))))
        (cons 'v2-oe-tlv-subtype-c37238tlv-totaltimeinaccuracy (list (cons 'raw v2-oe-tlv-subtype-c37238tlv-totaltimeinaccuracy) (cons 'formatted (number->string v2-oe-tlv-subtype-c37238tlv-totaltimeinaccuracy))))
        (cons 'v2-oe-tlv-subtype-c37238tlv-reserved (list (cons 'raw v2-oe-tlv-subtype-c37238tlv-reserved) (cons 'formatted (fmt-hex v2-oe-tlv-subtype-c37238tlv-reserved))))
        (cons 'v2-oe-tlv-subtype-smpte-defaultsystemframerate (list (cons 'raw v2-oe-tlv-subtype-smpte-defaultsystemframerate) (cons 'formatted (fmt-bytes v2-oe-tlv-subtype-smpte-defaultsystemframerate))))
        (cons 'v2-oe-tlv-subtype-smpte-defaultsystemframerate-numerator (list (cons 'raw v2-oe-tlv-subtype-smpte-defaultsystemframerate-numerator) (cons 'formatted (number->string v2-oe-tlv-subtype-smpte-defaultsystemframerate-numerator))))
        (cons 'v2-oe-tlv-subtype-smpte-defaultsystemframerate-denominator (list (cons 'raw v2-oe-tlv-subtype-smpte-defaultsystemframerate-denominator) (cons 'formatted (number->string v2-oe-tlv-subtype-smpte-defaultsystemframerate-denominator))))
        (cons 'v2-oe-tlv-subtype-smpte-timeaddressflags (list (cons 'raw v2-oe-tlv-subtype-smpte-timeaddressflags) (cons 'formatted (fmt-hex v2-oe-tlv-subtype-smpte-timeaddressflags))))
        (cons 'v2-oe-tlv-subtype-smpte-timeaddressflags-drop (list (cons 'raw v2-oe-tlv-subtype-smpte-timeaddressflags-drop) (cons 'formatted (if (= v2-oe-tlv-subtype-smpte-timeaddressflags-drop 0) "False" "True"))))
        (cons 'v2-oe-tlv-subtype-smpte-timeaddressflags-color (list (cons 'raw v2-oe-tlv-subtype-smpte-timeaddressflags-color) (cons 'formatted (if (= v2-oe-tlv-subtype-smpte-timeaddressflags-color 0) "False" "True"))))
        (cons 'v2-oe-tlv-subtype-smpte-currentlocaloffset (list (cons 'raw v2-oe-tlv-subtype-smpte-currentlocaloffset) (cons 'formatted (number->string v2-oe-tlv-subtype-smpte-currentlocaloffset))))
        (cons 'v2-oe-tlv-subtype-smpte-jumpseconds (list (cons 'raw v2-oe-tlv-subtype-smpte-jumpseconds) (cons 'formatted (number->string v2-oe-tlv-subtype-smpte-jumpseconds))))
        (cons 'v2-oe-tlv-subtype-smpte-timeofnextjump (list (cons 'raw v2-oe-tlv-subtype-smpte-timeofnextjump) (cons 'formatted (number->string v2-oe-tlv-subtype-smpte-timeofnextjump))))
        (cons 'v2-oe-tlv-subtype-smpte-timeofnextjam (list (cons 'raw v2-oe-tlv-subtype-smpte-timeofnextjam) (cons 'formatted (number->string v2-oe-tlv-subtype-smpte-timeofnextjam))))
        (cons 'v2-oe-tlv-subtype-smpte-timeofpreviousjam (list (cons 'raw v2-oe-tlv-subtype-smpte-timeofpreviousjam) (cons 'formatted (number->string v2-oe-tlv-subtype-smpte-timeofpreviousjam))))
        (cons 'v2-oe-tlv-subtype-smpte-previousjamlocaloffset (list (cons 'raw v2-oe-tlv-subtype-smpte-previousjamlocaloffset) (cons 'formatted (number->string v2-oe-tlv-subtype-smpte-previousjamlocaloffset))))
        (cons 'v2-oe-tlv-subtype-smpte-daylightsaving (list (cons 'raw v2-oe-tlv-subtype-smpte-daylightsaving) (cons 'formatted (fmt-hex v2-oe-tlv-subtype-smpte-daylightsaving))))
        (cons 'v2-oe-tlv-subtype-smpte-daylightsaving-current (list (cons 'raw v2-oe-tlv-subtype-smpte-daylightsaving-current) (cons 'formatted (if (= v2-oe-tlv-subtype-smpte-daylightsaving-current 0) "False" "True"))))
        (cons 'v2-oe-tlv-subtype-smpte-daylightsaving-next (list (cons 'raw v2-oe-tlv-subtype-smpte-daylightsaving-next) (cons 'formatted (if (= v2-oe-tlv-subtype-smpte-daylightsaving-next 0) "False" "True"))))
        (cons 'v2-oe-tlv-subtype-smpte-daylightsaving-previous (list (cons 'raw v2-oe-tlv-subtype-smpte-daylightsaving-previous) (cons 'formatted (if (= v2-oe-tlv-subtype-smpte-daylightsaving-previous 0) "False" "True"))))
        (cons 'v2-oe-tlv-subtype-smpte-leapsecondjump (list (cons 'raw v2-oe-tlv-subtype-smpte-leapsecondjump) (cons 'formatted (fmt-hex v2-oe-tlv-subtype-smpte-leapsecondjump))))
        (cons 'v2-oe-tlv-subtype-smpte-leapsecondjump-change (list (cons 'raw v2-oe-tlv-subtype-smpte-leapsecondjump-change) (cons 'formatted (if (= v2-oe-tlv-subtype-smpte-leapsecondjump-change 0) "False" "True"))))
        (cons 'v2-an-tlv-oe-cern-wrFlags (list (cons 'raw v2-an-tlv-oe-cern-wrFlags) (cons 'formatted (fmt-hex v2-an-tlv-oe-cern-wrFlags))))
        (cons 'v2-an-tlv-oe-cern-wrFlags-wrModeOn (list (cons 'raw v2-an-tlv-oe-cern-wrFlags-wrModeOn) (cons 'formatted (if (= v2-an-tlv-oe-cern-wrFlags-wrModeOn 0) "Not set" "Set"))))
        (cons 'v2-an-tlv-oe-cern-wrFlags-calibrated (list (cons 'raw v2-an-tlv-oe-cern-wrFlags-calibrated) (cons 'formatted (if (= v2-an-tlv-oe-cern-wrFlags-calibrated 0) "Not set" "Set"))))
        (cons 'v2-sig-oe-tlv-cern-calSendPattern (list (cons 'raw v2-sig-oe-tlv-cern-calSendPattern) (cons 'formatted (number->string v2-sig-oe-tlv-cern-calSendPattern))))
        (cons 'v2-sig-oe-tlv-cern-calRety (list (cons 'raw v2-sig-oe-tlv-cern-calRety) (cons 'formatted (number->string v2-sig-oe-tlv-cern-calRety))))
        (cons 'v2-sig-oe-tlv-cern-calPeriod (list (cons 'raw v2-sig-oe-tlv-cern-calPeriod) (cons 'formatted (number->string v2-sig-oe-tlv-cern-calPeriod))))
        (cons 'v2-sig-tlv-numberbits-before-timestamp (list (cons 'raw v2-sig-tlv-numberbits-before-timestamp) (cons 'formatted (number->string v2-sig-tlv-numberbits-before-timestamp))))
        (cons 'v2-sig-tlv-numberbits-after-timestamp (list (cons 'raw v2-sig-tlv-numberbits-after-timestamp) (cons 'formatted (number->string v2-sig-tlv-numberbits-after-timestamp))))
        (cons 'v2-sig-tlv-logInterMessagePeriod (list (cons 'raw v2-sig-tlv-logInterMessagePeriod) (cons 'formatted (number->string v2-sig-tlv-logInterMessagePeriod))))
        (cons 'v2-sig-tlv-logInterMessagePeriod-period (list (cons 'raw v2-sig-tlv-logInterMessagePeriod-period) (cons 'formatted (number->string v2-sig-tlv-logInterMessagePeriod-period))))
        (cons 'v2-sig-tlv-logInterMessagePeriod-rate (list (cons 'raw v2-sig-tlv-logInterMessagePeriod-rate) (cons 'formatted (number->string v2-sig-tlv-logInterMessagePeriod-rate))))
        (cons 'v2-sig-tlv-renewalInvited (list (cons 'raw v2-sig-tlv-renewalInvited) (cons 'formatted (number->string v2-sig-tlv-renewalInvited))))
        (cons 'v2-sig-tlv-maintainRequest (list (cons 'raw v2-sig-tlv-maintainRequest) (cons 'formatted (number->string v2-sig-tlv-maintainRequest))))
        (cons 'v2-sig-tlv-maintainGrant (list (cons 'raw v2-sig-tlv-maintainGrant) (cons 'formatted (number->string v2-sig-tlv-maintainGrant))))
        (cons 'v2-sig-tlv-reserved (list (cons 'raw v2-sig-tlv-reserved) (cons 'formatted (fmt-bytes v2-sig-tlv-reserved))))
        (cons 'v2-an-tlv-pathsequence (list (cons 'raw v2-an-tlv-pathsequence) (cons 'formatted (fmt-hex v2-an-tlv-pathsequence))))
        (cons 'v2-atoi-tlv-keyfield (list (cons 'raw v2-atoi-tlv-keyfield) (cons 'formatted (number->string v2-atoi-tlv-keyfield))))
        (cons 'v2-atoi-tlv-currentoffset (list (cons 'raw v2-atoi-tlv-currentoffset) (cons 'formatted (number->string v2-atoi-tlv-currentoffset))))
        (cons 'v2-atoi-tlv-jumpseconds (list (cons 'raw v2-atoi-tlv-jumpseconds) (cons 'formatted (number->string v2-atoi-tlv-jumpseconds))))
        (cons 'as-sig-tlv-flags (list (cons 'raw as-sig-tlv-flags) (cons 'formatted (fmt-hex as-sig-tlv-flags))))
        (cons 'as-sig-tlv-gptp-capable-message-interval (list (cons 'raw as-sig-tlv-gptp-capable-message-interval) (cons 'formatted (number->string as-sig-tlv-gptp-capable-message-interval))))
        (cons 'as-sig-tlv-gptp-capable-reserved (list (cons 'raw as-sig-tlv-gptp-capable-reserved) (cons 'formatted (fmt-bytes as-sig-tlv-gptp-capable-reserved))))
        (cons 'v2-sig-tlv-flags2 (list (cons 'raw v2-sig-tlv-flags2) (cons 'formatted (fmt-hex v2-sig-tlv-flags2))))
        (cons 'v2-sig-tlv-l1sync-flags2-reserved (list (cons 'raw v2-sig-tlv-l1sync-flags2-reserved) (cons 'formatted (if (= v2-sig-tlv-l1sync-flags2-reserved 0) "Not set" "Set"))))
        (cons 'v2-sig-tlv-flags3 (list (cons 'raw v2-sig-tlv-flags3) (cons 'formatted (fmt-hex v2-sig-tlv-flags3))))
        (cons 'v2-sig-tlv-l1sync-flags3-fov (list (cons 'raw v2-sig-tlv-l1sync-flags3-fov) (cons 'formatted (if (= v2-sig-tlv-l1sync-flags3-fov 0) "Not set" "Set"))))
        (cons 'v2-sig-tlv-l1sync-flags3-pov (list (cons 'raw v2-sig-tlv-l1sync-flags3-pov) (cons 'formatted (if (= v2-sig-tlv-l1sync-flags3-pov 0) "Not set" "Set"))))
        (cons 'v2-sig-tlv-l1sync-flags3-tct (list (cons 'raw v2-sig-tlv-l1sync-flags3-tct) (cons 'formatted (if (= v2-sig-tlv-l1sync-flags3-tct 0) "Not set" "Set"))))
        (cons 'v2-sig-tlv-l1sync-flags3-reserved (list (cons 'raw v2-sig-tlv-l1sync-flags3-reserved) (cons 'formatted (if (= v2-sig-tlv-l1sync-flags3-reserved 0) "Not set" "Set"))))
        (cons 'v2-auth-tlv-spp (list (cons 'raw v2-auth-tlv-spp) (cons 'formatted (number->string v2-auth-tlv-spp))))
        (cons 'v2-auth-tlv-sec-param-indicator (list (cons 'raw v2-auth-tlv-sec-param-indicator) (cons 'formatted (fmt-hex v2-auth-tlv-sec-param-indicator))))
        (cons 'v2-auth-tlv-key-id (list (cons 'raw v2-auth-tlv-key-id) (cons 'formatted (number->string v2-auth-tlv-key-id))))
        (cons 'tlv-unparsed-payload (list (cons 'raw tlv-unparsed-payload) (cons 'formatted (fmt-bytes tlv-unparsed-payload))))
        )))

    (catch (e)
      (err (str "PTP parse error: " e)))))

;; dissect-ptp: parse PTP from bytevector
;; Returns (ok fields-alist) or (err message)