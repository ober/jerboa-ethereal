;; packet-ged125.c
;; Routines for ged125 dissection
;; Copyright June/July 2008, Martin Corraine <mcorrain@cisco.com, mac1190@rit.edu>
;; Assistance was provided by the following:
;; Paul Antinori 		<pantinor[AT]cisco.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; GED125
;; This is Cisco's protocol that runs atop TCP (ged125 is in the payload of TCP).
;; The protocol serves as a way for the ICM and the VRU to communicate to each
;; other in Cisco's CVP. The spec sheet that was used to write this dissector was
;; Revision 3.1a of November 26, 2007.
;;
;; Protocol Structure
;;
;; All messages have an eight byte header. The first 4 bytes represent the package
;; length. This length doesn't include the length of the base header. Next, is the
;; message base type which is also 4 bytes. All ged125 messages have this format
;; unless a message spans across several packets. The most common message is the
;; service control type. This message type will have its own header and with in
;; that header have a few other things. One of these things is a sub-message type.
;;

;; jerboa-ethereal/dissectors/ged125.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ged125.c

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
(def (dissect-ged125 buffer)
  "Cisco GED-125 Protocol"
  (try
    (let* (
           (VersionNumber (unwrap (read-u32be buffer 24)))
           (length (unwrap (read-u32be buffer 25)))
           (IdleTimeout (unwrap (read-u32be buffer 28)))
           (floating-payload-ECC-tag (unwrap (read-u32be buffer 30)))
           (floating-uchar-array-index (unwrap (read-u32be buffer 34)))
           (floating-payload-strg (unwrap (slice buffer 35 1)))
           (floating-payload-unspec (unwrap (slice buffer 35 1)))
           (floating-payload-uint (unwrap (read-u32be buffer 35)))
           (floating-payload-bool (unwrap (read-u8 buffer 35)))
           (UseEventFeed (unwrap (read-u8 buffer 36)))
           (UsePolledFeed (unwrap (read-u8 buffer 40)))
           (UseCallRouting (unwrap (read-u8 buffer 44)))
           (UseTimeSynch (unwrap (read-u8 buffer 48)))
           (UseServiceControl (unwrap (read-u8 buffer 52)))
           (InServiceTimeToday (unwrap (read-u32be buffer 84)))
           (InUseInboundTimeToday (unwrap (read-u32be buffer 88)))
           (InUseOutboundTimeToday (unwrap (read-u32be buffer 92)))
           (AllTrunksInUseTimeToday (unwrap (read-u32be buffer 96)))
           (AvailableNow (unwrap (read-u8 buffer 108)))
           (CallsInNow (unwrap (read-u32be buffer 112)))
           (CallsOutNow (unwrap (read-u32be buffer 116)))
           (CallsInToday (unwrap (read-u32be buffer 120)))
           (CallsOutToday (unwrap (read-u32be buffer 124)))
           (CallsHandledToday (unwrap (read-u32be buffer 128)))
           (HandleTimeToday (unwrap (read-u32be buffer 132)))
           (DivertedInToday (unwrap (read-u32be buffer 136)))
           (DivertedOutToday (unwrap (read-u32be buffer 140)))
           (InitDataTime (unwrap (read-u32be buffer 156)))
           (StartOfDay (unwrap (read-u32be buffer 160)))
           (TrunkNumber (unwrap (read-u32be buffer 172)))
           (floating-CauseCode (unwrap (read-u32be buffer 184)))
           (ConferenceCallID (unwrap (read-u32be buffer 188)))
           (PrimaryCallID (unwrap (read-u32be buffer 192)))
           (SecondaryCallID (unwrap (read-u32be buffer 196)))
           (NewServiceID (unwrap (read-u32be buffer 208)))
           (NewCallID (unwrap (read-u32be buffer 216)))
           (CurrentTime-num (unwrap (read-u32be buffer 228)))
           (TimeZoneDelta (unwrap (read-u32be buffer 232)))
           (TrunkGroupID (unwrap (read-u32be buffer 236)))
           (TrunkCount (unwrap (read-u32be buffer 240)))
           (InService (unwrap (read-u8 buffer 244)))
           (ServiceID (unwrap (read-u32be buffer 248)))
           (ServiceAvailable (unwrap (read-u8 buffer 252)))
           (CallID (unwrap (read-u32be buffer 260)))
           (CrossRefID (unwrap (read-u32be buffer 272)))
           (VRUTimeLag (unwrap (read-u32be buffer 284)))
           (InvokeID (unwrap (read-u32be buffer 288)))
           (simulator-reset-event (unwrap (read-u32be buffer 292)))
           (CallVarsMask (unwrap (read-u32be buffer 292)))
           )

      (ok (list
        (cons 'VersionNumber (list (cons 'raw VersionNumber) (cons 'formatted (number->string VersionNumber))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'IdleTimeout (list (cons 'raw IdleTimeout) (cons 'formatted (number->string IdleTimeout))))
        (cons 'floating-payload-ECC-tag (list (cons 'raw floating-payload-ECC-tag) (cons 'formatted (number->string floating-payload-ECC-tag))))
        (cons 'floating-uchar-array-index (list (cons 'raw floating-uchar-array-index) (cons 'formatted (number->string floating-uchar-array-index))))
        (cons 'floating-payload-strg (list (cons 'raw floating-payload-strg) (cons 'formatted (utf8->string floating-payload-strg))))
        (cons 'floating-payload-unspec (list (cons 'raw floating-payload-unspec) (cons 'formatted (fmt-bytes floating-payload-unspec))))
        (cons 'floating-payload-uint (list (cons 'raw floating-payload-uint) (cons 'formatted (number->string floating-payload-uint))))
        (cons 'floating-payload-bool (list (cons 'raw floating-payload-bool) (cons 'formatted (number->string floating-payload-bool))))
        (cons 'UseEventFeed (list (cons 'raw UseEventFeed) (cons 'formatted (number->string UseEventFeed))))
        (cons 'UsePolledFeed (list (cons 'raw UsePolledFeed) (cons 'formatted (number->string UsePolledFeed))))
        (cons 'UseCallRouting (list (cons 'raw UseCallRouting) (cons 'formatted (number->string UseCallRouting))))
        (cons 'UseTimeSynch (list (cons 'raw UseTimeSynch) (cons 'formatted (number->string UseTimeSynch))))
        (cons 'UseServiceControl (list (cons 'raw UseServiceControl) (cons 'formatted (number->string UseServiceControl))))
        (cons 'InServiceTimeToday (list (cons 'raw InServiceTimeToday) (cons 'formatted (number->string InServiceTimeToday))))
        (cons 'InUseInboundTimeToday (list (cons 'raw InUseInboundTimeToday) (cons 'formatted (number->string InUseInboundTimeToday))))
        (cons 'InUseOutboundTimeToday (list (cons 'raw InUseOutboundTimeToday) (cons 'formatted (number->string InUseOutboundTimeToday))))
        (cons 'AllTrunksInUseTimeToday (list (cons 'raw AllTrunksInUseTimeToday) (cons 'formatted (number->string AllTrunksInUseTimeToday))))
        (cons 'AvailableNow (list (cons 'raw AvailableNow) (cons 'formatted (number->string AvailableNow))))
        (cons 'CallsInNow (list (cons 'raw CallsInNow) (cons 'formatted (number->string CallsInNow))))
        (cons 'CallsOutNow (list (cons 'raw CallsOutNow) (cons 'formatted (number->string CallsOutNow))))
        (cons 'CallsInToday (list (cons 'raw CallsInToday) (cons 'formatted (number->string CallsInToday))))
        (cons 'CallsOutToday (list (cons 'raw CallsOutToday) (cons 'formatted (number->string CallsOutToday))))
        (cons 'CallsHandledToday (list (cons 'raw CallsHandledToday) (cons 'formatted (number->string CallsHandledToday))))
        (cons 'HandleTimeToday (list (cons 'raw HandleTimeToday) (cons 'formatted (number->string HandleTimeToday))))
        (cons 'DivertedInToday (list (cons 'raw DivertedInToday) (cons 'formatted (number->string DivertedInToday))))
        (cons 'DivertedOutToday (list (cons 'raw DivertedOutToday) (cons 'formatted (number->string DivertedOutToday))))
        (cons 'InitDataTime (list (cons 'raw InitDataTime) (cons 'formatted (number->string InitDataTime))))
        (cons 'StartOfDay (list (cons 'raw StartOfDay) (cons 'formatted (number->string StartOfDay))))
        (cons 'TrunkNumber (list (cons 'raw TrunkNumber) (cons 'formatted (number->string TrunkNumber))))
        (cons 'floating-CauseCode (list (cons 'raw floating-CauseCode) (cons 'formatted (number->string floating-CauseCode))))
        (cons 'ConferenceCallID (list (cons 'raw ConferenceCallID) (cons 'formatted (number->string ConferenceCallID))))
        (cons 'PrimaryCallID (list (cons 'raw PrimaryCallID) (cons 'formatted (number->string PrimaryCallID))))
        (cons 'SecondaryCallID (list (cons 'raw SecondaryCallID) (cons 'formatted (number->string SecondaryCallID))))
        (cons 'NewServiceID (list (cons 'raw NewServiceID) (cons 'formatted (number->string NewServiceID))))
        (cons 'NewCallID (list (cons 'raw NewCallID) (cons 'formatted (number->string NewCallID))))
        (cons 'CurrentTime-num (list (cons 'raw CurrentTime-num) (cons 'formatted (number->string CurrentTime-num))))
        (cons 'TimeZoneDelta (list (cons 'raw TimeZoneDelta) (cons 'formatted (number->string TimeZoneDelta))))
        (cons 'TrunkGroupID (list (cons 'raw TrunkGroupID) (cons 'formatted (number->string TrunkGroupID))))
        (cons 'TrunkCount (list (cons 'raw TrunkCount) (cons 'formatted (number->string TrunkCount))))
        (cons 'InService (list (cons 'raw InService) (cons 'formatted (number->string InService))))
        (cons 'ServiceID (list (cons 'raw ServiceID) (cons 'formatted (number->string ServiceID))))
        (cons 'ServiceAvailable (list (cons 'raw ServiceAvailable) (cons 'formatted (number->string ServiceAvailable))))
        (cons 'CallID (list (cons 'raw CallID) (cons 'formatted (number->string CallID))))
        (cons 'CrossRefID (list (cons 'raw CrossRefID) (cons 'formatted (number->string CrossRefID))))
        (cons 'VRUTimeLag (list (cons 'raw VRUTimeLag) (cons 'formatted (number->string VRUTimeLag))))
        (cons 'InvokeID (list (cons 'raw InvokeID) (cons 'formatted (number->string InvokeID))))
        (cons 'simulator-reset-event (list (cons 'raw simulator-reset-event) (cons 'formatted (number->string simulator-reset-event))))
        (cons 'CallVarsMask (list (cons 'raw CallVarsMask) (cons 'formatted (fmt-hex CallVarsMask))))
        )))

    (catch (e)
      (err (str "GED125 parse error: " e)))))

;; dissect-ged125: parse GED125 from bytevector
;; Returns (ok fields-alist) or (err message)