;; packet-cast.c
;;
;; Dissector for the CAST Client Control Protocol
;; (The "D-Channel"-Protocol for Cisco Systems' IP-Phones)
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/cast.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cast.c

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
(def (dissect-cast buffer)
  "Cast Client Control Protocol"
  (try
    (let* (
           (reserved (unwrap (read-u32be buffer 0)))
           (version (unwrap (read-u32be buffer 0)))
           (videoCapCount (unwrap (read-u32be buffer 0)))
           (dataCapCount (unwrap (read-u32be buffer 0)))
           (RTPPayloadFormat (unwrap (read-u32be buffer 0)))
           (customPictureFormatCount (unwrap (read-u32be buffer 0)))
           (conferenceID (unwrap (read-u32be buffer 0)))
           (passThruPartyID (unwrap (read-u32be buffer 0)))
           (lineInstance (unwrap (read-u32be buffer 0)))
           (callIdentifier (unwrap (read-u32be buffer 0)))
           (payload-rfc-number (unwrap (read-u32be buffer 0)))
           (payloadType (unwrap (read-u32be buffer 0)))
           (isConferenceCreator (unwrap (read-u32be buffer 0)))
           (millisecondPacketSize (unwrap (read-u32be buffer 0)))
           (bitRate (unwrap (read-u32be buffer 0)))
           (pictureFormatCount (unwrap (read-u32be buffer 0)))
           (protocolDependentData (unwrap (read-u32be buffer 0)))
           (maxBitRate (unwrap (read-u32be buffer 0)))
           (ipAddress (unwrap (read-u32be buffer 0)))
           (portNumber (unwrap (read-u32be buffer 0)))
           (DSCPValue (unwrap (read-u32be buffer 0)))
           (firstGOB (unwrap (read-u32be buffer 0)))
           (numberOfGOBs (unwrap (read-u32be buffer 0)))
           (firstMB (unwrap (read-u32be buffer 0)))
           (numberOfMBs (unwrap (read-u32be buffer 0)))
           (pictureNumber (unwrap (read-u32be buffer 0)))
           (longTermPictureIndex (unwrap (read-u32be buffer 0)))
           (recoveryReferencePictureCount (unwrap (read-u32be buffer 0)))
           (temporalSpatialTradeOff (unwrap (read-u32be buffer 0)))
           (serviceNum (unwrap (read-u32be buffer 0)))
           (privacy (unwrap (read-u32be buffer 0)))
           (precedenceLv (unwrap (read-u32be buffer 0)))
           (precedenceDm (unwrap (read-u32be buffer 0)))
           (calledParty (unwrap (slice buffer 0 1)))
           (data-length (unwrap (read-u32be buffer 4)))
           )

      (ok (list
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-hex reserved))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'videoCapCount (list (cons 'raw videoCapCount) (cons 'formatted (number->string videoCapCount))))
        (cons 'dataCapCount (list (cons 'raw dataCapCount) (cons 'formatted (number->string dataCapCount))))
        (cons 'RTPPayloadFormat (list (cons 'raw RTPPayloadFormat) (cons 'formatted (number->string RTPPayloadFormat))))
        (cons 'customPictureFormatCount (list (cons 'raw customPictureFormatCount) (cons 'formatted (number->string customPictureFormatCount))))
        (cons 'conferenceID (list (cons 'raw conferenceID) (cons 'formatted (number->string conferenceID))))
        (cons 'passThruPartyID (list (cons 'raw passThruPartyID) (cons 'formatted (number->string passThruPartyID))))
        (cons 'lineInstance (list (cons 'raw lineInstance) (cons 'formatted (number->string lineInstance))))
        (cons 'callIdentifier (list (cons 'raw callIdentifier) (cons 'formatted (number->string callIdentifier))))
        (cons 'payload-rfc-number (list (cons 'raw payload-rfc-number) (cons 'formatted (number->string payload-rfc-number))))
        (cons 'payloadType (list (cons 'raw payloadType) (cons 'formatted (number->string payloadType))))
        (cons 'isConferenceCreator (list (cons 'raw isConferenceCreator) (cons 'formatted (number->string isConferenceCreator))))
        (cons 'millisecondPacketSize (list (cons 'raw millisecondPacketSize) (cons 'formatted (number->string millisecondPacketSize))))
        (cons 'bitRate (list (cons 'raw bitRate) (cons 'formatted (number->string bitRate))))
        (cons 'pictureFormatCount (list (cons 'raw pictureFormatCount) (cons 'formatted (number->string pictureFormatCount))))
        (cons 'protocolDependentData (list (cons 'raw protocolDependentData) (cons 'formatted (number->string protocolDependentData))))
        (cons 'maxBitRate (list (cons 'raw maxBitRate) (cons 'formatted (number->string maxBitRate))))
        (cons 'ipAddress (list (cons 'raw ipAddress) (cons 'formatted (fmt-ipv4 ipAddress))))
        (cons 'portNumber (list (cons 'raw portNumber) (cons 'formatted (number->string portNumber))))
        (cons 'DSCPValue (list (cons 'raw DSCPValue) (cons 'formatted (number->string DSCPValue))))
        (cons 'firstGOB (list (cons 'raw firstGOB) (cons 'formatted (number->string firstGOB))))
        (cons 'numberOfGOBs (list (cons 'raw numberOfGOBs) (cons 'formatted (number->string numberOfGOBs))))
        (cons 'firstMB (list (cons 'raw firstMB) (cons 'formatted (number->string firstMB))))
        (cons 'numberOfMBs (list (cons 'raw numberOfMBs) (cons 'formatted (number->string numberOfMBs))))
        (cons 'pictureNumber (list (cons 'raw pictureNumber) (cons 'formatted (number->string pictureNumber))))
        (cons 'longTermPictureIndex (list (cons 'raw longTermPictureIndex) (cons 'formatted (number->string longTermPictureIndex))))
        (cons 'recoveryReferencePictureCount (list (cons 'raw recoveryReferencePictureCount) (cons 'formatted (number->string recoveryReferencePictureCount))))
        (cons 'temporalSpatialTradeOff (list (cons 'raw temporalSpatialTradeOff) (cons 'formatted (number->string temporalSpatialTradeOff))))
        (cons 'serviceNum (list (cons 'raw serviceNum) (cons 'formatted (number->string serviceNum))))
        (cons 'privacy (list (cons 'raw privacy) (cons 'formatted (number->string privacy))))
        (cons 'precedenceLv (list (cons 'raw precedenceLv) (cons 'formatted (number->string precedenceLv))))
        (cons 'precedenceDm (list (cons 'raw precedenceDm) (cons 'formatted (number->string precedenceDm))))
        (cons 'calledParty (list (cons 'raw calledParty) (cons 'formatted (utf8->string calledParty))))
        (cons 'data-length (list (cons 'raw data-length) (cons 'formatted (number->string data-length))))
        )))

    (catch (e)
      (err (str "CAST parse error: " e)))))

;; dissect-cast: parse CAST from bytevector
;; Returns (ok fields-alist) or (err message)