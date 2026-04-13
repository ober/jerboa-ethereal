;; packet-ecpri.c
;; Routines for eCPRI dissection
;; Copyright 2019, Maximilian Kohler <maximilian.kohler@viavisolutions.com>
;; Copyright 2024, Tomasz Woszczynski <duchowe50k@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; ------------------------------------------------------------------------------------------------
;; eCPRI Transport Network V1.2 -- Specifications
;; http://www.cpri.info/downloads/Requirements_for_the_eCPRI_Transport_Network_V1_2_2018_06_25.pdf
;; eCPRI Transport Network V2.0 -- Specifications
;; https://www.cpri.info/downloads/eCPRI_v_2.0_2019_05_10c.pdf
;;
;; May carry ORAN FH-CUS (packet-oran.c) - Message Types, 0, 2
;; See https://specifications.o-ran.org/specifications, WG4, Fronthaul Interfaces Workgroup
;; ------------------------------------------------------------------------------------------------
;;

;; jerboa-ethereal/dissectors/ecpri.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ecpri.c

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
(def (dissect-ecpri buffer)
  "evolved Common Public Radio Interface"
  (try
    (let* (
           (way-delay-measurement-calculated-delay-response-frame (unwrap (read-u32be buffer 0)))
           (way-delay-measurement-calculated-delay-request-frame (unwrap (read-u32be buffer 0)))
           (way-delay-measurement-calculated-delay (unwrap (read-u64be buffer 0)))
           (header (unwrap (slice buffer 0 1)))
           (header-ecpri-protocol-revision (unwrap (read-u8 buffer 0)))
           (header-reserved (unwrap (read-u8 buffer 0)))
           (header-c-bit (unwrap (read-u8 buffer 0)))
           (header-ecpri-payload-size (unwrap (read-u16be buffer 2)))
           (data-seq-id (unwrap (read-u16be buffer 6)))
           (sequence-seq-id (unwrap (read-u16be buffer 10)))
           (time-control-data-rtc-id (unwrap (read-u16be buffer 12)))
           (time-control-data-seq-id (unwrap (read-u16be buffer 14)))
           (data-transfer-seq-id (unwrap (read-u32be buffer 20)))
           (memory-access-id (unwrap (read-u8 buffer 24)))
           (memory-access-element-id (unwrap (read-u16be buffer 26)))
           (memory-access-data-length (unwrap (read-u16be buffer 34)))
           (way-delay-measurement-id (unwrap (read-u8 buffer 36)))
           (reset-reset-id (unwrap (read-u16be buffer 48)))
           (indication-event-id (unwrap (read-u8 buffer 51)))
           (indication-sequence-number (unwrap (read-u8 buffer 53)))
           (indication-number-of-faults-notifications (unwrap (read-u8 buffer 54)))
           (indication-additional-information (unwrap (read-u32be buffer 59)))
           (start-up-hyperframe-number (unwrap (read-u8 buffer 65)))
           (start-up-subframe-number (unwrap (read-u8 buffer 66)))
           (start-up-fec-bit-indicator (unwrap (read-u8 buffer 71)))
           (start-up-scrambling-bit-indicator (unwrap (read-u8 buffer 71)))
           (id (unwrap (read-u32be buffer 76)))
           (delay-control-delay-control-id (unwrap (read-u8 buffer 78)))
           (delay-control-delay-a (unwrap (read-u32be buffer 80)))
           (delay-control-delay-b (unwrap (read-u32be buffer 84)))
           )

      (ok (list
        (cons 'way-delay-measurement-calculated-delay-response-frame (list (cons 'raw way-delay-measurement-calculated-delay-response-frame) (cons 'formatted (number->string way-delay-measurement-calculated-delay-response-frame))))
        (cons 'way-delay-measurement-calculated-delay-request-frame (list (cons 'raw way-delay-measurement-calculated-delay-request-frame) (cons 'formatted (number->string way-delay-measurement-calculated-delay-request-frame))))
        (cons 'way-delay-measurement-calculated-delay (list (cons 'raw way-delay-measurement-calculated-delay) (cons 'formatted (number->string way-delay-measurement-calculated-delay))))
        (cons 'header (list (cons 'raw header) (cons 'formatted (utf8->string header))))
        (cons 'header-ecpri-protocol-revision (list (cons 'raw header-ecpri-protocol-revision) (cons 'formatted (number->string header-ecpri-protocol-revision))))
        (cons 'header-reserved (list (cons 'raw header-reserved) (cons 'formatted (number->string header-reserved))))
        (cons 'header-c-bit (list (cons 'raw header-c-bit) (cons 'formatted (if (= header-c-bit 0) "This eCPRI message is last one inside eCPRI PDU" "Another eCPRI message follows this one with eCPRI PDU"))))
        (cons 'header-ecpri-payload-size (list (cons 'raw header-ecpri-payload-size) (cons 'formatted (number->string header-ecpri-payload-size))))
        (cons 'data-seq-id (list (cons 'raw data-seq-id) (cons 'formatted (fmt-hex data-seq-id))))
        (cons 'sequence-seq-id (list (cons 'raw sequence-seq-id) (cons 'formatted (fmt-hex sequence-seq-id))))
        (cons 'time-control-data-rtc-id (list (cons 'raw time-control-data-rtc-id) (cons 'formatted (fmt-hex time-control-data-rtc-id))))
        (cons 'time-control-data-seq-id (list (cons 'raw time-control-data-seq-id) (cons 'formatted (fmt-hex time-control-data-seq-id))))
        (cons 'data-transfer-seq-id (list (cons 'raw data-transfer-seq-id) (cons 'formatted (fmt-hex data-transfer-seq-id))))
        (cons 'memory-access-id (list (cons 'raw memory-access-id) (cons 'formatted (fmt-hex memory-access-id))))
        (cons 'memory-access-element-id (list (cons 'raw memory-access-element-id) (cons 'formatted (fmt-hex memory-access-element-id))))
        (cons 'memory-access-data-length (list (cons 'raw memory-access-data-length) (cons 'formatted (number->string memory-access-data-length))))
        (cons 'way-delay-measurement-id (list (cons 'raw way-delay-measurement-id) (cons 'formatted (fmt-hex way-delay-measurement-id))))
        (cons 'reset-reset-id (list (cons 'raw reset-reset-id) (cons 'formatted (fmt-hex reset-reset-id))))
        (cons 'indication-event-id (list (cons 'raw indication-event-id) (cons 'formatted (fmt-hex indication-event-id))))
        (cons 'indication-sequence-number (list (cons 'raw indication-sequence-number) (cons 'formatted (number->string indication-sequence-number))))
        (cons 'indication-number-of-faults-notifications (list (cons 'raw indication-number-of-faults-notifications) (cons 'formatted (number->string indication-number-of-faults-notifications))))
        (cons 'indication-additional-information (list (cons 'raw indication-additional-information) (cons 'formatted (fmt-hex indication-additional-information))))
        (cons 'start-up-hyperframe-number (list (cons 'raw start-up-hyperframe-number) (cons 'formatted (number->string start-up-hyperframe-number))))
        (cons 'start-up-subframe-number (list (cons 'raw start-up-subframe-number) (cons 'formatted (number->string start-up-subframe-number))))
        (cons 'start-up-fec-bit-indicator (list (cons 'raw start-up-fec-bit-indicator) (cons 'formatted (if (= start-up-fec-bit-indicator 0) "False" "True"))))
        (cons 'start-up-scrambling-bit-indicator (list (cons 'raw start-up-scrambling-bit-indicator) (cons 'formatted (if (= start-up-scrambling-bit-indicator 0) "False" "True"))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (fmt-hex id))))
        (cons 'delay-control-delay-control-id (list (cons 'raw delay-control-delay-control-id) (cons 'formatted (fmt-hex delay-control-delay-control-id))))
        (cons 'delay-control-delay-a (list (cons 'raw delay-control-delay-a) (cons 'formatted (number->string delay-control-delay-a))))
        (cons 'delay-control-delay-b (list (cons 'raw delay-control-delay-b) (cons 'formatted (number->string delay-control-delay-b))))
        )))

    (catch (e)
      (err (str "ECPRI parse error: " e)))))

;; dissect-ecpri: parse ECPRI from bytevector
;; Returns (ok fields-alist) or (err message)