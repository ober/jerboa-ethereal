;; packet-gsm_a_dtap.c
;; Routines for GSM A Interface DTAP dissection - A.K.A. GSM layer 3
;; NOTE: it actually includes RR messages, which are (generally) not carried
;; over the A interface on DTAP, but are part of the same Layer 3 protocol set
;;
;; Copyright 2003, Michael Lum <mlum [AT] telostech.com>
;; In association with Telos Technology Inc.
;;
;;
;; Added the GPRS Mobility Management Protocol and
;; the GPRS Session Management Protocol
;; Copyright 2004, Rene Pilz <rene.pilz [AT] ftw.com>
;; In association with Telecommunications Research Center
;; Vienna (ftw.)Betriebs-GmbH within the Project Metawin.
;;
;; Added Dissection of Radio Resource Management Information Elements
;; and other enhancements and fixes.
;; Copyright 2005 - 2009, Anders Broman [AT] ericsson.com
;; Small bugfixes, mainly in Qos and TFT by Nils Ljungberg and Stefan Boman [AT] ericsson.com
;;
;; Various updates, enhancements and fixes
;; Copyright 2009, Gerasimos Dimitriadis <dimeg [AT] intracom.gr>
;; In association with Intracom Telecom SA
;;
;; Added Dissection of Group Call Control (GCC) protocol.
;; Added Dissection of Broadcast Call Control (BCC) protocol.
;; Copyright 2015, Michail Koreshkov <michail.koreshkov [at] zte.com.cn
;;
;; Title        3GPP            Other
;;
;; Reference [3]
;; Mobile radio interface Layer 3 specification;
;; Core network protocols;
;; Stage 3
;; (3GPP TS 24.008 version 4.7.0 Release 4)
;; (ETSI TS 124 008 V6.8.0 (2005-03))
;;
;; Reference [4]
;; Mobile radio interface layer 3 specification;
;; Radio Resource Control Protocol
;; (GSM 04.18 version 8.4.1 Release 1999)
;; (3GPP TS 04.18 version 8.26.0 Release 1999)
;;
;; Reference [5]
;; Point-to-Point (PP) Short Message Service (SMS)
;; support on mobile radio interface
;; (3GPP TS 24.011 version 4.1.1 Release 4)
;;
;; Reference [6]
;; Mobile radio Layer 3 supplementary service specification;
;; Formats and coding
;; (3GPP TS 24.080 version 4.3.0 Release 4)
;;
;; Reference [7]
;; Mobile radio interface Layer 3 specification;
;; Core network protocols;
;; Stage 3
;; (3GPP TS 24.008 version 5.9.0 Release 5)
;;
;; Reference [8]
;; Mobile radio interface Layer 3 specification;
;; Core network protocols;
;; Stage 3
;; (3GPP TS 24.008 version 6.7.0 Release 6)
;; (3GPP TS 24.008 version 6.8.0 Release 6)
;;
;; Reference [9]
;; Mobile radio interface Layer 3 specification;
;; Core network protocols;
;; Stage 3
;; (3GPP TS 24.008 version 9.6.0 Release 9)
;;
;; Reference [10]
;; Mobile radio interface Layer 3 specification;
;; Core network protocols;
;; Stage 3
;; (3GPP TS 24.008 version 10.6.1 Release 10)
;;
;; Reference [11]
;; Mobile radio interface Layer 3 specification;
;; Core network protocols;
;; Stage 3
;; (3GPP TS 24.008 version 11.6.0 Release 11)
;;
;; Reference [12]
;; Digital cellular telecommunications system (Phase 2+);
;; Group Call Control (GCC) protocol
;; (GSM 04.68 version 8.1.0 Release 1999)
;;
;; Reference [13]
;; Digital cellular telecommunications system (Phase 2+);
;; Broadcast Call Control (BCC) protocol
;; (3GPP TS 44.069 version 11.0.0 Release 11)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gsm-a-dtap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gsm_a_dtap.c

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
(def (dissect-gsm-a-dtap buffer)
  "GSM A-I/F DTAP"
  (try
    (let* (
           (a-dtap-tio (unwrap (read-u8 buffer 0)))
           (a-dtap-ti-flag (unwrap (read-u8 buffer 0)))
           (a-dtap-rej-cause (unwrap (read-u8 buffer 0)))
           (a-seq-no (unwrap (read-u8 buffer 0)))
           (a-dtap-message-elements (unwrap (slice buffer 0 1)))
           (a-dtap-tie (unwrap (read-u8 buffer 1)))
           (a-dtap-mm-timer (unwrap (read-u8 buffer 6)))
           (a-dtap-mm-timer-value (unwrap (read-u8 buffer 6)))
           (a-dtap-call-state (unwrap (read-u8 buffer 6)))
           (a-dtap-gcc-state-attr (unwrap (read-u8 buffer 58)))
           (a-dtap-gcc-state-attr-da (unwrap (read-u8 buffer 58)))
           (a-dtap-gcc-state-attr-ua (unwrap (read-u8 buffer 58)))
           (a-dtap-gcc-state-attr-comm (unwrap (read-u8 buffer 58)))
           (a-dtap-gcc-state-attr-oi (unwrap (read-u8 buffer 58)))
           (a-dtap-bcc-state-attr (unwrap (read-u8 buffer 62)))
           (a-dtap-bcc-state-attr-da (unwrap (read-u8 buffer 62)))
           (a-dtap-bcc-state-attr-ua (unwrap (read-u8 buffer 62)))
           (a-dtap-bcc-state-attr-comm (unwrap (read-u8 buffer 62)))
           (a-dtap-bcc-state-attr-oi (unwrap (read-u8 buffer 62)))
           (a-dtap-bcc-compr-otdi (unwrap (slice buffer 62 1)))
           )

      (ok (list
        (cons 'a-dtap-tio (list (cons 'raw a-dtap-tio) (cons 'formatted (number->string a-dtap-tio))))
        (cons 'a-dtap-ti-flag (list (cons 'raw a-dtap-ti-flag) (cons 'formatted (if (= a-dtap-ti-flag 0) "False" "True"))))
        (cons 'a-dtap-rej-cause (list (cons 'raw a-dtap-rej-cause) (cons 'formatted (number->string a-dtap-rej-cause))))
        (cons 'a-seq-no (list (cons 'raw a-seq-no) (cons 'formatted (number->string a-seq-no))))
        (cons 'a-dtap-message-elements (list (cons 'raw a-dtap-message-elements) (cons 'formatted (fmt-bytes a-dtap-message-elements))))
        (cons 'a-dtap-tie (list (cons 'raw a-dtap-tie) (cons 'formatted (number->string a-dtap-tie))))
        (cons 'a-dtap-mm-timer (list (cons 'raw a-dtap-mm-timer) (cons 'formatted (number->string a-dtap-mm-timer))))
        (cons 'a-dtap-mm-timer-value (list (cons 'raw a-dtap-mm-timer-value) (cons 'formatted (number->string a-dtap-mm-timer-value))))
        (cons 'a-dtap-call-state (list (cons 'raw a-dtap-call-state) (cons 'formatted (number->string a-dtap-call-state))))
        (cons 'a-dtap-gcc-state-attr (list (cons 'raw a-dtap-gcc-state-attr) (cons 'formatted (fmt-hex a-dtap-gcc-state-attr))))
        (cons 'a-dtap-gcc-state-attr-da (list (cons 'raw a-dtap-gcc-state-attr-da) (cons 'formatted (if (= a-dtap-gcc-state-attr-da 0) "User connection in the downlink not attached (D-ATT = F)" "User connection in the downlink attached (D-ATT = T)"))))
        (cons 'a-dtap-gcc-state-attr-ua (list (cons 'raw a-dtap-gcc-state-attr-ua) (cons 'formatted (if (= a-dtap-gcc-state-attr-ua 0) "User connection in the uplink not attached (U-ATT = F)" "User connection in the uplink attached (U-ATT = T)"))))
        (cons 'a-dtap-gcc-state-attr-comm (list (cons 'raw a-dtap-gcc-state-attr-comm) (cons 'formatted (if (= a-dtap-gcc-state-attr-comm 0) "Communication with its peer entity is not enabled in both directions (COMM = F)" "Communication with its peer entity is enabled in both directions  (COMM = T)"))))
        (cons 'a-dtap-gcc-state-attr-oi (list (cons 'raw a-dtap-gcc-state-attr-oi) (cons 'formatted (if (= a-dtap-gcc-state-attr-oi 0) "The MS is not the originator of the call (ORIG = F)" "The MS is the originator of the call (ORIG = T)"))))
        (cons 'a-dtap-bcc-state-attr (list (cons 'raw a-dtap-bcc-state-attr) (cons 'formatted (fmt-hex a-dtap-bcc-state-attr))))
        (cons 'a-dtap-bcc-state-attr-da (list (cons 'raw a-dtap-bcc-state-attr-da) (cons 'formatted (if (= a-dtap-bcc-state-attr-da 0) "User connection in the downlink not attached (D-ATT = F)" "User connection in the downlink attached (D-ATT = T)"))))
        (cons 'a-dtap-bcc-state-attr-ua (list (cons 'raw a-dtap-bcc-state-attr-ua) (cons 'formatted (if (= a-dtap-bcc-state-attr-ua 0) "User connection in the uplink not attached (U-ATT = F)" "User connection in the uplink attached (U-ATT = T)"))))
        (cons 'a-dtap-bcc-state-attr-comm (list (cons 'raw a-dtap-bcc-state-attr-comm) (cons 'formatted (if (= a-dtap-bcc-state-attr-comm 0) "Communication with its peer entity is not enabled in both directions (COMM = F)" "Communication with its peer entity is enabled in both directions  (COMM = T)"))))
        (cons 'a-dtap-bcc-state-attr-oi (list (cons 'raw a-dtap-bcc-state-attr-oi) (cons 'formatted (if (= a-dtap-bcc-state-attr-oi 0) "The MS is not the originator of the call (ORIG = F)" "The MS is the originator of the call (ORIG = T)"))))
        (cons 'a-dtap-bcc-compr-otdi (list (cons 'raw a-dtap-bcc-compr-otdi) (cons 'formatted (fmt-bytes a-dtap-bcc-compr-otdi))))
        )))

    (catch (e)
      (err (str "GSM-A-DTAP parse error: " e)))))

;; dissect-gsm-a-dtap: parse GSM-A-DTAP from bytevector
;; Returns (ok fields-alist) or (err message)