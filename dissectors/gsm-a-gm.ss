;; packet-gsm_a_gm.c
;; Routines for GSM A Interface GPRS Mobility Management and GPRS Session Management
;;
;; Copyright 2003, Michael Lum <mlum [AT] telostech.com>
;; In association with Telos Technology Inc.
;;
;; Added the GPRS Mobility Management Protocol and
;; the GPRS Session Management Protocol
;; Copyright 2004, Rene Pilz <rene.pilz [AT] ftw.com>
;; In association with Telecommunications Research Center
;; Vienna (ftw.)Betriebs-GmbH within the Project Metawin.
;;
;; Various updates, enhancements and fixes
;; Copyright 2009, Gerasimos Dimitriadis <dimeg [AT] intracom.gr>
;; In association with Intracom Telecom SA
;;
;; Title		3GPP			Other
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
;; (3GPP TS 24.008 version 11.7.0 Release 11)
;;
;; Reference [12]
;; Mobile radio interface Layer 3 specification;
;; Core network protocols;
;; Stage 3
;; (3GPP TS 24.008 version 12.10.0 Release 12)
;;
;; Reference [13]
;; Mobile radio interface Layer 3 specification;
;; Core network protocols;
;; Stage 3
;; (3GPP TS 24.008 version 13.8.0 Release 13)
;;
;; Reference [14]
;; Mobile radio interface Layer 3 specification;
;; Core network protocols;
;; Stage 3
;; (3GPP TS 24.008 version 14.6.0 Release 14)
;;
;; Reference [15]
;; Mobile radio interface Layer 3 specification;
;; Core network protocols;
;; Stage 3
;; (3GPP TS 24.008 version 15.6.0 Release 15)
;;
;; Reference [16]
;; Mobile radio interface Layer 3 specification;
;; Core network protocols;
;; Stage 3
;; (3GPP TS 24.008 version 16.6.0 Release 16)
;;
;; Reference [17]
;; Mobile radio interface Layer 3 specification;
;; Core network protocols;
;; Stage 3
;; (3GPP TS 24.008 version 17.8.0 Release 17)
;;
;; Reference [18]
;; Mobile radio interface Layer 3 specification;
;; Core network protocols;
;; Stage 3
;; (3GPP TS 24.008 version 18.8.0 Release 18)
;;
;; Reference [19]
;; Mobile radio interface Layer 3 specification;
;; Core network protocols;
;; Stage 3
;; (3GPP TS 24.008 version 19.5.0 Release 19)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/gsm-a-gm.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gsm_a_gm.c

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
(def (dissect-gsm-a-gm buffer)
  "GSM A-I/F GPRS Mobility and Session Management"
  (try
    (let* (
           (a-gm-fop (unwrap (read-u8 buffer 3)))
           (a-gm-tmsi-flag (unwrap (read-u8 buffer 3)))
           (a-gm-power-off (unwrap (read-u8 buffer 3)))
           (a-gm-for (unwrap (read-u8 buffer 84)))
           (a-gm-mac (unwrap (read-u32be buffer 110)))
           (a-gm-up-integ-ind (unwrap (read-u8 buffer 110)))
           (a-gm-dcn-id (unwrap (read-u16be buffer 110)))
           (a-gm-n3en-ind (unwrap (read-u8 buffer 110)))
           (a-gm-gprs-timer (unwrap (read-u8 buffer 110)))
           (a-gm-gprs-timer-value (unwrap (read-u8 buffer 110)))
           (a-gm-gprs-timer2-value (unwrap (read-u8 buffer 110)))
           (a-gm-gprs-timer3-value (unwrap (read-u8 buffer 110)))
           (a-sm-eplmnc (unwrap (read-u8 buffer 227)))
           (a-sm-ratc (unwrap (read-u8 buffer 227)))
           (a-sm-cause (unwrap (read-u8 buffer 227)))
           (a-sm-cause-2 (unwrap (read-u8 buffer 227)))
           (a-sm-ti-flag (unwrap (read-u8 buffer 227)))
           (a-sm-tdi (unwrap (read-u8 buffer 227)))
           (a-sm-enh-nsapi (unwrap (read-u8 buffer 347)))
           (a-sm-nbifom-cont (unwrap (slice buffer 347 1)))
           )

      (ok (list
        (cons 'a-gm-fop (list (cons 'raw a-gm-fop) (cons 'formatted (number->string a-gm-fop))))
        (cons 'a-gm-tmsi-flag (list (cons 'raw a-gm-tmsi-flag) (cons 'formatted (if (= a-gm-tmsi-flag 0) "no valid TMSI available" "valid TMSI available"))))
        (cons 'a-gm-power-off (list (cons 'raw a-gm-power-off) (cons 'formatted (if (= a-gm-power-off 0) "normal detach" "power switched off"))))
        (cons 'a-gm-for (list (cons 'raw a-gm-for) (cons 'formatted (number->string a-gm-for))))
        (cons 'a-gm-mac (list (cons 'raw a-gm-mac) (cons 'formatted (fmt-hex a-gm-mac))))
        (cons 'a-gm-up-integ-ind (list (cons 'raw a-gm-up-integ-ind) (cons 'formatted (if (= a-gm-up-integ-ind 0) "MS shall disable integrity protection of user plane data in LLC layer" "MS shall enable integrity protection of user plane data in LLC layer"))))
        (cons 'a-gm-dcn-id (list (cons 'raw a-gm-dcn-id) (cons 'formatted (fmt-hex a-gm-dcn-id))))
        (cons 'a-gm-n3en-ind (list (cons 'raw a-gm-n3en-ind) (cons 'formatted (if (= a-gm-n3en-ind 0) "Use of non-3GPP emergency numbers not permitted" "Use of non-3GPP emergency numbers permitted"))))
        (cons 'a-gm-gprs-timer (list (cons 'raw a-gm-gprs-timer) (cons 'formatted (fmt-hex a-gm-gprs-timer))))
        (cons 'a-gm-gprs-timer-value (list (cons 'raw a-gm-gprs-timer-value) (cons 'formatted (number->string a-gm-gprs-timer-value))))
        (cons 'a-gm-gprs-timer2-value (list (cons 'raw a-gm-gprs-timer2-value) (cons 'formatted (number->string a-gm-gprs-timer2-value))))
        (cons 'a-gm-gprs-timer3-value (list (cons 'raw a-gm-gprs-timer3-value) (cons 'formatted (number->string a-gm-gprs-timer3-value))))
        (cons 'a-sm-eplmnc (list (cons 'raw a-sm-eplmnc) (cons 'formatted (if (= a-sm-eplmnc 0) "MS is allowed to re-attempt the procedure in an equivalent PLMN" "MS is not allowed to re-attempt the procedure in an equivalent PLMN"))))
        (cons 'a-sm-ratc (list (cons 'raw a-sm-ratc) (cons 'formatted (if (= a-sm-ratc 0) "MS is allowed to re-attempt the procedure in S1 mode" "MS is not allowed to re-attempt the procedure in S1 mode"))))
        (cons 'a-sm-cause (list (cons 'raw a-sm-cause) (cons 'formatted (number->string a-sm-cause))))
        (cons 'a-sm-cause-2 (list (cons 'raw a-sm-cause-2) (cons 'formatted (number->string a-sm-cause-2))))
        (cons 'a-sm-ti-flag (list (cons 'raw a-sm-ti-flag) (cons 'formatted (if (= a-sm-ti-flag 0) "The message is sent from the side that originates the TI" "The message is sent to the side that originates the TI"))))
        (cons 'a-sm-tdi (list (cons 'raw a-sm-tdi) (cons 'formatted (if (= a-sm-tdi 0) "Tear down not requested" "Tear down requested"))))
        (cons 'a-sm-enh-nsapi (list (cons 'raw a-sm-enh-nsapi) (cons 'formatted (number->string a-sm-enh-nsapi))))
        (cons 'a-sm-nbifom-cont (list (cons 'raw a-sm-nbifom-cont) (cons 'formatted (fmt-bytes a-sm-nbifom-cont))))
        )))

    (catch (e)
      (err (str "GSM-A-GM parse error: " e)))))

;; dissect-gsm-a-gm: parse GSM-A-GM from bytevector
;; Returns (ok fields-alist) or (err message)