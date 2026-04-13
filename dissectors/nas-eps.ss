;; packet-nas_eps.c
;; Routines for Non-Access-Stratum (NAS) protocol for Evolved Packet System (EPS) dissection
;;
;; Copyright 2008 - 2020, Anders Broman <anders.broman@ericsson.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; References: 3GPP TS 24.301 V19.5.0 (2025-12)
;;

;; jerboa-ethereal/dissectors/nas-eps.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nas_eps.c

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
(def (dissect-nas-eps buffer)
  "Non-Access-Stratum (NAS)PDU"
  (try
    (let* (
           (eps-cmn-add-info (unwrap (slice buffer 0 1)))
           (eps-deciphered-msg (unwrap (slice buffer 0 1)))
           (eps-seq-no (unwrap (read-u8 buffer 0)))
           (eps-msg-auth-code (unwrap (read-u32be buffer 4)))
           (eps-ciphered-msg (unwrap (slice buffer 8 1)))
           (eps-gen-msg-cont (unwrap (slice buffer 51 1)))
           (eps-hash-mme (unwrap (slice buffer 54 8)))
           (eps-replayed-nas-msg-cont (unwrap (slice buffer 54 1)))
           (eps-redir-policy (unwrap (read-u8 buffer 54)))
           (eps-emm-cipher-key (unwrap (read-u8 buffer 54)))
           (eps-emm-ue-radio-cap-id-request (unwrap (read-u8 buffer 79)))
           (eps-emm-imsi-offset (unwrap (read-u16be buffer 79)))
           (eps-emm-ue-info-req-uclir (unwrap (read-u8 buffer 93)))
           (eps-emm-sf-sat-op-params-esfudtpi (unwrap (read-u8 buffer 93)))
           (eps-emm-sf-sat-op-params-sfwtpi (unwrap (read-u8 buffer 93)))
           (eps-emm-sf-sat-op-params-sf-mon-list-nb-sat-id (unwrap (read-u8 buffer 98)))
           (eps-emm-sf-sat-op-params-sf-mon-list-sat-id (unwrap (read-u8 buffer 98)))
           (eps-esm-eplmnc (unwrap (read-u8 buffer 126)))
           (eps-esm-ratc (unwrap (read-u8 buffer 126)))
           (eps-esm-nbifom-cont (unwrap (slice buffer 126 1)))
           (eps-esm-user-data-cont (unwrap (slice buffer 166 1)))
           (eps-esm-serv-plmn-rate-ctrl-val (unwrap (read-u16be buffer 166)))
           (eps-esm-proc-trans-id (unwrap (read-u8 buffer 293)))
           (eps-msg-elems (unwrap (slice buffer 297 1)))
           )

      (ok (list
        (cons 'eps-cmn-add-info (list (cons 'raw eps-cmn-add-info) (cons 'formatted (fmt-bytes eps-cmn-add-info))))
        (cons 'eps-deciphered-msg (list (cons 'raw eps-deciphered-msg) (cons 'formatted (fmt-bytes eps-deciphered-msg))))
        (cons 'eps-seq-no (list (cons 'raw eps-seq-no) (cons 'formatted (number->string eps-seq-no))))
        (cons 'eps-msg-auth-code (list (cons 'raw eps-msg-auth-code) (cons 'formatted (fmt-hex eps-msg-auth-code))))
        (cons 'eps-ciphered-msg (list (cons 'raw eps-ciphered-msg) (cons 'formatted (fmt-bytes eps-ciphered-msg))))
        (cons 'eps-gen-msg-cont (list (cons 'raw eps-gen-msg-cont) (cons 'formatted (fmt-bytes eps-gen-msg-cont))))
        (cons 'eps-hash-mme (list (cons 'raw eps-hash-mme) (cons 'formatted (fmt-bytes eps-hash-mme))))
        (cons 'eps-replayed-nas-msg-cont (list (cons 'raw eps-replayed-nas-msg-cont) (cons 'formatted (fmt-bytes eps-replayed-nas-msg-cont))))
        (cons 'eps-redir-policy (list (cons 'raw eps-redir-policy) (cons 'formatted (if (= eps-redir-policy 0) "Unsecured redirection to GERAN or UTRAN allowed" "Unsecured redirection to GERAN or UTRAN not allowed"))))
        (cons 'eps-emm-cipher-key (list (cons 'raw eps-emm-cipher-key) (cons 'formatted (if (= eps-emm-cipher-key 0) "False" "True"))))
        (cons 'eps-emm-ue-radio-cap-id-request (list (cons 'raw eps-emm-ue-radio-cap-id-request) (cons 'formatted (if (= eps-emm-ue-radio-cap-id-request 0) "False" "True"))))
        (cons 'eps-emm-imsi-offset (list (cons 'raw eps-emm-imsi-offset) (cons 'formatted (number->string eps-emm-imsi-offset))))
        (cons 'eps-emm-ue-info-req-uclir (list (cons 'raw eps-emm-ue-info-req-uclir) (cons 'formatted (if (= eps-emm-ue-info-req-uclir 0) "False" "True"))))
        (cons 'eps-emm-sf-sat-op-params-esfudtpi (list (cons 'raw eps-emm-sf-sat-op-params-esfudtpi) (cons 'formatted (if (= eps-emm-sf-sat-op-params-esfudtpi 0) "False" "True"))))
        (cons 'eps-emm-sf-sat-op-params-sfwtpi (list (cons 'raw eps-emm-sf-sat-op-params-sfwtpi) (cons 'formatted (if (= eps-emm-sf-sat-op-params-sfwtpi 0) "False" "True"))))
        (cons 'eps-emm-sf-sat-op-params-sf-mon-list-nb-sat-id (list (cons 'raw eps-emm-sf-sat-op-params-sf-mon-list-nb-sat-id) (cons 'formatted (number->string eps-emm-sf-sat-op-params-sf-mon-list-nb-sat-id))))
        (cons 'eps-emm-sf-sat-op-params-sf-mon-list-sat-id (list (cons 'raw eps-emm-sf-sat-op-params-sf-mon-list-sat-id) (cons 'formatted (number->string eps-emm-sf-sat-op-params-sf-mon-list-sat-id))))
        (cons 'eps-esm-eplmnc (list (cons 'raw eps-esm-eplmnc) (cons 'formatted (if (= eps-esm-eplmnc 0) "UE is allowed to re-attempt the procedure in an equivalent PLMN" "UE is not allowed to re-attempt the procedure in an equivalent PLMN"))))
        (cons 'eps-esm-ratc (list (cons 'raw eps-esm-ratc) (cons 'formatted (if (= eps-esm-ratc 0) "UE is allowed to re-attempt the procedure in A/Gb mode or Iu mode or N1 mode" "UE is not allowed to re-attempt the procedure in A/Gb mode or Iu mode or N1 mode"))))
        (cons 'eps-esm-nbifom-cont (list (cons 'raw eps-esm-nbifom-cont) (cons 'formatted (fmt-bytes eps-esm-nbifom-cont))))
        (cons 'eps-esm-user-data-cont (list (cons 'raw eps-esm-user-data-cont) (cons 'formatted (fmt-bytes eps-esm-user-data-cont))))
        (cons 'eps-esm-serv-plmn-rate-ctrl-val (list (cons 'raw eps-esm-serv-plmn-rate-ctrl-val) (cons 'formatted (number->string eps-esm-serv-plmn-rate-ctrl-val))))
        (cons 'eps-esm-proc-trans-id (list (cons 'raw eps-esm-proc-trans-id) (cons 'formatted (number->string eps-esm-proc-trans-id))))
        (cons 'eps-msg-elems (list (cons 'raw eps-msg-elems) (cons 'formatted (fmt-bytes eps-msg-elems))))
        )))

    (catch (e)
      (err (str "NAS-EPS parse error: " e)))))

;; dissect-nas-eps: parse NAS-EPS from bytevector
;; Returns (ok fields-alist) or (err message)