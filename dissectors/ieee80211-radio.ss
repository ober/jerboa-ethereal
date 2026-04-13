;; packet-ieee80211-radio.c
;; Routines for pseudo 802.11 header dissection and radio packet timing calculation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copyright 2012 Parc Inc and Samsung Electronics
;; Copyright 2015, 2016 & 2017 Cisco Inc
;;
;; Copied from README.developer
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ieee80211-radio.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ieee80211_radio.c

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
(def (dissect-ieee80211-radio buffer)
  "802.11 radio information"
  (try
    (let* (
           (a-mpdu-aggregate-id (unwrap (read-u32be buffer 0)))
           (a-mpdu-delim-crc-error (unwrap (read-u8 buffer 0)))
           (last-part-of-a-mpdu (unwrap (read-u8 buffer 0)))
           (radio-timestamp (unwrap (read-u64be buffer 0)))
           (radio-channel (unwrap (read-u32be buffer 0)))
           (radio-data-rate (unwrap (read-u32be buffer 0)))
           (radio-11be-nsts (unwrap (read-u32be buffer 0)))
           (radio-11be-mcs (unwrap (read-u32be buffer 0)))
           (radio-11ax-mcs (unwrap (read-u32be buffer 0)))
           (radio-11ax-short-gi (unwrap (read-u8 buffer 0)))
           (radio-11ac-p-aid (unwrap (read-u16be buffer 0)))
           (radio-11ac-gid (unwrap (read-u32be buffer 0)))
           (radio-11ac-nsts (unwrap (read-u32be buffer 0)))
           (radio-11ac-nss (unwrap (read-u32be buffer 0)))
           (radio-11ac-mcs (unwrap (read-u32be buffer 0)))
           (radio-11ac-beamformed (unwrap (read-u8 buffer 0)))
           (radio-11ac-ldpc-extra-ofdm-symbol (unwrap (read-u8 buffer 0)))
           (radio-11ac-short-gi-nsym-disambig (unwrap (read-u8 buffer 0)))
           (radio-11ac-txop-ps-not-allowed (unwrap (read-u8 buffer 0)))
           (radio-11ac-stbc (unwrap (read-u8 buffer 0)))
           (radio-11ac-short-gi (unwrap (read-u8 buffer 0)))
           (radio-11n-ness (unwrap (read-u32be buffer 0)))
           (radio-11n-stbc-streams (unwrap (read-u32be buffer 0)))
           (radio-11n-greenfield (unwrap (read-u8 buffer 0)))
           (radio-11n-short-gi (unwrap (read-u8 buffer 0)))
           (radio-11n-mcs-index (unwrap (read-u32be buffer 0)))
           (radio-short-preamble (unwrap (read-u8 buffer 0)))
           (radio-11-fhss-hop-index (unwrap (read-u8 buffer 0)))
           (radio-11-fhss-hop-pattern (unwrap (read-u8 buffer 0)))
           (radio-11-fhss-hop-set (unwrap (read-u8 buffer 0)))
           )

      (ok (list
        (cons 'a-mpdu-aggregate-id (list (cons 'raw a-mpdu-aggregate-id) (cons 'formatted (number->string a-mpdu-aggregate-id))))
        (cons 'a-mpdu-delim-crc-error (list (cons 'raw a-mpdu-delim-crc-error) (cons 'formatted (number->string a-mpdu-delim-crc-error))))
        (cons 'last-part-of-a-mpdu (list (cons 'raw last-part-of-a-mpdu) (cons 'formatted (number->string last-part-of-a-mpdu))))
        (cons 'radio-timestamp (list (cons 'raw radio-timestamp) (cons 'formatted (number->string radio-timestamp))))
        (cons 'radio-channel (list (cons 'raw radio-channel) (cons 'formatted (number->string radio-channel))))
        (cons 'radio-data-rate (list (cons 'raw radio-data-rate) (cons 'formatted (number->string radio-data-rate))))
        (cons 'radio-11be-nsts (list (cons 'raw radio-11be-nsts) (cons 'formatted (number->string radio-11be-nsts))))
        (cons 'radio-11be-mcs (list (cons 'raw radio-11be-mcs) (cons 'formatted (number->string radio-11be-mcs))))
        (cons 'radio-11ax-mcs (list (cons 'raw radio-11ax-mcs) (cons 'formatted (number->string radio-11ax-mcs))))
        (cons 'radio-11ax-short-gi (list (cons 'raw radio-11ax-short-gi) (cons 'formatted (number->string radio-11ax-short-gi))))
        (cons 'radio-11ac-p-aid (list (cons 'raw radio-11ac-p-aid) (cons 'formatted (number->string radio-11ac-p-aid))))
        (cons 'radio-11ac-gid (list (cons 'raw radio-11ac-gid) (cons 'formatted (number->string radio-11ac-gid))))
        (cons 'radio-11ac-nsts (list (cons 'raw radio-11ac-nsts) (cons 'formatted (number->string radio-11ac-nsts))))
        (cons 'radio-11ac-nss (list (cons 'raw radio-11ac-nss) (cons 'formatted (number->string radio-11ac-nss))))
        (cons 'radio-11ac-mcs (list (cons 'raw radio-11ac-mcs) (cons 'formatted (number->string radio-11ac-mcs))))
        (cons 'radio-11ac-beamformed (list (cons 'raw radio-11ac-beamformed) (cons 'formatted (number->string radio-11ac-beamformed))))
        (cons 'radio-11ac-ldpc-extra-ofdm-symbol (list (cons 'raw radio-11ac-ldpc-extra-ofdm-symbol) (cons 'formatted (number->string radio-11ac-ldpc-extra-ofdm-symbol))))
        (cons 'radio-11ac-short-gi-nsym-disambig (list (cons 'raw radio-11ac-short-gi-nsym-disambig) (cons 'formatted (number->string radio-11ac-short-gi-nsym-disambig))))
        (cons 'radio-11ac-txop-ps-not-allowed (list (cons 'raw radio-11ac-txop-ps-not-allowed) (cons 'formatted (number->string radio-11ac-txop-ps-not-allowed))))
        (cons 'radio-11ac-stbc (list (cons 'raw radio-11ac-stbc) (cons 'formatted (if (= radio-11ac-stbc 0) "False" "True"))))
        (cons 'radio-11ac-short-gi (list (cons 'raw radio-11ac-short-gi) (cons 'formatted (number->string radio-11ac-short-gi))))
        (cons 'radio-11n-ness (list (cons 'raw radio-11n-ness) (cons 'formatted (number->string radio-11n-ness))))
        (cons 'radio-11n-stbc-streams (list (cons 'raw radio-11n-stbc-streams) (cons 'formatted (number->string radio-11n-stbc-streams))))
        (cons 'radio-11n-greenfield (list (cons 'raw radio-11n-greenfield) (cons 'formatted (number->string radio-11n-greenfield))))
        (cons 'radio-11n-short-gi (list (cons 'raw radio-11n-short-gi) (cons 'formatted (number->string radio-11n-short-gi))))
        (cons 'radio-11n-mcs-index (list (cons 'raw radio-11n-mcs-index) (cons 'formatted (number->string radio-11n-mcs-index))))
        (cons 'radio-short-preamble (list (cons 'raw radio-short-preamble) (cons 'formatted (number->string radio-short-preamble))))
        (cons 'radio-11-fhss-hop-index (list (cons 'raw radio-11-fhss-hop-index) (cons 'formatted (fmt-hex radio-11-fhss-hop-index))))
        (cons 'radio-11-fhss-hop-pattern (list (cons 'raw radio-11-fhss-hop-pattern) (cons 'formatted (fmt-hex radio-11-fhss-hop-pattern))))
        (cons 'radio-11-fhss-hop-set (list (cons 'raw radio-11-fhss-hop-set) (cons 'formatted (fmt-hex radio-11-fhss-hop-set))))
        )))

    (catch (e)
      (err (str "IEEE80211-RADIO parse error: " e)))))

;; dissect-ieee80211-radio: parse IEEE80211-RADIO from bytevector
;; Returns (ok fields-alist) or (err message)