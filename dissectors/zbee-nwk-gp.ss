;; packet-zbee-nwk-gp.c
;; Dissector routines for the ZigBee Green Power profile (GP)
;; Copyright 2013 DSR Corporation, http://dsr-wireless.com/
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Used Owen Kirby's packet-zbee-aps module as a template. Based
;; on ZigBee Cluster Library Specification document 075123r02ZB
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/zbee-nwk-gp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-zbee_nwk_gp.c

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
(def (dissect-zbee-nwk-gp buffer)
  "ZigBee Green Power Profile"
  (try
    (let* (
           (nwk-gp-fcf (unwrap (read-u8 buffer 0)))
           (nwk-gp-proto-version (extract-bits nwk-gp-fcf 0x0 0))
           (nwk-gp-auto-commissioning (extract-bits nwk-gp-fcf 0x0 0))
           (nwk-gp-fc-ext (extract-bits nwk-gp-fcf 0x0 0))
           (nwk-gp-cmd-comm-opt (unwrap (read-u8 buffer 1)))
           (nwk-gp-fc-ext-field (unwrap (read-u8 buffer 1)))
           (nwk-gp-fc-ext-sec-key (extract-bits nwk-gp-fc-ext-field 0x0 0))
           (nwk-gp-fc-ext-rx-after-tx (extract-bits nwk-gp-fc-ext-field 0x0 0))
           (nwk-gp-cmd-comm-ext-opt (unwrap (read-u8 buffer 2)))
           (nwk-gp-cmd-comm-ext-opt-sec-level-cap (extract-bits nwk-gp-cmd-comm-ext-opt 0x0 0))
           (nwk-gp-cmd-comm-ext-opt-gpd-key-present (extract-bits nwk-gp-cmd-comm-ext-opt 0x0 0))
           (nwk-gp-cmd-comm-ext-opt-gpd-key-encr (extract-bits nwk-gp-cmd-comm-ext-opt 0x0 0))
           (nwk-gp-cmd-comm-ext-opt-outgoing-counter (extract-bits nwk-gp-cmd-comm-ext-opt 0x0 0))
           (nwk-gp-zgpd-endpoint (unwrap (read-u8 buffer 6)))
           (nwk-gp-cmd-comm-outgoing-counter (unwrap (read-u32be buffer 7)))
           (nwk-gp-security-frame-counter (unwrap (read-u32be buffer 7)))
           (nwk-gp-cmd-comm-appli-info (unwrap (read-u8 buffer 11)))
           (nwk-gp-cmd-comm-appli-info-mip (extract-bits nwk-gp-cmd-comm-appli-info 0x0 0))
           (nwk-gp-cmd-comm-appli-info-mmip (extract-bits nwk-gp-cmd-comm-appli-info 0x0 0))
           (nwk-gp-cmd-comm-appli-info-gclp (extract-bits nwk-gp-cmd-comm-appli-info 0x0 0))
           (nwk-gp-cmd-comm-appli-info-crp (extract-bits nwk-gp-cmd-comm-appli-info 0x0 0))
           (nwk-gp-cmd-comm-manufacturer-dev-id (unwrap (read-u16be buffer 16)))
           (nwk-gp-cmd-comm-gpd-cmd-num (unwrap (read-u8 buffer 18)))
           (nwk-gp-cmd-comm-length-of-clid-list (unwrap (read-u8 buffer 19)))
           (nwk-gp-cmd-comm-length-of-clid-list-server (extract-bits nwk-gp-cmd-comm-length-of-clid-list 0x0 0))
           (nwk-gp-cmd-comm-length-of-clid-list-client (extract-bits nwk-gp-cmd-comm-length-of-clid-list 0x0 0))
           (nwk-cmd-comm-cluster-id (unwrap (read-u16be buffer 24)))
           (nwk-gp-cmd-channel-request-toggling-behaviour (unwrap (read-u8 buffer 24)))
           (nwk-gp-cmd-operational-channel (unwrap (read-u8 buffer 25)))
           (nwk-gp-cmd-channel-configuration (extract-bits nwk-gp-cmd-operational-channel 0x0 0))
           (nwk-gp-cmd-comm-rep-opt (unwrap (read-u8 buffer 30)))
           (nwk-gp-cmd-comm-rep-pan-id (unwrap (read-u16be buffer 31)))
           (nwk-gp-cmd-comm-security-key (unwrap (slice buffer 33 1)))
           (nwk-gp-cmd-comm-gpd-sec-key-mic (unwrap (read-u32be buffer 33)))
           (nwk-gp-cmd-comm-rep-frame-counter (unwrap (read-u32be buffer 37)))
           (nwk-gp-cmd-read-att-opt (unwrap (read-u8 buffer 53)))
           (nwk-gp-cmd-read-att-record-len (unwrap (read-u8 buffer 58)))
           (nwk-gp-cmd-zcl-tunnel-opt (unwrap (read-u8 buffer 59)))
           (nwk-gp-cmd-zcl-tunnel-opt-frame-type (extract-bits nwk-gp-cmd-zcl-tunnel-opt 0x0 0))
           (nwk-gp-cmd-zcl-tunnel-opt-man-field-present (extract-bits nwk-gp-cmd-zcl-tunnel-opt 0x0 0))
           (nwk-gp-cmd-zcl-tunnel-opt-direction (extract-bits nwk-gp-cmd-zcl-tunnel-opt 0x0 0))
           (nwk-gp-cmd-zcl-tunnel-command-id (unwrap (read-u8 buffer 64)))
           (nwk-gp-cmd-zcl-tunnel-payload-len (unwrap (read-u8 buffer 65)))
           (nwk-gp-cmd-move-color-ratex (unwrap (read-u16be buffer 70)))
           (nwk-gp-cmd-move-color-ratey (unwrap (read-u16be buffer 72)))
           (nwk-gp-cmd-move-up-down-rate (unwrap (read-u8 buffer 74)))
           (nwk-gp-cmd-step-color-stepx (unwrap (read-u16be buffer 75)))
           (nwk-gp-cmd-step-color-stepy (unwrap (read-u16be buffer 77)))
           (nwk-gp-cmd-step-color-transition-time (unwrap (read-u16be buffer 79)))
           (nwk-gp-cmd-step-up-down-step-size (unwrap (read-u8 buffer 81)))
           (nwk-gp-cmd-step-up-down-transition-time (unwrap (read-u16be buffer 82)))
           )

      (ok (list
        (cons 'nwk-gp-fcf (list (cons 'raw nwk-gp-fcf) (cons 'formatted (fmt-hex nwk-gp-fcf))))
        (cons 'nwk-gp-proto-version (list (cons 'raw nwk-gp-proto-version) (cons 'formatted (if (= nwk-gp-proto-version 0) "Not set" "Set"))))
        (cons 'nwk-gp-auto-commissioning (list (cons 'raw nwk-gp-auto-commissioning) (cons 'formatted (if (= nwk-gp-auto-commissioning 0) "Not set" "Set"))))
        (cons 'nwk-gp-fc-ext (list (cons 'raw nwk-gp-fc-ext) (cons 'formatted (if (= nwk-gp-fc-ext 0) "Not set" "Set"))))
        (cons 'nwk-gp-cmd-comm-opt (list (cons 'raw nwk-gp-cmd-comm-opt) (cons 'formatted (fmt-hex nwk-gp-cmd-comm-opt))))
        (cons 'nwk-gp-fc-ext-field (list (cons 'raw nwk-gp-fc-ext-field) (cons 'formatted (fmt-hex nwk-gp-fc-ext-field))))
        (cons 'nwk-gp-fc-ext-sec-key (list (cons 'raw nwk-gp-fc-ext-sec-key) (cons 'formatted (if (= nwk-gp-fc-ext-sec-key 0) "Not set" "Set"))))
        (cons 'nwk-gp-fc-ext-rx-after-tx (list (cons 'raw nwk-gp-fc-ext-rx-after-tx) (cons 'formatted (if (= nwk-gp-fc-ext-rx-after-tx 0) "Not set" "Set"))))
        (cons 'nwk-gp-cmd-comm-ext-opt (list (cons 'raw nwk-gp-cmd-comm-ext-opt) (cons 'formatted (fmt-hex nwk-gp-cmd-comm-ext-opt))))
        (cons 'nwk-gp-cmd-comm-ext-opt-sec-level-cap (list (cons 'raw nwk-gp-cmd-comm-ext-opt-sec-level-cap) (cons 'formatted (if (= nwk-gp-cmd-comm-ext-opt-sec-level-cap 0) "Not set" "Set"))))
        (cons 'nwk-gp-cmd-comm-ext-opt-gpd-key-present (list (cons 'raw nwk-gp-cmd-comm-ext-opt-gpd-key-present) (cons 'formatted (if (= nwk-gp-cmd-comm-ext-opt-gpd-key-present 0) "Not set" "Set"))))
        (cons 'nwk-gp-cmd-comm-ext-opt-gpd-key-encr (list (cons 'raw nwk-gp-cmd-comm-ext-opt-gpd-key-encr) (cons 'formatted (if (= nwk-gp-cmd-comm-ext-opt-gpd-key-encr 0) "Not set" "Set"))))
        (cons 'nwk-gp-cmd-comm-ext-opt-outgoing-counter (list (cons 'raw nwk-gp-cmd-comm-ext-opt-outgoing-counter) (cons 'formatted (if (= nwk-gp-cmd-comm-ext-opt-outgoing-counter 0) "Not set" "Set"))))
        (cons 'nwk-gp-zgpd-endpoint (list (cons 'raw nwk-gp-zgpd-endpoint) (cons 'formatted (number->string nwk-gp-zgpd-endpoint))))
        (cons 'nwk-gp-cmd-comm-outgoing-counter (list (cons 'raw nwk-gp-cmd-comm-outgoing-counter) (cons 'formatted (fmt-hex nwk-gp-cmd-comm-outgoing-counter))))
        (cons 'nwk-gp-security-frame-counter (list (cons 'raw nwk-gp-security-frame-counter) (cons 'formatted (number->string nwk-gp-security-frame-counter))))
        (cons 'nwk-gp-cmd-comm-appli-info (list (cons 'raw nwk-gp-cmd-comm-appli-info) (cons 'formatted (fmt-hex nwk-gp-cmd-comm-appli-info))))
        (cons 'nwk-gp-cmd-comm-appli-info-mip (list (cons 'raw nwk-gp-cmd-comm-appli-info-mip) (cons 'formatted (if (= nwk-gp-cmd-comm-appli-info-mip 0) "Not set" "Set"))))
        (cons 'nwk-gp-cmd-comm-appli-info-mmip (list (cons 'raw nwk-gp-cmd-comm-appli-info-mmip) (cons 'formatted (if (= nwk-gp-cmd-comm-appli-info-mmip 0) "Not set" "Set"))))
        (cons 'nwk-gp-cmd-comm-appli-info-gclp (list (cons 'raw nwk-gp-cmd-comm-appli-info-gclp) (cons 'formatted (if (= nwk-gp-cmd-comm-appli-info-gclp 0) "Not set" "Set"))))
        (cons 'nwk-gp-cmd-comm-appli-info-crp (list (cons 'raw nwk-gp-cmd-comm-appli-info-crp) (cons 'formatted (if (= nwk-gp-cmd-comm-appli-info-crp 0) "Not set" "Set"))))
        (cons 'nwk-gp-cmd-comm-manufacturer-dev-id (list (cons 'raw nwk-gp-cmd-comm-manufacturer-dev-id) (cons 'formatted (fmt-hex nwk-gp-cmd-comm-manufacturer-dev-id))))
        (cons 'nwk-gp-cmd-comm-gpd-cmd-num (list (cons 'raw nwk-gp-cmd-comm-gpd-cmd-num) (cons 'formatted (number->string nwk-gp-cmd-comm-gpd-cmd-num))))
        (cons 'nwk-gp-cmd-comm-length-of-clid-list (list (cons 'raw nwk-gp-cmd-comm-length-of-clid-list) (cons 'formatted (fmt-hex nwk-gp-cmd-comm-length-of-clid-list))))
        (cons 'nwk-gp-cmd-comm-length-of-clid-list-server (list (cons 'raw nwk-gp-cmd-comm-length-of-clid-list-server) (cons 'formatted (if (= nwk-gp-cmd-comm-length-of-clid-list-server 0) "Not set" "Set"))))
        (cons 'nwk-gp-cmd-comm-length-of-clid-list-client (list (cons 'raw nwk-gp-cmd-comm-length-of-clid-list-client) (cons 'formatted (if (= nwk-gp-cmd-comm-length-of-clid-list-client 0) "Not set" "Set"))))
        (cons 'nwk-cmd-comm-cluster-id (list (cons 'raw nwk-cmd-comm-cluster-id) (cons 'formatted (fmt-hex nwk-cmd-comm-cluster-id))))
        (cons 'nwk-gp-cmd-channel-request-toggling-behaviour (list (cons 'raw nwk-gp-cmd-channel-request-toggling-behaviour) (cons 'formatted (fmt-hex nwk-gp-cmd-channel-request-toggling-behaviour))))
        (cons 'nwk-gp-cmd-operational-channel (list (cons 'raw nwk-gp-cmd-operational-channel) (cons 'formatted (fmt-hex nwk-gp-cmd-operational-channel))))
        (cons 'nwk-gp-cmd-channel-configuration (list (cons 'raw nwk-gp-cmd-channel-configuration) (cons 'formatted (if (= nwk-gp-cmd-channel-configuration 0) "Not set" "Set"))))
        (cons 'nwk-gp-cmd-comm-rep-opt (list (cons 'raw nwk-gp-cmd-comm-rep-opt) (cons 'formatted (fmt-hex nwk-gp-cmd-comm-rep-opt))))
        (cons 'nwk-gp-cmd-comm-rep-pan-id (list (cons 'raw nwk-gp-cmd-comm-rep-pan-id) (cons 'formatted (fmt-hex nwk-gp-cmd-comm-rep-pan-id))))
        (cons 'nwk-gp-cmd-comm-security-key (list (cons 'raw nwk-gp-cmd-comm-security-key) (cons 'formatted (fmt-bytes nwk-gp-cmd-comm-security-key))))
        (cons 'nwk-gp-cmd-comm-gpd-sec-key-mic (list (cons 'raw nwk-gp-cmd-comm-gpd-sec-key-mic) (cons 'formatted (fmt-hex nwk-gp-cmd-comm-gpd-sec-key-mic))))
        (cons 'nwk-gp-cmd-comm-rep-frame-counter (list (cons 'raw nwk-gp-cmd-comm-rep-frame-counter) (cons 'formatted (fmt-hex nwk-gp-cmd-comm-rep-frame-counter))))
        (cons 'nwk-gp-cmd-read-att-opt (list (cons 'raw nwk-gp-cmd-read-att-opt) (cons 'formatted (fmt-hex nwk-gp-cmd-read-att-opt))))
        (cons 'nwk-gp-cmd-read-att-record-len (list (cons 'raw nwk-gp-cmd-read-att-record-len) (cons 'formatted (number->string nwk-gp-cmd-read-att-record-len))))
        (cons 'nwk-gp-cmd-zcl-tunnel-opt (list (cons 'raw nwk-gp-cmd-zcl-tunnel-opt) (cons 'formatted (fmt-hex nwk-gp-cmd-zcl-tunnel-opt))))
        (cons 'nwk-gp-cmd-zcl-tunnel-opt-frame-type (list (cons 'raw nwk-gp-cmd-zcl-tunnel-opt-frame-type) (cons 'formatted (if (= nwk-gp-cmd-zcl-tunnel-opt-frame-type 0) "Not set" "Set"))))
        (cons 'nwk-gp-cmd-zcl-tunnel-opt-man-field-present (list (cons 'raw nwk-gp-cmd-zcl-tunnel-opt-man-field-present) (cons 'formatted (if (= nwk-gp-cmd-zcl-tunnel-opt-man-field-present 0) "Not set" "Set"))))
        (cons 'nwk-gp-cmd-zcl-tunnel-opt-direction (list (cons 'raw nwk-gp-cmd-zcl-tunnel-opt-direction) (cons 'formatted (if (= nwk-gp-cmd-zcl-tunnel-opt-direction 0) "Not set" "Set"))))
        (cons 'nwk-gp-cmd-zcl-tunnel-command-id (list (cons 'raw nwk-gp-cmd-zcl-tunnel-command-id) (cons 'formatted (fmt-hex nwk-gp-cmd-zcl-tunnel-command-id))))
        (cons 'nwk-gp-cmd-zcl-tunnel-payload-len (list (cons 'raw nwk-gp-cmd-zcl-tunnel-payload-len) (cons 'formatted (number->string nwk-gp-cmd-zcl-tunnel-payload-len))))
        (cons 'nwk-gp-cmd-move-color-ratex (list (cons 'raw nwk-gp-cmd-move-color-ratex) (cons 'formatted (number->string nwk-gp-cmd-move-color-ratex))))
        (cons 'nwk-gp-cmd-move-color-ratey (list (cons 'raw nwk-gp-cmd-move-color-ratey) (cons 'formatted (number->string nwk-gp-cmd-move-color-ratey))))
        (cons 'nwk-gp-cmd-move-up-down-rate (list (cons 'raw nwk-gp-cmd-move-up-down-rate) (cons 'formatted (number->string nwk-gp-cmd-move-up-down-rate))))
        (cons 'nwk-gp-cmd-step-color-stepx (list (cons 'raw nwk-gp-cmd-step-color-stepx) (cons 'formatted (number->string nwk-gp-cmd-step-color-stepx))))
        (cons 'nwk-gp-cmd-step-color-stepy (list (cons 'raw nwk-gp-cmd-step-color-stepy) (cons 'formatted (number->string nwk-gp-cmd-step-color-stepy))))
        (cons 'nwk-gp-cmd-step-color-transition-time (list (cons 'raw nwk-gp-cmd-step-color-transition-time) (cons 'formatted (number->string nwk-gp-cmd-step-color-transition-time))))
        (cons 'nwk-gp-cmd-step-up-down-step-size (list (cons 'raw nwk-gp-cmd-step-up-down-step-size) (cons 'formatted (number->string nwk-gp-cmd-step-up-down-step-size))))
        (cons 'nwk-gp-cmd-step-up-down-transition-time (list (cons 'raw nwk-gp-cmd-step-up-down-transition-time) (cons 'formatted (number->string nwk-gp-cmd-step-up-down-transition-time))))
        )))

    (catch (e)
      (err (str "ZBEE-NWK-GP parse error: " e)))))

;; dissect-zbee-nwk-gp: parse ZBEE-NWK-GP from bytevector
;; Returns (ok fields-alist) or (err message)