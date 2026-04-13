;;
;; packet-radius_packetcable.c
;;
;; Routines for Packetcable's RADIUS AVPs dissection
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;;

;; jerboa-ethereal/dissectors/radius-packetcable.ss
;; Auto-generated from wireshark/epan/dissectors/packet-radius_packetcable.c

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
(def (dissect-radius-packetcable buffer)
  "PacketCable AVPs"
  (try
    (let* (
           (terminal-display-info-terminal-display-status-bitmask (unwrap (read-u8 buffer 0)))
           (terminal-display-info-sbm-general-display (extract-bits terminal-display-info-terminal-display-status-bitmask 0x1 0))
           (terminal-display-info-sbm-calling-number (extract-bits terminal-display-info-terminal-display-status-bitmask 0x2 1))
           (terminal-display-info-sbm-calling-name (extract-bits terminal-display-info-terminal-display-status-bitmask 0x4 2))
           (terminal-display-info-sbm-message-waiting (extract-bits terminal-display-info-terminal-display-status-bitmask 0x8 3))
           (qos-status (unwrap (read-u32be buffer 0)))
           (qos-desc-flags-sfst (extract-bits qos-status 0x0 0))
           (qos-desc-flags-gi (extract-bits qos-status 0x0 0))
           (qos-desc-flags-tgj (extract-bits qos-status 0x0 0))
           (qos-desc-flags-gpi (extract-bits qos-status 0x0 0))
           (qos-desc-flags-ugs (extract-bits qos-status 0x0 0))
           (qos-desc-flags-tp (extract-bits qos-status 0x0 0))
           (qos-desc-flags-msr (extract-bits qos-status 0x0 0))
           (qos-desc-flags-mtb (extract-bits qos-status 0x0 0))
           (qos-desc-flags-mrtr (extract-bits qos-status 0x0 0))
           (qos-desc-flags-mps (extract-bits qos-status 0x0 0))
           (qos-desc-flags-mcb (extract-bits qos-status 0x0 0))
           (qos-desc-flags-srtp (extract-bits qos-status 0x0 0))
           (qos-desc-flags-npi (extract-bits qos-status 0x0 0))
           (qos-desc-flags-tpj (extract-bits qos-status 0x0 0))
           (qos-desc-flags-toso (extract-bits qos-status 0x0 0))
           (qos-desc-flags-mdl (extract-bits qos-status 0x0 0))
           (electronic-surveillance-indication-df-cdc-address (unwrap (read-u32be buffer 0)))
           (redirected-from-last-redirecting-party (unwrap (slice buffer 0 20)))
           (time-adjustment (unwrap (read-u64be buffer 0)))
           (em-header-version-id (unwrap (read-u16be buffer 0)))
           (bcid-timestamp (unwrap (read-u32be buffer 0)))
           (bcid-element-id (unwrap (slice buffer 0 8)))
           (bcid-time-zone-dst (unwrap (read-u8 buffer 0)))
           (bcid-time-zone-offset (unwrap (slice buffer 0 7)))
           (bcid-event-counter (unwrap (read-u32be buffer 0)))
           (trunk-group-id-trunk-number (unwrap (read-u32be buffer 2)))
           (call-termination-cause-code (unwrap (read-u32be buffer 2)))
           (electronic-surveillance-indication-df-ccc-address (unwrap (read-u32be buffer 4)))
           (qos-service-class-name (unwrap (slice buffer 4 16)))
           (electronic-surveillance-indication-cdc-port (unwrap (read-u16be buffer 8)))
           (electronic-surveillance-indication-ccc-port (unwrap (read-u16be buffer 10)))
           (electronic-surveillance-indication-df-df-key (unwrap (slice buffer 12 1)))
           (redirected-from-original-called-party (unwrap (slice buffer 20 20)))
           (em-header-element-id (unwrap (slice buffer 30 8)))
           (em-header-time-zone-dst (unwrap (read-u8 buffer 38)))
           (em-header-time-zone-offset (unwrap (slice buffer 39 7)))
           (redirected-from-info-number-of-redirections (unwrap (read-u16be buffer 40)))
           (em-header-sequence-number (unwrap (read-u32be buffer 46)))
           (em-header-event-time (unwrap (slice buffer 50 18)))
           (em-header-status (unwrap (read-u32be buffer 68)))
           (em-header-priority (unwrap (read-u8 buffer 72)))
           (em-header-attribute-count (unwrap (read-u16be buffer 73)))
           (em-header-event-object (unwrap (read-u8 buffer 75)))
           )

      (ok (list
        (cons 'terminal-display-info-terminal-display-status-bitmask (list (cons 'raw terminal-display-info-terminal-display-status-bitmask) (cons 'formatted (fmt-hex terminal-display-info-terminal-display-status-bitmask))))
        (cons 'terminal-display-info-sbm-general-display (list (cons 'raw terminal-display-info-sbm-general-display) (cons 'formatted (if (= terminal-display-info-sbm-general-display 0) "Not set" "Set"))))
        (cons 'terminal-display-info-sbm-calling-number (list (cons 'raw terminal-display-info-sbm-calling-number) (cons 'formatted (if (= terminal-display-info-sbm-calling-number 0) "Not set" "Set"))))
        (cons 'terminal-display-info-sbm-calling-name (list (cons 'raw terminal-display-info-sbm-calling-name) (cons 'formatted (if (= terminal-display-info-sbm-calling-name 0) "Not set" "Set"))))
        (cons 'terminal-display-info-sbm-message-waiting (list (cons 'raw terminal-display-info-sbm-message-waiting) (cons 'formatted (if (= terminal-display-info-sbm-message-waiting 0) "Not set" "Set"))))
        (cons 'qos-status (list (cons 'raw qos-status) (cons 'formatted (fmt-hex qos-status))))
        (cons 'qos-desc-flags-sfst (list (cons 'raw qos-desc-flags-sfst) (cons 'formatted (if (= qos-desc-flags-sfst 0) "Not set" "Set"))))
        (cons 'qos-desc-flags-gi (list (cons 'raw qos-desc-flags-gi) (cons 'formatted (if (= qos-desc-flags-gi 0) "Not set" "Set"))))
        (cons 'qos-desc-flags-tgj (list (cons 'raw qos-desc-flags-tgj) (cons 'formatted (if (= qos-desc-flags-tgj 0) "Not set" "Set"))))
        (cons 'qos-desc-flags-gpi (list (cons 'raw qos-desc-flags-gpi) (cons 'formatted (if (= qos-desc-flags-gpi 0) "Not set" "Set"))))
        (cons 'qos-desc-flags-ugs (list (cons 'raw qos-desc-flags-ugs) (cons 'formatted (if (= qos-desc-flags-ugs 0) "Not set" "Set"))))
        (cons 'qos-desc-flags-tp (list (cons 'raw qos-desc-flags-tp) (cons 'formatted (if (= qos-desc-flags-tp 0) "Not set" "Set"))))
        (cons 'qos-desc-flags-msr (list (cons 'raw qos-desc-flags-msr) (cons 'formatted (if (= qos-desc-flags-msr 0) "Not set" "Set"))))
        (cons 'qos-desc-flags-mtb (list (cons 'raw qos-desc-flags-mtb) (cons 'formatted (if (= qos-desc-flags-mtb 0) "Not set" "Set"))))
        (cons 'qos-desc-flags-mrtr (list (cons 'raw qos-desc-flags-mrtr) (cons 'formatted (if (= qos-desc-flags-mrtr 0) "Not set" "Set"))))
        (cons 'qos-desc-flags-mps (list (cons 'raw qos-desc-flags-mps) (cons 'formatted (if (= qos-desc-flags-mps 0) "Not set" "Set"))))
        (cons 'qos-desc-flags-mcb (list (cons 'raw qos-desc-flags-mcb) (cons 'formatted (if (= qos-desc-flags-mcb 0) "Not set" "Set"))))
        (cons 'qos-desc-flags-srtp (list (cons 'raw qos-desc-flags-srtp) (cons 'formatted (if (= qos-desc-flags-srtp 0) "Not set" "Set"))))
        (cons 'qos-desc-flags-npi (list (cons 'raw qos-desc-flags-npi) (cons 'formatted (if (= qos-desc-flags-npi 0) "Not set" "Set"))))
        (cons 'qos-desc-flags-tpj (list (cons 'raw qos-desc-flags-tpj) (cons 'formatted (if (= qos-desc-flags-tpj 0) "Not set" "Set"))))
        (cons 'qos-desc-flags-toso (list (cons 'raw qos-desc-flags-toso) (cons 'formatted (if (= qos-desc-flags-toso 0) "Not set" "Set"))))
        (cons 'qos-desc-flags-mdl (list (cons 'raw qos-desc-flags-mdl) (cons 'formatted (if (= qos-desc-flags-mdl 0) "Not set" "Set"))))
        (cons 'electronic-surveillance-indication-df-cdc-address (list (cons 'raw electronic-surveillance-indication-df-cdc-address) (cons 'formatted (fmt-ipv4 electronic-surveillance-indication-df-cdc-address))))
        (cons 'redirected-from-last-redirecting-party (list (cons 'raw redirected-from-last-redirecting-party) (cons 'formatted (utf8->string redirected-from-last-redirecting-party))))
        (cons 'time-adjustment (list (cons 'raw time-adjustment) (cons 'formatted (number->string time-adjustment))))
        (cons 'em-header-version-id (list (cons 'raw em-header-version-id) (cons 'formatted (number->string em-header-version-id))))
        (cons 'bcid-timestamp (list (cons 'raw bcid-timestamp) (cons 'formatted (number->string bcid-timestamp))))
        (cons 'bcid-element-id (list (cons 'raw bcid-element-id) (cons 'formatted (utf8->string bcid-element-id))))
        (cons 'bcid-time-zone-dst (list (cons 'raw bcid-time-zone-dst) (cons 'formatted (number->string bcid-time-zone-dst))))
        (cons 'bcid-time-zone-offset (list (cons 'raw bcid-time-zone-offset) (cons 'formatted (utf8->string bcid-time-zone-offset))))
        (cons 'bcid-event-counter (list (cons 'raw bcid-event-counter) (cons 'formatted (number->string bcid-event-counter))))
        (cons 'trunk-group-id-trunk-number (list (cons 'raw trunk-group-id-trunk-number) (cons 'formatted (number->string trunk-group-id-trunk-number))))
        (cons 'call-termination-cause-code (list (cons 'raw call-termination-cause-code) (cons 'formatted (number->string call-termination-cause-code))))
        (cons 'electronic-surveillance-indication-df-ccc-address (list (cons 'raw electronic-surveillance-indication-df-ccc-address) (cons 'formatted (fmt-ipv4 electronic-surveillance-indication-df-ccc-address))))
        (cons 'qos-service-class-name (list (cons 'raw qos-service-class-name) (cons 'formatted (utf8->string qos-service-class-name))))
        (cons 'electronic-surveillance-indication-cdc-port (list (cons 'raw electronic-surveillance-indication-cdc-port) (cons 'formatted (number->string electronic-surveillance-indication-cdc-port))))
        (cons 'electronic-surveillance-indication-ccc-port (list (cons 'raw electronic-surveillance-indication-ccc-port) (cons 'formatted (number->string electronic-surveillance-indication-ccc-port))))
        (cons 'electronic-surveillance-indication-df-df-key (list (cons 'raw electronic-surveillance-indication-df-df-key) (cons 'formatted (fmt-bytes electronic-surveillance-indication-df-df-key))))
        (cons 'redirected-from-original-called-party (list (cons 'raw redirected-from-original-called-party) (cons 'formatted (utf8->string redirected-from-original-called-party))))
        (cons 'em-header-element-id (list (cons 'raw em-header-element-id) (cons 'formatted (utf8->string em-header-element-id))))
        (cons 'em-header-time-zone-dst (list (cons 'raw em-header-time-zone-dst) (cons 'formatted (number->string em-header-time-zone-dst))))
        (cons 'em-header-time-zone-offset (list (cons 'raw em-header-time-zone-offset) (cons 'formatted (utf8->string em-header-time-zone-offset))))
        (cons 'redirected-from-info-number-of-redirections (list (cons 'raw redirected-from-info-number-of-redirections) (cons 'formatted (number->string redirected-from-info-number-of-redirections))))
        (cons 'em-header-sequence-number (list (cons 'raw em-header-sequence-number) (cons 'formatted (number->string em-header-sequence-number))))
        (cons 'em-header-event-time (list (cons 'raw em-header-event-time) (cons 'formatted (utf8->string em-header-event-time))))
        (cons 'em-header-status (list (cons 'raw em-header-status) (cons 'formatted (fmt-hex em-header-status))))
        (cons 'em-header-priority (list (cons 'raw em-header-priority) (cons 'formatted (number->string em-header-priority))))
        (cons 'em-header-attribute-count (list (cons 'raw em-header-attribute-count) (cons 'formatted (number->string em-header-attribute-count))))
        (cons 'em-header-event-object (list (cons 'raw em-header-event-object) (cons 'formatted (number->string em-header-event-object))))
        )))

    (catch (e)
      (err (str "RADIUS-PACKETCABLE parse error: " e)))))

;; dissect-radius-packetcable: parse RADIUS-PACKETCABLE from bytevector
;; Returns (ok fields-alist) or (err message)