;; packet-q2931.c
;; Routines for Q.2931 frame disassembly
;; Guy Harris <guy@alum.mit.edu>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/q2931.ss
;; Auto-generated from wireshark/epan/dissectors/packet-q2931.c

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
(def (dissect-q2931 buffer)
  "Q.2931"
  (try
    (let* (
           (locking-codeset (unwrap (read-u8 buffer 0)))
           (discriminator (unwrap (read-u8 buffer 0)))
           (user-defined-aal-information (unwrap (slice buffer 1 1)))
           (aal-parameter-identifier (unwrap (read-u8 buffer 1)))
           (aal1-multiplier (unwrap (read-u16be buffer 1)))
           (call-ref-len (unwrap (read-u8 buffer 1)))
           (call-ref-flag (unwrap (read-u8 buffer 2)))
           (call-ref (unwrap (slice buffer 2 1)))
           (aal1-structured-data-transfer-block-size (unwrap (read-u16be buffer 3)))
           (message-type-ext (unwrap (read-u8 buffer 3)))
           (message-flag (extract-bits message-type-ext 0x0 0))
           (message-len (unwrap (read-u16be buffer 4)))
           (aal1-forward-max-cpcs-sdu-size (unwrap (read-u16be buffer 5)))
           (aal1-backward-max-cpcs-sdu-size (unwrap (read-u16be buffer 7)))
           (midrange (unwrap (read-u32be buffer 9)))
           (frame-discard-forward-dir (unwrap (read-u8 buffer 18)))
           (frame-discard-backward-dir (unwrap (read-u8 buffer 18)))
           (tagging-backward-dir (unwrap (read-u8 buffer 18)))
           (tagging-forward-dir (unwrap (read-u8 buffer 18)))
           (bband-low-layer-info-user-info-l1-proto (unwrap (read-u8 buffer 23)))
           (bband-low-layer-info-user-specified-l2-proto (unwrap (read-u8 buffer 25)))
           (bband-low-layer-info-window-size (unwrap (read-u8 buffer 26)))
           (bband-low-layer-info-packet-window-size (unwrap (read-u8 buffer 30)))
           (organization-code (unwrap (read-u24be buffer 35)))
           (protocol-id (unwrap (read-u16be buffer 38)))
           (cause-network-service (unwrap (read-u8 buffer 40)))
           (cause-network-behavior (unwrap (read-u8 buffer 40)))
           (cause-rejection-user-specific-diagnostic (unwrap (slice buffer 41 1)))
           (cause-vpci (unwrap (read-u16be buffer 43)))
           (cause-vci (unwrap (read-u16be buffer 45)))
           (cause-timer (unwrap (slice buffer 45 3)))
           (cause-rejection-diagnostic (unwrap (slice buffer 45 1)))
           (number-string (unwrap (slice buffer 47 1)))
           (nsap-address-number-short (unwrap (slice buffer 47 1)))
           (number-bytes (unwrap (slice buffer 47 1)))
           (party-subaddr-subaddress (unwrap (slice buffer 48 1)))
           (conn-id-vpci (unwrap (read-u16be buffer 49)))
           (conn-id-vci (unwrap (read-u16be buffer 51)))
           (e2e-transit-delay-identifier (unwrap (read-u8 buffer 51)))
           (e2e-transit-delay-maximum-end-to-end (unwrap (read-u16be buffer 51)))
           (bband-sending-complete-id (unwrap (read-u8 buffer 52)))
           (transit-network-sel-network-id (unwrap (slice buffer 54 1)))
           (oam-end-to-end-f5-flow (unwrap (read-u8 buffer 54)))
           (endpoint-reference-flag (unwrap (read-u8 buffer 56)))
           (endpoint-reference-identifier-value (unwrap (read-u16be buffer 56)))
           (information-element-extension (unwrap (read-u8 buffer 56)))
           (ie-handling-instructions (unwrap (read-u8 buffer 56)))
           (information-element-length (unwrap (read-u16be buffer 56)))
           (information-element-data (unwrap (slice buffer 56 1)))
           )

      (ok (list
        (cons 'locking-codeset (list (cons 'raw locking-codeset) (cons 'formatted (number->string locking-codeset))))
        (cons 'discriminator (list (cons 'raw discriminator) (cons 'formatted (fmt-hex discriminator))))
        (cons 'user-defined-aal-information (list (cons 'raw user-defined-aal-information) (cons 'formatted (fmt-bytes user-defined-aal-information))))
        (cons 'aal-parameter-identifier (list (cons 'raw aal-parameter-identifier) (cons 'formatted (fmt-hex aal-parameter-identifier))))
        (cons 'aal1-multiplier (list (cons 'raw aal1-multiplier) (cons 'formatted (number->string aal1-multiplier))))
        (cons 'call-ref-len (list (cons 'raw call-ref-len) (cons 'formatted (number->string call-ref-len))))
        (cons 'call-ref-flag (list (cons 'raw call-ref-flag) (cons 'formatted (if (= call-ref-flag 0) "Message sent from originating side" "Message sent to originating side"))))
        (cons 'call-ref (list (cons 'raw call-ref) (cons 'formatted (fmt-bytes call-ref))))
        (cons 'aal1-structured-data-transfer-block-size (list (cons 'raw aal1-structured-data-transfer-block-size) (cons 'formatted (number->string aal1-structured-data-transfer-block-size))))
        (cons 'message-type-ext (list (cons 'raw message-type-ext) (cons 'formatted (fmt-hex message-type-ext))))
        (cons 'message-flag (list (cons 'raw message-flag) (cons 'formatted (if (= message-flag 0) "Follow explicit error handling instructions" "Regular error handling procedures apply"))))
        (cons 'message-len (list (cons 'raw message-len) (cons 'formatted (number->string message-len))))
        (cons 'aal1-forward-max-cpcs-sdu-size (list (cons 'raw aal1-forward-max-cpcs-sdu-size) (cons 'formatted (number->string aal1-forward-max-cpcs-sdu-size))))
        (cons 'aal1-backward-max-cpcs-sdu-size (list (cons 'raw aal1-backward-max-cpcs-sdu-size) (cons 'formatted (number->string aal1-backward-max-cpcs-sdu-size))))
        (cons 'midrange (list (cons 'raw midrange) (cons 'formatted (fmt-hex midrange))))
        (cons 'frame-discard-forward-dir (list (cons 'raw frame-discard-forward-dir) (cons 'formatted (if (= frame-discard-forward-dir 0) "False" "True"))))
        (cons 'frame-discard-backward-dir (list (cons 'raw frame-discard-backward-dir) (cons 'formatted (if (= frame-discard-backward-dir 0) "False" "True"))))
        (cons 'tagging-backward-dir (list (cons 'raw tagging-backward-dir) (cons 'formatted (if (= tagging-backward-dir 0) "False" "True"))))
        (cons 'tagging-forward-dir (list (cons 'raw tagging-forward-dir) (cons 'formatted (if (= tagging-forward-dir 0) "False" "True"))))
        (cons 'bband-low-layer-info-user-info-l1-proto (list (cons 'raw bband-low-layer-info-user-info-l1-proto) (cons 'formatted (fmt-hex bband-low-layer-info-user-info-l1-proto))))
        (cons 'bband-low-layer-info-user-specified-l2-proto (list (cons 'raw bband-low-layer-info-user-specified-l2-proto) (cons 'formatted (fmt-hex bband-low-layer-info-user-specified-l2-proto))))
        (cons 'bband-low-layer-info-window-size (list (cons 'raw bband-low-layer-info-window-size) (cons 'formatted (number->string bband-low-layer-info-window-size))))
        (cons 'bband-low-layer-info-packet-window-size (list (cons 'raw bband-low-layer-info-packet-window-size) (cons 'formatted (number->string bband-low-layer-info-packet-window-size))))
        (cons 'organization-code (list (cons 'raw organization-code) (cons 'formatted (number->string organization-code))))
        (cons 'protocol-id (list (cons 'raw protocol-id) (cons 'formatted (fmt-hex protocol-id))))
        (cons 'cause-network-service (list (cons 'raw cause-network-service) (cons 'formatted (if (= cause-network-service 0) "False" "True"))))
        (cons 'cause-network-behavior (list (cons 'raw cause-network-behavior) (cons 'formatted (if (= cause-network-behavior 0) "Normal" "Abnormal"))))
        (cons 'cause-rejection-user-specific-diagnostic (list (cons 'raw cause-rejection-user-specific-diagnostic) (cons 'formatted (fmt-bytes cause-rejection-user-specific-diagnostic))))
        (cons 'cause-vpci (list (cons 'raw cause-vpci) (cons 'formatted (number->string cause-vpci))))
        (cons 'cause-vci (list (cons 'raw cause-vci) (cons 'formatted (number->string cause-vci))))
        (cons 'cause-timer (list (cons 'raw cause-timer) (cons 'formatted (utf8->string cause-timer))))
        (cons 'cause-rejection-diagnostic (list (cons 'raw cause-rejection-diagnostic) (cons 'formatted (fmt-bytes cause-rejection-diagnostic))))
        (cons 'number-string (list (cons 'raw number-string) (cons 'formatted (utf8->string number-string))))
        (cons 'nsap-address-number-short (list (cons 'raw nsap-address-number-short) (cons 'formatted (fmt-bytes nsap-address-number-short))))
        (cons 'number-bytes (list (cons 'raw number-bytes) (cons 'formatted (fmt-bytes number-bytes))))
        (cons 'party-subaddr-subaddress (list (cons 'raw party-subaddr-subaddress) (cons 'formatted (fmt-bytes party-subaddr-subaddress))))
        (cons 'conn-id-vpci (list (cons 'raw conn-id-vpci) (cons 'formatted (number->string conn-id-vpci))))
        (cons 'conn-id-vci (list (cons 'raw conn-id-vci) (cons 'formatted (number->string conn-id-vci))))
        (cons 'e2e-transit-delay-identifier (list (cons 'raw e2e-transit-delay-identifier) (cons 'formatted (fmt-hex e2e-transit-delay-identifier))))
        (cons 'e2e-transit-delay-maximum-end-to-end (list (cons 'raw e2e-transit-delay-maximum-end-to-end) (cons 'formatted (number->string e2e-transit-delay-maximum-end-to-end))))
        (cons 'bband-sending-complete-id (list (cons 'raw bband-sending-complete-id) (cons 'formatted (fmt-hex bband-sending-complete-id))))
        (cons 'transit-network-sel-network-id (list (cons 'raw transit-network-sel-network-id) (cons 'formatted (utf8->string transit-network-sel-network-id))))
        (cons 'oam-end-to-end-f5-flow (list (cons 'raw oam-end-to-end-f5-flow) (cons 'formatted (if (= oam-end-to-end-f5-flow 0) "Optional" "Mandatory"))))
        (cons 'endpoint-reference-flag (list (cons 'raw endpoint-reference-flag) (cons 'formatted (if (= endpoint-reference-flag 0) "Message sent from side that originates the endpoint reference" "Message sent to side that originates the endpoint reference"))))
        (cons 'endpoint-reference-identifier-value (list (cons 'raw endpoint-reference-identifier-value) (cons 'formatted (number->string endpoint-reference-identifier-value))))
        (cons 'information-element-extension (list (cons 'raw information-element-extension) (cons 'formatted (fmt-hex information-element-extension))))
        (cons 'ie-handling-instructions (list (cons 'raw ie-handling-instructions) (cons 'formatted (if (= ie-handling-instructions 0) "Regular error handling procedures apply" "Follow explicit error handling instructions"))))
        (cons 'information-element-length (list (cons 'raw information-element-length) (cons 'formatted (number->string information-element-length))))
        (cons 'information-element-data (list (cons 'raw information-element-data) (cons 'formatted (fmt-bytes information-element-data))))
        )))

    (catch (e)
      (err (str "Q2931 parse error: " e)))))

;; dissect-q2931: parse Q2931 from bytevector
;; Returns (ok fields-alist) or (err message)