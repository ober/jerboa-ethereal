;; packet-q933.c
;; Routines for Q.933 frame disassembly
;; Guy Harris <guy@alum.mit.edu>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/q933.ss
;; Auto-generated from wireshark/epan/dissectors/packet-q933.c

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
(def (dissect-q933 buffer)
  "Q.933"
  (try
    (let* (
           (segmented-message-type (unwrap (read-u8 buffer 0)))
           (discriminator (unwrap (read-u8 buffer 0)))
           (out-band-negotiation (unwrap (read-u8 buffer 1)))
           (call-ref-len (unwrap (read-u8 buffer 1)))
           (call-ref-flag (unwrap (read-u8 buffer 2)))
           (call-ref (unwrap (slice buffer 2 1)))
           (layer-1 (unwrap (read-u8 buffer 4)))
           (rate-adaption-header (unwrap (read-u8 buffer 5)))
           (multiple-frame-establishment (unwrap (read-u8 buffer 5)))
           (mode-of-operation (unwrap (read-u8 buffer 5)))
           (length (unwrap (read-u8 buffer 5)))
           (data (unwrap (slice buffer 5 1)))
           (duplex (unwrap (read-u8 buffer 7)))
           (modem-type (unwrap (read-u8 buffer 7)))
           (user-specified-layer-2-protocol-information (unwrap (read-u8 buffer 9)))
           (default-packet-size-0F (unwrap (read-u8 buffer 12)))
           (packet-window-size (unwrap (read-u8 buffer 13)))
           (network-service (unwrap (read-u8 buffer 20)))
           (condition-normal (unwrap (read-u8 buffer 20)))
           (user-specific-diagnostic (unwrap (slice buffer 21 1)))
           (diagnostic (unwrap (slice buffer 21 1)))
           (timer (unwrap (slice buffer 22 3)))
           (diagnostics (unwrap (slice buffer 22 1)))
           (link-verf-txseq (unwrap (read-u8 buffer 22)))
           (link-verf-rxseq (unwrap (read-u8 buffer 22)))
           (dlci (unwrap (read-u32be buffer 22)))
           (interface-identified (unwrap (read-u8 buffer 22)))
           (interface-basic (unwrap (read-u8 buffer 22)))
           (indicated-channel-required (unwrap (read-u8 buffer 22)))
           (indicated-channel-d-channel (unwrap (read-u8 buffer 22)))
           (channel-indicated-by (unwrap (read-u8 buffer 24)))
           (network-identification-length (unwrap (read-u8 buffer 25)))
           (network-identification (unwrap (slice buffer 27 1)))
           (network-specific-facility-specification (unwrap (slice buffer 27 1)))
           (request (unwrap (read-u8 buffer 30)))
           (confirmation (unwrap (read-u8 buffer 30)))
           (extension-ind (unwrap (read-u8 buffer 31)))
           (subaddress (unwrap (slice buffer 34 1)))
           (user-information-str (unwrap (slice buffer 37 1)))
           (user-information-bytes (unwrap (slice buffer 37 1)))
           )

      (ok (list
        (cons 'segmented-message-type (list (cons 'raw segmented-message-type) (cons 'formatted (number->string segmented-message-type))))
        (cons 'discriminator (list (cons 'raw discriminator) (cons 'formatted (fmt-hex discriminator))))
        (cons 'out-band-negotiation (list (cons 'raw out-band-negotiation) (cons 'formatted (if (= out-band-negotiation 0) "False" "True"))))
        (cons 'call-ref-len (list (cons 'raw call-ref-len) (cons 'formatted (number->string call-ref-len))))
        (cons 'call-ref-flag (list (cons 'raw call-ref-flag) (cons 'formatted (if (= call-ref-flag 0) "Message sent from originating side" "Message sent to originating side"))))
        (cons 'call-ref (list (cons 'raw call-ref) (cons 'formatted (fmt-bytes call-ref))))
        (cons 'layer-1 (list (cons 'raw layer-1) (cons 'formatted (if (= layer-1 0) "False" "True"))))
        (cons 'rate-adaption-header (list (cons 'raw rate-adaption-header) (cons 'formatted (if (= rate-adaption-header 0) "False" "True"))))
        (cons 'multiple-frame-establishment (list (cons 'raw multiple-frame-establishment) (cons 'formatted (if (= multiple-frame-establishment 0) "False" "True"))))
        (cons 'mode-of-operation (list (cons 'raw mode-of-operation) (cons 'formatted (if (= mode-of-operation 0) "False" "True"))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'duplex (list (cons 'raw duplex) (cons 'formatted (if (= duplex 0) "False" "True"))))
        (cons 'modem-type (list (cons 'raw modem-type) (cons 'formatted (fmt-hex modem-type))))
        (cons 'user-specified-layer-2-protocol-information (list (cons 'raw user-specified-layer-2-protocol-information) (cons 'formatted (fmt-hex user-specified-layer-2-protocol-information))))
        (cons 'default-packet-size-0F (list (cons 'raw default-packet-size-0F) (cons 'formatted (number->string default-packet-size-0F))))
        (cons 'packet-window-size (list (cons 'raw packet-window-size) (cons 'formatted (number->string packet-window-size))))
        (cons 'network-service (list (cons 'raw network-service) (cons 'formatted (if (= network-service 0) "False" "True"))))
        (cons 'condition-normal (list (cons 'raw condition-normal) (cons 'formatted (number->string condition-normal))))
        (cons 'user-specific-diagnostic (list (cons 'raw user-specific-diagnostic) (cons 'formatted (fmt-bytes user-specific-diagnostic))))
        (cons 'diagnostic (list (cons 'raw diagnostic) (cons 'formatted (fmt-bytes diagnostic))))
        (cons 'timer (list (cons 'raw timer) (cons 'formatted (utf8->string timer))))
        (cons 'diagnostics (list (cons 'raw diagnostics) (cons 'formatted (fmt-bytes diagnostics))))
        (cons 'link-verf-txseq (list (cons 'raw link-verf-txseq) (cons 'formatted (number->string link-verf-txseq))))
        (cons 'link-verf-rxseq (list (cons 'raw link-verf-rxseq) (cons 'formatted (number->string link-verf-rxseq))))
        (cons 'dlci (list (cons 'raw dlci) (cons 'formatted (number->string dlci))))
        (cons 'interface-identified (list (cons 'raw interface-identified) (cons 'formatted (if (= interface-identified 0) "Implicitly identified" "Explicitly identified"))))
        (cons 'interface-basic (list (cons 'raw interface-basic) (cons 'formatted (if (= interface-basic 0) "Basic" "Not basic"))))
        (cons 'indicated-channel-required (list (cons 'raw indicated-channel-required) (cons 'formatted (if (= indicated-channel-required 0) "Preferred" "Required"))))
        (cons 'indicated-channel-d-channel (list (cons 'raw indicated-channel-d-channel) (cons 'formatted (if (= indicated-channel-d-channel 0) "Not D-channel" "D-channel"))))
        (cons 'channel-indicated-by (list (cons 'raw channel-indicated-by) (cons 'formatted (if (= channel-indicated-by 0) "number" "slot map"))))
        (cons 'network-identification-length (list (cons 'raw network-identification-length) (cons 'formatted (number->string network-identification-length))))
        (cons 'network-identification (list (cons 'raw network-identification) (cons 'formatted (utf8->string network-identification))))
        (cons 'network-specific-facility-specification (list (cons 'raw network-specific-facility-specification) (cons 'formatted (fmt-bytes network-specific-facility-specification))))
        (cons 'request (list (cons 'raw request) (cons 'formatted (if (= request 0) "Request indicated/request accepted" "No request/request denied"))))
        (cons 'confirmation (list (cons 'raw confirmation) (cons 'formatted (if (= confirmation 0) "End-to-end" "Link-by-link"))))
        (cons 'extension-ind (list (cons 'raw extension-ind) (cons 'formatted (if (= extension-ind 0) "False" "True"))))
        (cons 'subaddress (list (cons 'raw subaddress) (cons 'formatted (fmt-bytes subaddress))))
        (cons 'user-information-str (list (cons 'raw user-information-str) (cons 'formatted (utf8->string user-information-str))))
        (cons 'user-information-bytes (list (cons 'raw user-information-bytes) (cons 'formatted (fmt-bytes user-information-bytes))))
        )))

    (catch (e)
      (err (str "Q933 parse error: " e)))))

;; dissect-q933: parse Q933 from bytevector
;; Returns (ok fields-alist) or (err message)