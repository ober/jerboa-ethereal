;; packet-busmirroring.c
;; Routines for BusMirroring protocol packet disassembly
;; Copyright 2023, Haiyun Liu <liu0hy@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Bus Mirroring is an AUTOSAR Basic Software module. Its purpose is the replication of
;; the traffic and the state of internal buses to an external bus, such that a tester
;; connected to that external bus can monitor internal buses for debugging purposes.
;; When mirroring to an IP destination bus like Ethernet, the Bus Mirroring module applies
;; a protocol to pack several smaller frames (e.g. CAN, LIN or FlexRay) into one large
;; frame of the destination bus.
;; For more information, see AUTOSAR "Specification of Bus Mirroring", Section 7.4
;; "Mirroring to FlexRay, IP, and CDD":
;; https://www.autosar.org/fileadmin/standards/R22-11/CP/AUTOSAR_SWS_BusMirroring.pdf
;;

;; jerboa-ethereal/dissectors/busmirroring.ss
;; Auto-generated from wireshark/epan/dissectors/packet-busmirroring.c

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
(def (dissect-busmirroring buffer)
  "Bus Mirroring Protocol"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (hf-timestamp (unwrap (read-u16be buffer 0)))
           (number (unwrap (read-u8 buffer 1)))
           (hf-seconds (unwrap (slice buffer 2 6)))
           (state-available (unwrap (read-u8 buffer 2)))
           (id-available (unwrap (read-u8 buffer 2)))
           (available (unwrap (read-u8 buffer 2)))
           (state (unwrap (read-u8 buffer 4)))
           (lost (unwrap (read-u8 buffer 4)))
           (online (unwrap (read-u8 buffer 4)))
           (error-passive (unwrap (read-u8 buffer 4)))
           (bus-off (unwrap (read-u8 buffer 4)))
           (tx-error-count (unwrap (read-u8 buffer 4)))
           (header-tx-error (unwrap (read-u8 buffer 4)))
           (tx-error (unwrap (read-u8 buffer 4)))
           (rx-error (unwrap (read-u8 buffer 4)))
           (rx-no-response (unwrap (read-u8 buffer 4)))
           (bus-synchronous (unwrap (read-u8 buffer 4)))
           (normal-active (unwrap (read-u8 buffer 4)))
           (syntax-error (unwrap (read-u8 buffer 4)))
           (content-error (unwrap (read-u8 buffer 4)))
           (boundary-violation (unwrap (read-u8 buffer 4)))
           (tx-conflict (unwrap (read-u8 buffer 4)))
           (id-type (unwrap (read-u8 buffer 5)))
           (frame-type (unwrap (read-u8 buffer 5)))
           (hf-nanoseconds (unwrap (read-u32be buffer 8)))
           (pid (unwrap (read-u8 buffer 9)))
           (id (unwrap (read-u32be buffer 10)))
           (channel-b (unwrap (read-u8 buffer 10)))
           (channel-a (unwrap (read-u8 buffer 10)))
           (slot-valid (unwrap (read-u8 buffer 10)))
           (slot-id (unwrap (read-u16be buffer 10)))
           (cycle (unwrap (read-u8 buffer 12)))
           (length (unwrap (read-u8 buffer 13)))
           (hf-payload (unwrap (slice buffer 14 1)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'hf-timestamp (list (cons 'raw hf-timestamp) (cons 'formatted (number->string hf-timestamp))))
        (cons 'number (list (cons 'raw number) (cons 'formatted (number->string number))))
        (cons 'hf-seconds (list (cons 'raw hf-seconds) (cons 'formatted (number->string hf-seconds))))
        (cons 'state-available (list (cons 'raw state-available) (cons 'formatted (if (= state-available 0) "False" "True"))))
        (cons 'id-available (list (cons 'raw id-available) (cons 'formatted (if (= id-available 0) "False" "True"))))
        (cons 'available (list (cons 'raw available) (cons 'formatted (if (= available 0) "False" "True"))))
        (cons 'state (list (cons 'raw state) (cons 'formatted (fmt-hex state))))
        (cons 'lost (list (cons 'raw lost) (cons 'formatted (number->string lost))))
        (cons 'online (list (cons 'raw online) (cons 'formatted (number->string online))))
        (cons 'error-passive (list (cons 'raw error-passive) (cons 'formatted (number->string error-passive))))
        (cons 'bus-off (list (cons 'raw bus-off) (cons 'formatted (number->string bus-off))))
        (cons 'tx-error-count (list (cons 'raw tx-error-count) (cons 'formatted (number->string tx-error-count))))
        (cons 'header-tx-error (list (cons 'raw header-tx-error) (cons 'formatted (number->string header-tx-error))))
        (cons 'tx-error (list (cons 'raw tx-error) (cons 'formatted (number->string tx-error))))
        (cons 'rx-error (list (cons 'raw rx-error) (cons 'formatted (number->string rx-error))))
        (cons 'rx-no-response (list (cons 'raw rx-no-response) (cons 'formatted (number->string rx-no-response))))
        (cons 'bus-synchronous (list (cons 'raw bus-synchronous) (cons 'formatted (number->string bus-synchronous))))
        (cons 'normal-active (list (cons 'raw normal-active) (cons 'formatted (number->string normal-active))))
        (cons 'syntax-error (list (cons 'raw syntax-error) (cons 'formatted (number->string syntax-error))))
        (cons 'content-error (list (cons 'raw content-error) (cons 'formatted (number->string content-error))))
        (cons 'boundary-violation (list (cons 'raw boundary-violation) (cons 'formatted (number->string boundary-violation))))
        (cons 'tx-conflict (list (cons 'raw tx-conflict) (cons 'formatted (number->string tx-conflict))))
        (cons 'id-type (list (cons 'raw id-type) (cons 'formatted (if (= id-type 0) "Standard" "Extended"))))
        (cons 'frame-type (list (cons 'raw frame-type) (cons 'formatted (if (= frame-type 0) "CAN 2.0" "CAN FD"))))
        (cons 'hf-nanoseconds (list (cons 'raw hf-nanoseconds) (cons 'formatted (number->string hf-nanoseconds))))
        (cons 'pid (list (cons 'raw pid) (cons 'formatted (fmt-hex pid))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (fmt-hex id))))
        (cons 'channel-b (list (cons 'raw channel-b) (cons 'formatted (if (= channel-b 0) "False" "True"))))
        (cons 'channel-a (list (cons 'raw channel-a) (cons 'formatted (if (= channel-a 0) "False" "True"))))
        (cons 'slot-valid (list (cons 'raw slot-valid) (cons 'formatted (if (= slot-valid 0) "False" "True"))))
        (cons 'slot-id (list (cons 'raw slot-id) (cons 'formatted (fmt-hex slot-id))))
        (cons 'cycle (list (cons 'raw cycle) (cons 'formatted (number->string cycle))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'hf-payload (list (cons 'raw hf-payload) (cons 'formatted (fmt-bytes hf-payload))))
        )))

    (catch (e)
      (err (str "BUSMIRRORING parse error: " e)))))

;; dissect-busmirroring: parse BUSMIRRORING from bytevector
;; Returns (ok fields-alist) or (err message)