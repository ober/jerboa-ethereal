;; packet-dlsw.c
;; Routines for DLSw packet dissection (Data Link Switching)
;; Copyright 2001, Paul Ionescu <paul@acorp.ro>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dlsw.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dlsw.c
;; RFC 1434

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
(def (dissect-dlsw buffer)
  "Data Link SWitching"
  (try
    (let* (
           (header-length (unwrap (read-u8 buffer 1)))
           (message-length (unwrap (read-u16be buffer 2)))
           (remote-dlc (unwrap (read-u32be buffer 4)))
           (remote-dlc-pid (unwrap (read-u32be buffer 8)))
           (reserved (unwrap (slice buffer 12 2)))
           (flow-control-ack (unwrap (read-u8 buffer 15)))
           (flow-control-indication (unwrap (read-u8 buffer 15)))
           (flow-ctrl-byte (unwrap (read-u8 buffer 15)))
           (protocol-id (unwrap (read-u8 buffer 16)))
           (header-number (unwrap (read-u8 buffer 17)))
           (largest-frame-size (unwrap (read-u8 buffer 20)))
           (flags-explorer-msg (unwrap (read-u8 buffer 21)))
           (ssp-flags (unwrap (read-u8 buffer 21)))
           (target-mac-address (unwrap (slice buffer 24 6)))
           (origin-mac-address (unwrap (slice buffer 30 6)))
           (origin-link-sap (unwrap (read-u8 buffer 36)))
           (target-link-sap (unwrap (read-u8 buffer 37)))
           (dlc-header-length (unwrap (read-u16be buffer 42)))
           (origin-dlc-port-id (unwrap (read-u32be buffer 44)))
           (origin-dlc (unwrap (read-u32be buffer 48)))
           (origin-transport-id (unwrap (read-u32be buffer 52)))
           (target-dlc-port-id (unwrap (read-u32be buffer 56)))
           (target-dlc (unwrap (read-u32be buffer 60)))
           (target-transport-id (unwrap (read-u32be buffer 64)))
           )

      (ok (list
        (cons 'header-length (list (cons 'raw header-length) (cons 'formatted (number->string header-length))))
        (cons 'message-length (list (cons 'raw message-length) (cons 'formatted (number->string message-length))))
        (cons 'remote-dlc (list (cons 'raw remote-dlc) (cons 'formatted (number->string remote-dlc))))
        (cons 'remote-dlc-pid (list (cons 'raw remote-dlc-pid) (cons 'formatted (number->string remote-dlc-pid))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'flow-control-ack (list (cons 'raw flow-control-ack) (cons 'formatted (if (= flow-control-ack 0) "False" "True"))))
        (cons 'flow-control-indication (list (cons 'raw flow-control-indication) (cons 'formatted (if (= flow-control-indication 0) "False" "True"))))
        (cons 'flow-ctrl-byte (list (cons 'raw flow-ctrl-byte) (cons 'formatted (fmt-hex flow-ctrl-byte))))
        (cons 'protocol-id (list (cons 'raw protocol-id) (cons 'formatted (fmt-hex protocol-id))))
        (cons 'header-number (list (cons 'raw header-number) (cons 'formatted (fmt-hex header-number))))
        (cons 'largest-frame-size (list (cons 'raw largest-frame-size) (cons 'formatted (number->string largest-frame-size))))
        (cons 'flags-explorer-msg (list (cons 'raw flags-explorer-msg) (cons 'formatted (if (= flags-explorer-msg 0) "False" "True"))))
        (cons 'ssp-flags (list (cons 'raw ssp-flags) (cons 'formatted (fmt-hex ssp-flags))))
        (cons 'target-mac-address (list (cons 'raw target-mac-address) (cons 'formatted (fmt-mac target-mac-address))))
        (cons 'origin-mac-address (list (cons 'raw origin-mac-address) (cons 'formatted (fmt-mac origin-mac-address))))
        (cons 'origin-link-sap (list (cons 'raw origin-link-sap) (cons 'formatted (fmt-hex origin-link-sap))))
        (cons 'target-link-sap (list (cons 'raw target-link-sap) (cons 'formatted (fmt-hex target-link-sap))))
        (cons 'dlc-header-length (list (cons 'raw dlc-header-length) (cons 'formatted (number->string dlc-header-length))))
        (cons 'origin-dlc-port-id (list (cons 'raw origin-dlc-port-id) (cons 'formatted (number->string origin-dlc-port-id))))
        (cons 'origin-dlc (list (cons 'raw origin-dlc) (cons 'formatted (number->string origin-dlc))))
        (cons 'origin-transport-id (list (cons 'raw origin-transport-id) (cons 'formatted (number->string origin-transport-id))))
        (cons 'target-dlc-port-id (list (cons 'raw target-dlc-port-id) (cons 'formatted (number->string target-dlc-port-id))))
        (cons 'target-dlc (list (cons 'raw target-dlc) (cons 'formatted (number->string target-dlc))))
        (cons 'target-transport-id (list (cons 'raw target-transport-id) (cons 'formatted (number->string target-transport-id))))
        )))

    (catch (e)
      (err (str "DLSW parse error: " e)))))

;; dissect-dlsw: parse DLSW from bytevector
;; Returns (ok fields-alist) or (err message)