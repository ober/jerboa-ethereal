;; packet-bpdu.c
;; Routines for BPDU (Spanning Tree Protocol) disassembly
;;
;; Copyright 1999 Christophe Tronche <ch.tronche@computer.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bpdu.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bpdu.c

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
(def (dissect-bpdu buffer)
  "Spanning Tree Protocol"
  (try
    (let* (
           (msti-flags (unwrap (read-u8 buffer 0)))
           (flags-tcack (extract-bits msti-flags 0x0 0))
           (flags-agreement (extract-bits msti-flags 0x0 0))
           (flags-forwarding (extract-bits msti-flags 0x0 0))
           (flags-learning (extract-bits msti-flags 0x0 0))
           (flags-proposal (extract-bits msti-flags 0x0 0))
           (flags-tc (extract-bits msti-flags 0x0 0))
           (mst-priority (unwrap (read-u8 buffer 0)))
           (msti-id-FFF (unwrap (read-u16be buffer 0)))
           (msti-internal-root-path-cost (unwrap (read-u32be buffer 0)))
           (msti-bridge-identifier-priority (unwrap (read-u8 buffer 0)))
           (msti-port-identifier-priority (unwrap (read-u8 buffer 0)))
           (msti-remaining-hops (unwrap (read-u8 buffer 0)))
           (msti-id (unwrap (read-u16be buffer 0)))
           (msti-regional-root-id (unwrap (read-u16be buffer 0)))
           (msti-bridge-id (unwrap (read-u16be buffer 0)))
           (msti-bridge-id-priority (unwrap (read-u16be buffer 0)))
           (msti-port-id (unwrap (read-u16be buffer 0)))
           )

      (ok (list
        (cons 'msti-flags (list (cons 'raw msti-flags) (cons 'formatted (fmt-hex msti-flags))))
        (cons 'flags-tcack (list (cons 'raw flags-tcack) (cons 'formatted (if (= flags-tcack 0) "Not set" "Set"))))
        (cons 'flags-agreement (list (cons 'raw flags-agreement) (cons 'formatted (if (= flags-agreement 0) "Not set" "Set"))))
        (cons 'flags-forwarding (list (cons 'raw flags-forwarding) (cons 'formatted (if (= flags-forwarding 0) "Not set" "Set"))))
        (cons 'flags-learning (list (cons 'raw flags-learning) (cons 'formatted (if (= flags-learning 0) "Not set" "Set"))))
        (cons 'flags-proposal (list (cons 'raw flags-proposal) (cons 'formatted (if (= flags-proposal 0) "Not set" "Set"))))
        (cons 'flags-tc (list (cons 'raw flags-tc) (cons 'formatted (if (= flags-tc 0) "Not set" "Set"))))
        (cons 'mst-priority (list (cons 'raw mst-priority) (cons 'formatted (fmt-hex mst-priority))))
        (cons 'msti-id-FFF (list (cons 'raw msti-id-FFF) (cons 'formatted (number->string msti-id-FFF))))
        (cons 'msti-internal-root-path-cost (list (cons 'raw msti-internal-root-path-cost) (cons 'formatted (number->string msti-internal-root-path-cost))))
        (cons 'msti-bridge-identifier-priority (list (cons 'raw msti-bridge-identifier-priority) (cons 'formatted (number->string msti-bridge-identifier-priority))))
        (cons 'msti-port-identifier-priority (list (cons 'raw msti-port-identifier-priority) (cons 'formatted (number->string msti-port-identifier-priority))))
        (cons 'msti-remaining-hops (list (cons 'raw msti-remaining-hops) (cons 'formatted (number->string msti-remaining-hops))))
        (cons 'msti-id (list (cons 'raw msti-id) (cons 'formatted (number->string msti-id))))
        (cons 'msti-regional-root-id (list (cons 'raw msti-regional-root-id) (cons 'formatted (number->string msti-regional-root-id))))
        (cons 'msti-bridge-id (list (cons 'raw msti-bridge-id) (cons 'formatted (number->string msti-bridge-id))))
        (cons 'msti-bridge-id-priority (list (cons 'raw msti-bridge-id-priority) (cons 'formatted (number->string msti-bridge-id-priority))))
        (cons 'msti-port-id (list (cons 'raw msti-port-id) (cons 'formatted (fmt-hex msti-port-id))))
        )))

    (catch (e)
      (err (str "BPDU parse error: " e)))))

;; dissect-bpdu: parse BPDU from bytevector
;; Returns (ok fields-alist) or (err message)