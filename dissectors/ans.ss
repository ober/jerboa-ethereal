;; packet-ans.c
;; Routines for Intel ANS probe dissection
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 2003 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; The following information was graciously provided by Intel:
;; Offset    Size (bytes)    Contents
;; 0         6               Destination Broadcast probes: {FF,FF,FF,FF,FF,FF}
;; Multicast probes: {01,AA,00,00,00,00}
;; 6         6               Source Matches the CurrentMACAddress of the
;; adapter sending the probe.
;; 8         2               Type Network order is 0x886D, Intel's reserved
;; packet type.
;; 10 (0)    2               ApplicationID Network order is 0x0001, identifies
;; it as fault tolerance probe.
;; 12 (2)    2               RevID Network order, identifies the revision id
;; of Teaming software.
;; 16 (4)    4               ProbeSequenceNumber Ascending sequence number
;; that identifies the current probing cycle.
;; 20 (8)    2               SenderID Unique ID within a team identifying
;; the member that originally sent the probe.
;; 22 (10)   6               TeamID Unique ID identifying the team in charge
;; of this probe.
;; 28        Padding         Reserved
;;
;;

;; jerboa-ethereal/dissectors/ans.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ans.c

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
(def (dissect-ans buffer)
  "Intel ANS probe"
  (try
    (let* (
           (app-id (unwrap (read-u16be buffer 0)))
           (rev-id (unwrap (read-u16be buffer 2)))
           (seq-num (unwrap (read-u32be buffer 4)))
           (sender-id (unwrap (read-u16be buffer 8)))
           (team-id (unwrap (slice buffer 10 6)))
           )

      (ok (list
        (cons 'app-id (list (cons 'raw app-id) (cons 'formatted (fmt-hex app-id))))
        (cons 'rev-id (list (cons 'raw rev-id) (cons 'formatted (fmt-hex rev-id))))
        (cons 'seq-num (list (cons 'raw seq-num) (cons 'formatted (number->string seq-num))))
        (cons 'sender-id (list (cons 'raw sender-id) (cons 'formatted (number->string sender-id))))
        (cons 'team-id (list (cons 'raw team-id) (cons 'formatted (fmt-mac team-id))))
        )))

    (catch (e)
      (err (str "ANS parse error: " e)))))

;; dissect-ans: parse ANS from bytevector
;; Returns (ok fields-alist) or (err message)