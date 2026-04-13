;; packet-devicenet.c
;; Routines for dissection of DeviceNet
;; DeviceNet Home: www.odva.org
;;
;; This dissector includes items from:
;; CIP Volume 3: DeviceNet Adaptation of CIP, Edition 1.14
;;
;; Michael Mann
;; Erik Ivarsson <eriki@student.chalmers.se>
;; Hans-Jorgen Gunnarsson <hag@hms.se>
;; Copyright 2012
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/devicenet.ss
;; Auto-generated from wireshark/epan/dissectors/packet-devicenet.c

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
(def (dissect-devicenet buffer)
  "DeviceNet Protocol"
  (try
    (let* (
           (grp-msg4-id (unwrap (read-u16be buffer 0)))
           (grp-msg3-id (unwrap (read-u16be buffer 0)))
           (grp-msg2-id (unwrap (read-u16be buffer 0)))
           (src-mac-id (unwrap (read-u8 buffer 0)))
           (grp-msg1-id (unwrap (read-u16be buffer 0)))
           (can-id (unwrap (read-u16be buffer 0)))
           (dup-mac-id-physical-port-number (unwrap (read-u8 buffer 0)))
           (dup-mac-id-serial-number (unwrap (read-u32be buffer 2)))
           (grp-msg3-frag (unwrap (read-u8 buffer 2)))
           (grp-msg3-xid (unwrap (read-u8 buffer 2)))
           (grp-msg3-dest-mac-id (unwrap (read-u8 buffer 2)))
           (fragment-count (unwrap (read-u8 buffer 2)))
           (open-exp-msg-reserved (unwrap (read-u8 buffer 2)))
           (open-exp-dest-message-id (unwrap (read-u8 buffer 2)))
           (open-exp-src-message-id (unwrap (read-u8 buffer 2)))
           (connection-id (unwrap (read-u16be buffer 2)))
           (data (unwrap (slice buffer 2 1)))
           (comm-fault-rsv (unwrap (read-u8 buffer 2)))
           (comm-fault-match (unwrap (read-u8 buffer 2)))
           (comm-fault-value (unwrap (read-u8 buffer 2)))
           (offline-ownership-reserved (unwrap (read-u8 buffer 4)))
           (offline-ownership-client-mac-id (unwrap (read-u8 buffer 4)))
           (offline-ownership-allocate (unwrap (read-u8 buffer 4)))
           (serial-number (unwrap (read-u32be buffer 6)))
           )

      (ok (list
        (cons 'grp-msg4-id (list (cons 'raw grp-msg4-id) (cons 'formatted (number->string grp-msg4-id))))
        (cons 'grp-msg3-id (list (cons 'raw grp-msg3-id) (cons 'formatted (number->string grp-msg3-id))))
        (cons 'grp-msg2-id (list (cons 'raw grp-msg2-id) (cons 'formatted (number->string grp-msg2-id))))
        (cons 'src-mac-id (list (cons 'raw src-mac-id) (cons 'formatted (number->string src-mac-id))))
        (cons 'grp-msg1-id (list (cons 'raw grp-msg1-id) (cons 'formatted (number->string grp-msg1-id))))
        (cons 'can-id (list (cons 'raw can-id) (cons 'formatted (fmt-hex can-id))))
        (cons 'dup-mac-id-physical-port-number (list (cons 'raw dup-mac-id-physical-port-number) (cons 'formatted (number->string dup-mac-id-physical-port-number))))
        (cons 'dup-mac-id-serial-number (list (cons 'raw dup-mac-id-serial-number) (cons 'formatted (fmt-hex dup-mac-id-serial-number))))
        (cons 'grp-msg3-frag (list (cons 'raw grp-msg3-frag) (cons 'formatted (number->string grp-msg3-frag))))
        (cons 'grp-msg3-xid (list (cons 'raw grp-msg3-xid) (cons 'formatted (number->string grp-msg3-xid))))
        (cons 'grp-msg3-dest-mac-id (list (cons 'raw grp-msg3-dest-mac-id) (cons 'formatted (number->string grp-msg3-dest-mac-id))))
        (cons 'fragment-count (list (cons 'raw fragment-count) (cons 'formatted (fmt-hex fragment-count))))
        (cons 'open-exp-msg-reserved (list (cons 'raw open-exp-msg-reserved) (cons 'formatted (number->string open-exp-msg-reserved))))
        (cons 'open-exp-dest-message-id (list (cons 'raw open-exp-dest-message-id) (cons 'formatted (number->string open-exp-dest-message-id))))
        (cons 'open-exp-src-message-id (list (cons 'raw open-exp-src-message-id) (cons 'formatted (number->string open-exp-src-message-id))))
        (cons 'connection-id (list (cons 'raw connection-id) (cons 'formatted (number->string connection-id))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'comm-fault-rsv (list (cons 'raw comm-fault-rsv) (cons 'formatted (fmt-hex comm-fault-rsv))))
        (cons 'comm-fault-match (list (cons 'raw comm-fault-match) (cons 'formatted (fmt-hex comm-fault-match))))
        (cons 'comm-fault-value (list (cons 'raw comm-fault-value) (cons 'formatted (fmt-hex comm-fault-value))))
        (cons 'offline-ownership-reserved (list (cons 'raw offline-ownership-reserved) (cons 'formatted (fmt-hex offline-ownership-reserved))))
        (cons 'offline-ownership-client-mac-id (list (cons 'raw offline-ownership-client-mac-id) (cons 'formatted (fmt-hex offline-ownership-client-mac-id))))
        (cons 'offline-ownership-allocate (list (cons 'raw offline-ownership-allocate) (cons 'formatted (fmt-hex offline-ownership-allocate))))
        (cons 'serial-number (list (cons 'raw serial-number) (cons 'formatted (fmt-hex serial-number))))
        )))

    (catch (e)
      (err (str "DEVICENET parse error: " e)))))

;; dissect-devicenet: parse DEVICENET from bytevector
;; Returns (ok fields-alist) or (err message)