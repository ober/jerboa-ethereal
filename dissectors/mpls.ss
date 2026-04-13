;; packet-mpls.c
;; Routines for MPLS data packet disassembly
;; RFC 3032
;;
;; (c) Copyright Ashok Narayanan <ashokn@cisco.com>
;;
;; (c) Copyright 2006, _FF_ Francesco Fondelli <francesco.fondelli@gmail.com>
;; - added MPLS OAM support, ITU-T Y.1711
;; - PW Associated Channel Header dissection as per RFC 4385
;; - PW MPLS Control Word dissection as per RFC 4385
;; - mpls subdissector table indexed by label value
;; - enhanced "what's past last mpls label?" heuristic
;;
;; (c) Copyright 2011, Shobhank Sharma <ssharma5@ncsu.edu>
;; - Removed some mpls preferences which are no longer relevant/needed like
;; decode PWAC payloads as PPP traffic and assume all channel types except
;; 0x21 are raw BFD.
;; - MPLS extension from PW-ACH to MPLS Generic Associated Channel as per RFC 5586
;; - Updated Pseudowire Associated Channel Types as per http://www.iana.org/assignments/pwe3-parameters
;;
;; (c) Copyright 2011, Jaihari Kalijanakiraman <jaiharik@ipinfusion.com>
;; Krishnamurthy Mayya <krishnamurthy.mayya@ipinfusion.com>
;; Nikitha Malgi       <malgi.nikitha@ipinfusion.com>
;; - Identification of BFD CC, BFD CV and ON-Demand CV ACH types as per RFC 6428, RFC 6426
;; respectively and the corresponding decoding of messages
;; - Decoding support for MPLS-TP Lock Instruct as per RFC 6435
;; - Decoding support for MPLS-TP Fault-Management as per RFC 6427
;;
;; (c) Copyright 2012, Aditya Ambadkar and Diana Chris <arambadk,dvchris@ncsu.edu>
;; -  Added preference to select BOS label as flowlabel as per RFC 6391
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mpls.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mpls.c
;; RFC 3032

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
(def (dissect-mpls buffer)
  "MultiProtocol Label Switching Header"
  (try
    (let* (
           (pw-mcw-flags (unwrap (read-u16be buffer 0)))
           (pw-ach-ver (unwrap (read-u8 buffer 0)))
           (label (unwrap (read-u32be buffer 0)))
           (exp (unwrap (read-u32be buffer 0)))
           (bos (unwrap (read-u32be buffer 0)))
           (ttl (unwrap (read-u32be buffer 0)))
           (pw-mcw-length (unwrap (read-u8 buffer 1)))
           (pw-ach-res (unwrap (read-u8 buffer 1)))
           (pw-mcw-sequence-number (unwrap (read-u16be buffer 2)))
           )

      (ok (list
        (cons 'pw-mcw-flags (list (cons 'raw pw-mcw-flags) (cons 'formatted (fmt-hex pw-mcw-flags))))
        (cons 'pw-ach-ver (list (cons 'raw pw-ach-ver) (cons 'formatted (number->string pw-ach-ver))))
        (cons 'label (list (cons 'raw label) (cons 'formatted (number->string label))))
        (cons 'exp (list (cons 'raw exp) (cons 'formatted (number->string exp))))
        (cons 'bos (list (cons 'raw bos) (cons 'formatted (number->string bos))))
        (cons 'ttl (list (cons 'raw ttl) (cons 'formatted (number->string ttl))))
        (cons 'pw-mcw-length (list (cons 'raw pw-mcw-length) (cons 'formatted (number->string pw-mcw-length))))
        (cons 'pw-ach-res (list (cons 'raw pw-ach-res) (cons 'formatted (fmt-hex pw-ach-res))))
        (cons 'pw-mcw-sequence-number (list (cons 'raw pw-mcw-sequence-number) (cons 'formatted (number->string pw-mcw-sequence-number))))
        )))

    (catch (e)
      (err (str "MPLS parse error: " e)))))

;; dissect-mpls: parse MPLS from bytevector
;; Returns (ok fields-alist) or (err message)