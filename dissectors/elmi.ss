;; packet-elmi.c
;; Routines for Ethernet Local Management Interface (E-LMI) dissection
;; Copyright 2014, Martin Kaiser <martin@kaiser.cx>
;;
;; based on a dissector written in lua
;; Copyright 2013, Werner Fischer (fischer-interactive.de)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/elmi.ss
;; Auto-generated from wireshark/epan/dissectors/packet-elmi.c

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
(def (dissect-elmi buffer)
  "Ethernet Local Management Interface"
  (try
    (let* (
           (sub-info-elem-len (unwrap (read-u8 buffer 0)))
           (uni-id (unwrap (slice buffer 0 1)))
           (evc-id (unwrap (slice buffer 0 1)))
           (ce-vlan-id (unwrap (read-u16be buffer 0)))
           (ver (unwrap (read-u8 buffer 0)))
           (sub-info-color-mode-flag (unwrap (read-u8 buffer 2)))
           (sub-info-coupling-flag (unwrap (read-u8 buffer 2)))
           (sub-info-per-cos-bit (unwrap (read-u8 buffer 2)))
           (sub-cir-magnitude (unwrap (read-u8 buffer 2)))
           (sub-cir-multiplier (unwrap (read-u16be buffer 2)))
           (sub-cbs-magnitude (unwrap (read-u8 buffer 4)))
           (sub-cbs-multiplier (unwrap (read-u8 buffer 4)))
           (sub-eir-magnitude (unwrap (read-u8 buffer 4)))
           (sub-eir-multiplier (unwrap (read-u16be buffer 4)))
           (sub-ebs-magnitude (unwrap (read-u8 buffer 6)))
           (sub-ebs-multiplier (unwrap (read-u8 buffer 6)))
           (sub-user-prio-0 (unwrap (read-u8 buffer 6)))
           (sub-user-prio-1 (unwrap (read-u8 buffer 6)))
           (sub-user-prio-2 (unwrap (read-u8 buffer 6)))
           (sub-user-prio-3 (unwrap (read-u8 buffer 6)))
           (sub-user-prio-4 (unwrap (read-u8 buffer 6)))
           (sub-user-prio-5 (unwrap (read-u8 buffer 6)))
           (sub-user-prio-6 (unwrap (read-u8 buffer 6)))
           (sub-user-prio-7 (unwrap (read-u8 buffer 6)))
           (info-elem-len (unwrap (read-u8 buffer 6)))
           (snd-seq-num (unwrap (read-u8 buffer 6)))
           (rcv-seq-num (unwrap (read-u8 buffer 6)))
           (reserved (unwrap (read-u8 buffer 6)))
           (dat-inst (unwrap (read-u32be buffer 6)))
           (evc-refid (unwrap (read-u16be buffer 12)))
           (ie (unwrap (read-u8 buffer 14)))
           (seq (unwrap (read-u8 buffer 14)))
           (hf-priority (unwrap (read-u8 buffer 14)))
           (evc (unwrap (read-u8 buffer 14)))
           )

      (ok (list
        (cons 'sub-info-elem-len (list (cons 'raw sub-info-elem-len) (cons 'formatted (number->string sub-info-elem-len))))
        (cons 'uni-id (list (cons 'raw uni-id) (cons 'formatted (utf8->string uni-id))))
        (cons 'evc-id (list (cons 'raw evc-id) (cons 'formatted (utf8->string evc-id))))
        (cons 'ce-vlan-id (list (cons 'raw ce-vlan-id) (cons 'formatted (number->string ce-vlan-id))))
        (cons 'ver (list (cons 'raw ver) (cons 'formatted (number->string ver))))
        (cons 'sub-info-color-mode-flag (list (cons 'raw sub-info-color-mode-flag) (cons 'formatted (if (= sub-info-color-mode-flag 0) "False" "True"))))
        (cons 'sub-info-coupling-flag (list (cons 'raw sub-info-coupling-flag) (cons 'formatted (if (= sub-info-coupling-flag 0) "False" "True"))))
        (cons 'sub-info-per-cos-bit (list (cons 'raw sub-info-per-cos-bit) (cons 'formatted (if (= sub-info-per-cos-bit 0) "False" "True"))))
        (cons 'sub-cir-magnitude (list (cons 'raw sub-cir-magnitude) (cons 'formatted (number->string sub-cir-magnitude))))
        (cons 'sub-cir-multiplier (list (cons 'raw sub-cir-multiplier) (cons 'formatted (number->string sub-cir-multiplier))))
        (cons 'sub-cbs-magnitude (list (cons 'raw sub-cbs-magnitude) (cons 'formatted (number->string sub-cbs-magnitude))))
        (cons 'sub-cbs-multiplier (list (cons 'raw sub-cbs-multiplier) (cons 'formatted (number->string sub-cbs-multiplier))))
        (cons 'sub-eir-magnitude (list (cons 'raw sub-eir-magnitude) (cons 'formatted (number->string sub-eir-magnitude))))
        (cons 'sub-eir-multiplier (list (cons 'raw sub-eir-multiplier) (cons 'formatted (number->string sub-eir-multiplier))))
        (cons 'sub-ebs-magnitude (list (cons 'raw sub-ebs-magnitude) (cons 'formatted (number->string sub-ebs-magnitude))))
        (cons 'sub-ebs-multiplier (list (cons 'raw sub-ebs-multiplier) (cons 'formatted (number->string sub-ebs-multiplier))))
        (cons 'sub-user-prio-0 (list (cons 'raw sub-user-prio-0) (cons 'formatted (if (= sub-user-prio-0 0) "False" "True"))))
        (cons 'sub-user-prio-1 (list (cons 'raw sub-user-prio-1) (cons 'formatted (if (= sub-user-prio-1 0) "False" "True"))))
        (cons 'sub-user-prio-2 (list (cons 'raw sub-user-prio-2) (cons 'formatted (if (= sub-user-prio-2 0) "False" "True"))))
        (cons 'sub-user-prio-3 (list (cons 'raw sub-user-prio-3) (cons 'formatted (if (= sub-user-prio-3 0) "False" "True"))))
        (cons 'sub-user-prio-4 (list (cons 'raw sub-user-prio-4) (cons 'formatted (if (= sub-user-prio-4 0) "False" "True"))))
        (cons 'sub-user-prio-5 (list (cons 'raw sub-user-prio-5) (cons 'formatted (if (= sub-user-prio-5 0) "False" "True"))))
        (cons 'sub-user-prio-6 (list (cons 'raw sub-user-prio-6) (cons 'formatted (if (= sub-user-prio-6 0) "False" "True"))))
        (cons 'sub-user-prio-7 (list (cons 'raw sub-user-prio-7) (cons 'formatted (if (= sub-user-prio-7 0) "False" "True"))))
        (cons 'info-elem-len (list (cons 'raw info-elem-len) (cons 'formatted (number->string info-elem-len))))
        (cons 'snd-seq-num (list (cons 'raw snd-seq-num) (cons 'formatted (number->string snd-seq-num))))
        (cons 'rcv-seq-num (list (cons 'raw rcv-seq-num) (cons 'formatted (number->string rcv-seq-num))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-hex reserved))))
        (cons 'dat-inst (list (cons 'raw dat-inst) (cons 'formatted (fmt-hex dat-inst))))
        (cons 'evc-refid (list (cons 'raw evc-refid) (cons 'formatted (number->string evc-refid))))
        (cons 'ie (list (cons 'raw ie) (cons 'formatted (if (= ie 0) "False" "True"))))
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (number->string seq))))
        (cons 'hf-priority (list (cons 'raw hf-priority) (cons 'formatted (if (= hf-priority 0) "False" "True"))))
        (cons 'evc (list (cons 'raw evc) (cons 'formatted (if (= evc 0) "False" "True"))))
        )))

    (catch (e)
      (err (str "ELMI parse error: " e)))))

;; dissect-elmi: parse ELMI from bytevector
;; Returns (ok fields-alist) or (err message)