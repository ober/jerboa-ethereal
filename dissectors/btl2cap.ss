;; packet-btl2cap.c
;; Routines for the Bluetooth L2CAP dissection
;; Copyright 2002, Christoph Scholz <scholz@cs.uni-bonn.de>
;; From: http://affix.sourceforge.net/archive/ethereal_affix-3.patch
;;
;; Refactored for wireshark checkin
;; Ronnie Sahlberg 2006
;;
;; Added handling and reassembly of LE-Frames
;; Anders Broman at ericsson dot com 2016
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/btl2cap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-btl2cap.c

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
(def (dissect-btl2cap buffer)
  "Bluetooth L2CAP Protocol"
  (try
    (let* (
           (continuation-to (unwrap (read-u32be buffer 0)))
           (reassembled-in (unwrap (read-u32be buffer 0)))
           (connect-in-frame (unwrap (read-u32be buffer 0)))
           (disconnect-in-frame (unwrap (read-u32be buffer 0)))
           (length (unwrap (read-u16be buffer 0)))
           (sig-mtu (unwrap (read-u16be buffer 2)))
           (cmd-ident (unwrap (read-u8 buffer 5)))
           (cmd-length (unwrap (read-u16be buffer 6)))
           (data (unwrap (slice buffer 8 1)))
           (credits (unwrap (read-u16be buffer 10)))
           (control-field (unwrap (read-u16le buffer 14)))
           (payload (unwrap (slice buffer 16 1)))
           (initial-credits (unwrap (read-u16be buffer 47)))
           (option-length (unwrap (read-u8 buffer 56)))
           (option-mtu (unwrap (read-u16be buffer 58)))
           (option-flushTO (unwrap (read-u16be buffer 60)))
           (option-flags (unwrap (read-u8 buffer 62)))
           (option-tokenrate (unwrap (read-u32be buffer 64)))
           (option-tokenbucketsize (unwrap (read-u32be buffer 68)))
           (option-peakbandwidth (unwrap (read-u32be buffer 72)))
           (option-latency (unwrap (read-u32be buffer 76)))
           (option-delayvariation (unwrap (read-u32be buffer 80)))
           (option-txwindow (unwrap (read-u8 buffer 85)))
           (option-maxtransmit (unwrap (read-u8 buffer 86)))
           (option-retransmittimeout (unwrap (read-u16be buffer 87)))
           (option-monitortimeout (unwrap (read-u16be buffer 89)))
           (option-mps (unwrap (read-u16be buffer 91)))
           (option-identifier (unwrap (read-u8 buffer 94)))
           (option-sdu-size (unwrap (read-u16be buffer 96)))
           (option-sdu-arrival-time (unwrap (read-u32be buffer 98)))
           (option-access-latency (unwrap (read-u32be buffer 102)))
           (option-flush-to-us (unwrap (read-u32be buffer 106)))
           (option-window (unwrap (read-u16be buffer 110)))
           (info-mtu (unwrap (read-u16be buffer 122)))
           (info-flowcontrol (unwrap (read-u32be buffer 124)))
           (info-retransmission (unwrap (read-u32be buffer 124)))
           (info-bidirqos (unwrap (read-u32be buffer 124)))
           (info-enh-retransmission (unwrap (read-u32be buffer 124)))
           (info-streaming (unwrap (read-u32be buffer 124)))
           (info-fcs (unwrap (read-u32be buffer 124)))
           (info-flow-spec (unwrap (read-u32be buffer 124)))
           (info-fixedchan (unwrap (read-u32be buffer 124)))
           (info-window (unwrap (read-u32be buffer 124)))
           (info-unicast (unwrap (read-u32be buffer 124)))
           (info-fixedchans-null (unwrap (read-u32be buffer 128)))
           (info-fixedchans-signal (unwrap (read-u32be buffer 128)))
           (info-fixedchans-connless (unwrap (read-u32be buffer 128)))
           (info-fixedchans-amp-man (unwrap (read-u32be buffer 128)))
           (info-fixedchans-rfu (unwrap (read-u32be buffer 128)))
           (info-fixedchans-smp (unwrap (read-u32be buffer 128)))
           (info-fixedchans-amp-test (unwrap (read-u32be buffer 132)))
           (flags-reserved (unwrap (read-u16be buffer 138)))
           (flags-continuation (unwrap (read-u8 buffer 138)))
           (min-interval (unwrap (read-u16be buffer 160)))
           (max-interval (unwrap (read-u16be buffer 162)))
           (timeout-multiplier (unwrap (read-u16be buffer 166)))
           (le-sdu-length (unwrap (read-u16be buffer 174)))
           (sdulength (unwrap (read-u16be buffer 182)))
           (psm-dynamic (unwrap (read-u16be buffer 184)))
           (ext-control-field (unwrap (read-u32le buffer 186)))
           (control-reqseq (extract-bits ext-control-field 0x3F00 8))
           (control-retransmissiondisable (extract-bits ext-control-field 0x80 7))
           (control-txseq (extract-bits ext-control-field 0x7E 1))
           )

      (ok (list
        (cons 'continuation-to (list (cons 'raw continuation-to) (cons 'formatted (number->string continuation-to))))
        (cons 'reassembled-in (list (cons 'raw reassembled-in) (cons 'formatted (number->string reassembled-in))))
        (cons 'connect-in-frame (list (cons 'raw connect-in-frame) (cons 'formatted (number->string connect-in-frame))))
        (cons 'disconnect-in-frame (list (cons 'raw disconnect-in-frame) (cons 'formatted (number->string disconnect-in-frame))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'sig-mtu (list (cons 'raw sig-mtu) (cons 'formatted (number->string sig-mtu))))
        (cons 'cmd-ident (list (cons 'raw cmd-ident) (cons 'formatted (fmt-hex cmd-ident))))
        (cons 'cmd-length (list (cons 'raw cmd-length) (cons 'formatted (number->string cmd-length))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'credits (list (cons 'raw credits) (cons 'formatted (number->string credits))))
        (cons 'control-field (list (cons 'raw control-field) (cons 'formatted (fmt-hex control-field))))
        (cons 'payload (list (cons 'raw payload) (cons 'formatted (fmt-bytes payload))))
        (cons 'initial-credits (list (cons 'raw initial-credits) (cons 'formatted (number->string initial-credits))))
        (cons 'option-length (list (cons 'raw option-length) (cons 'formatted (number->string option-length))))
        (cons 'option-mtu (list (cons 'raw option-mtu) (cons 'formatted (number->string option-mtu))))
        (cons 'option-flushTO (list (cons 'raw option-flushTO) (cons 'formatted (number->string option-flushTO))))
        (cons 'option-flags (list (cons 'raw option-flags) (cons 'formatted (fmt-hex option-flags))))
        (cons 'option-tokenrate (list (cons 'raw option-tokenrate) (cons 'formatted (number->string option-tokenrate))))
        (cons 'option-tokenbucketsize (list (cons 'raw option-tokenbucketsize) (cons 'formatted (number->string option-tokenbucketsize))))
        (cons 'option-peakbandwidth (list (cons 'raw option-peakbandwidth) (cons 'formatted (number->string option-peakbandwidth))))
        (cons 'option-latency (list (cons 'raw option-latency) (cons 'formatted (number->string option-latency))))
        (cons 'option-delayvariation (list (cons 'raw option-delayvariation) (cons 'formatted (number->string option-delayvariation))))
        (cons 'option-txwindow (list (cons 'raw option-txwindow) (cons 'formatted (number->string option-txwindow))))
        (cons 'option-maxtransmit (list (cons 'raw option-maxtransmit) (cons 'formatted (number->string option-maxtransmit))))
        (cons 'option-retransmittimeout (list (cons 'raw option-retransmittimeout) (cons 'formatted (number->string option-retransmittimeout))))
        (cons 'option-monitortimeout (list (cons 'raw option-monitortimeout) (cons 'formatted (number->string option-monitortimeout))))
        (cons 'option-mps (list (cons 'raw option-mps) (cons 'formatted (number->string option-mps))))
        (cons 'option-identifier (list (cons 'raw option-identifier) (cons 'formatted (fmt-hex option-identifier))))
        (cons 'option-sdu-size (list (cons 'raw option-sdu-size) (cons 'formatted (number->string option-sdu-size))))
        (cons 'option-sdu-arrival-time (list (cons 'raw option-sdu-arrival-time) (cons 'formatted (number->string option-sdu-arrival-time))))
        (cons 'option-access-latency (list (cons 'raw option-access-latency) (cons 'formatted (number->string option-access-latency))))
        (cons 'option-flush-to-us (list (cons 'raw option-flush-to-us) (cons 'formatted (number->string option-flush-to-us))))
        (cons 'option-window (list (cons 'raw option-window) (cons 'formatted (number->string option-window))))
        (cons 'info-mtu (list (cons 'raw info-mtu) (cons 'formatted (number->string info-mtu))))
        (cons 'info-flowcontrol (list (cons 'raw info-flowcontrol) (cons 'formatted (number->string info-flowcontrol))))
        (cons 'info-retransmission (list (cons 'raw info-retransmission) (cons 'formatted (number->string info-retransmission))))
        (cons 'info-bidirqos (list (cons 'raw info-bidirqos) (cons 'formatted (number->string info-bidirqos))))
        (cons 'info-enh-retransmission (list (cons 'raw info-enh-retransmission) (cons 'formatted (number->string info-enh-retransmission))))
        (cons 'info-streaming (list (cons 'raw info-streaming) (cons 'formatted (number->string info-streaming))))
        (cons 'info-fcs (list (cons 'raw info-fcs) (cons 'formatted (number->string info-fcs))))
        (cons 'info-flow-spec (list (cons 'raw info-flow-spec) (cons 'formatted (number->string info-flow-spec))))
        (cons 'info-fixedchan (list (cons 'raw info-fixedchan) (cons 'formatted (number->string info-fixedchan))))
        (cons 'info-window (list (cons 'raw info-window) (cons 'formatted (number->string info-window))))
        (cons 'info-unicast (list (cons 'raw info-unicast) (cons 'formatted (number->string info-unicast))))
        (cons 'info-fixedchans-null (list (cons 'raw info-fixedchans-null) (cons 'formatted (number->string info-fixedchans-null))))
        (cons 'info-fixedchans-signal (list (cons 'raw info-fixedchans-signal) (cons 'formatted (number->string info-fixedchans-signal))))
        (cons 'info-fixedchans-connless (list (cons 'raw info-fixedchans-connless) (cons 'formatted (number->string info-fixedchans-connless))))
        (cons 'info-fixedchans-amp-man (list (cons 'raw info-fixedchans-amp-man) (cons 'formatted (number->string info-fixedchans-amp-man))))
        (cons 'info-fixedchans-rfu (list (cons 'raw info-fixedchans-rfu) (cons 'formatted (number->string info-fixedchans-rfu))))
        (cons 'info-fixedchans-smp (list (cons 'raw info-fixedchans-smp) (cons 'formatted (number->string info-fixedchans-smp))))
        (cons 'info-fixedchans-amp-test (list (cons 'raw info-fixedchans-amp-test) (cons 'formatted (number->string info-fixedchans-amp-test))))
        (cons 'flags-reserved (list (cons 'raw flags-reserved) (cons 'formatted (fmt-hex flags-reserved))))
        (cons 'flags-continuation (list (cons 'raw flags-continuation) (cons 'formatted (number->string flags-continuation))))
        (cons 'min-interval (list (cons 'raw min-interval) (cons 'formatted (number->string min-interval))))
        (cons 'max-interval (list (cons 'raw max-interval) (cons 'formatted (number->string max-interval))))
        (cons 'timeout-multiplier (list (cons 'raw timeout-multiplier) (cons 'formatted (number->string timeout-multiplier))))
        (cons 'le-sdu-length (list (cons 'raw le-sdu-length) (cons 'formatted (number->string le-sdu-length))))
        (cons 'sdulength (list (cons 'raw sdulength) (cons 'formatted (number->string sdulength))))
        (cons 'psm-dynamic (list (cons 'raw psm-dynamic) (cons 'formatted (fmt-hex psm-dynamic))))
        (cons 'ext-control-field (list (cons 'raw ext-control-field) (cons 'formatted (fmt-hex ext-control-field))))
        (cons 'control-reqseq (list (cons 'raw control-reqseq) (cons 'formatted (if (= control-reqseq 0) "Not set" "Set"))))
        (cons 'control-retransmissiondisable (list (cons 'raw control-retransmissiondisable) (cons 'formatted (if (= control-retransmissiondisable 0) "Not set" "Set"))))
        (cons 'control-txseq (list (cons 'raw control-txseq) (cons 'formatted (if (= control-txseq 0) "Not set" "Set"))))
        )))

    (catch (e)
      (err (str "BTL2CAP parse error: " e)))))

;; dissect-btl2cap: parse BTL2CAP from bytevector
;; Returns (ok fields-alist) or (err message)