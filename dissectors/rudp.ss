;; packet-rudp.c
;; Routines for Reliable UDP Protocol.
;; Copyright 2004, Duncan Sargeant <dunc-ethereal@rcpt.to>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-data.c, README.developer, and various other files.
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;;
;; Reliable UDP is a lightweight protocol for providing TCP-like flow
;; control over UDP.  Cisco published an PFC a long time ago, and
;; their actual implementation is slightly different, having no
;; checksum field.
;;
;; I've cheated here - RUDP could be used for anything, but I've only
;; seen it used to switched telephony calls, so we just call the Cisco SM
;; dissector from here.
;;
;; Here are some links:
;;
;; http://www.watersprings.org/pub/id/draft-ietf-sigtran-reliable-udp-00.txt
;; http://www.javvin.com/protocolRUDP.html
;; http://www.cisco.com/univercd/cc/td/doc/product/access/sc/rel7/omts/omts_apb.htm#30052
;;
;;

;; jerboa-ethereal/dissectors/rudp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rudp.c

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
(def (dissect-rudp buffer)
  "Reliable UDP"
  (try
    (let* (
           (flags (unwrap (read-u8 buffer 0)))
           (flags-syn (extract-bits flags 0x80 7))
           (flags-ack (extract-bits flags 0x40 6))
           (flags-eak (extract-bits flags 0x20 5))
           (flags-rst (extract-bits flags 0x10 4))
           (flags-nul (extract-bits flags 0x8 3))
           (flags-chk (extract-bits flags 0x4 2))
           (flags-tcs (extract-bits flags 0x2 1))
           (flags-0 (extract-bits flags 0x1 0))
           (hlen (unwrap (read-u8 buffer 1)))
           (seq (unwrap (read-u8 buffer 2)))
           (ack (unwrap (read-u8 buffer 3)))
           )

      (ok (list
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (number->string flags))))
        (cons 'flags-syn (list (cons 'raw flags-syn) (cons 'formatted (if (= flags-syn 0) "Not set" "Set"))))
        (cons 'flags-ack (list (cons 'raw flags-ack) (cons 'formatted (if (= flags-ack 0) "Not set" "Set"))))
        (cons 'flags-eak (list (cons 'raw flags-eak) (cons 'formatted (if (= flags-eak 0) "Not set" "Set"))))
        (cons 'flags-rst (list (cons 'raw flags-rst) (cons 'formatted (if (= flags-rst 0) "Not set" "Set"))))
        (cons 'flags-nul (list (cons 'raw flags-nul) (cons 'formatted (if (= flags-nul 0) "Not set" "Set"))))
        (cons 'flags-chk (list (cons 'raw flags-chk) (cons 'formatted (if (= flags-chk 0) "Not set" "Set"))))
        (cons 'flags-tcs (list (cons 'raw flags-tcs) (cons 'formatted (if (= flags-tcs 0) "Not set" "Set"))))
        (cons 'flags-0 (list (cons 'raw flags-0) (cons 'formatted (if (= flags-0 0) "Not set" "Set"))))
        (cons 'hlen (list (cons 'raw hlen) (cons 'formatted (number->string hlen))))
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (number->string seq))))
        (cons 'ack (list (cons 'raw ack) (cons 'formatted (number->string ack))))
        )))

    (catch (e)
      (err (str "RUDP parse error: " e)))))

;; dissect-rudp: parse RUDP from bytevector
;; Returns (ok fields-alist) or (err message)