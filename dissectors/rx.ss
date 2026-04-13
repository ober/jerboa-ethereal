;; packet-rx.c
;; Routines for RX packet dissection
;; Copyright 1999, Nathan Neulinger <nneul@umr.edu>
;; Based on routines from tcpdump patches by
;; Ken Hornstein <kenh@cmf.nrl.navy.mil>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-tftp.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rx.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rx.c

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
(def (dissect-rx buffer)
  "RX Protocol"
  (try
    (let* (
           (cid (unwrap (read-u32be buffer 4)))
           (callnumber (unwrap (read-u32be buffer 8)))
           (seq (unwrap (read-u32be buffer 12)))
           (serial (unwrap (read-u32be buffer 16)))
           (inc-nonce (unwrap (read-u32be buffer 20)))
           (userstatus (unwrap (read-u32be buffer 21)))
           (securityindex (unwrap (read-u32be buffer 22)))
           (spare (unwrap (read-u16be buffer 23)))
           (level (unwrap (read-u32be buffer 24)))
           (serviceid (unwrap (read-u16be buffer 25)))
           (kvno (unwrap (read-u32be buffer 36)))
           (ticket-len (unwrap (read-u32be buffer 40)))
           (ticket (unwrap (slice buffer 44 1)))
           (abortcode (unwrap (read-u32be buffer 44)))
           (version (unwrap (read-u32be buffer 48)))
           (nonce (unwrap (read-u32be buffer 52)))
           (min-level (unwrap (read-u32be buffer 56)))
           (bufferspace (unwrap (read-u16be buffer 60)))
           (maxskew (unwrap (read-u16be buffer 62)))
           (first-packet (unwrap (read-u32be buffer 64)))
           (prev-packet (unwrap (read-u32be buffer 68)))
           (numacks (unwrap (read-u8 buffer 77)))
           (maxmtu (unwrap (read-u32be buffer 82)))
           (ifmtu (unwrap (read-u32be buffer 86)))
           (rwind (unwrap (read-u32be buffer 90)))
           (maxpackets (unwrap (read-u32be buffer 94)))
           (flags (unwrap (read-u8 buffer 98)))
           (flags-free-packet (extract-bits flags 0x0 0))
           (flags-more-packets (extract-bits flags 0x0 0))
           (flags-last-packet (extract-bits flags 0x0 0))
           (flags-request-ack (extract-bits flags 0x0 0))
           (flags-clientinit (extract-bits flags 0x0 0))
           )

      (ok (list
        (cons 'cid (list (cons 'raw cid) (cons 'formatted (number->string cid))))
        (cons 'callnumber (list (cons 'raw callnumber) (cons 'formatted (number->string callnumber))))
        (cons 'seq (list (cons 'raw seq) (cons 'formatted (number->string seq))))
        (cons 'serial (list (cons 'raw serial) (cons 'formatted (number->string serial))))
        (cons 'inc-nonce (list (cons 'raw inc-nonce) (cons 'formatted (fmt-hex inc-nonce))))
        (cons 'userstatus (list (cons 'raw userstatus) (cons 'formatted (number->string userstatus))))
        (cons 'securityindex (list (cons 'raw securityindex) (cons 'formatted (number->string securityindex))))
        (cons 'spare (list (cons 'raw spare) (cons 'formatted (number->string spare))))
        (cons 'level (list (cons 'raw level) (cons 'formatted (number->string level))))
        (cons 'serviceid (list (cons 'raw serviceid) (cons 'formatted (number->string serviceid))))
        (cons 'kvno (list (cons 'raw kvno) (cons 'formatted (number->string kvno))))
        (cons 'ticket-len (list (cons 'raw ticket-len) (cons 'formatted (number->string ticket-len))))
        (cons 'ticket (list (cons 'raw ticket) (cons 'formatted (fmt-bytes ticket))))
        (cons 'abortcode (list (cons 'raw abortcode) (cons 'formatted (number->string abortcode))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'nonce (list (cons 'raw nonce) (cons 'formatted (fmt-hex nonce))))
        (cons 'min-level (list (cons 'raw min-level) (cons 'formatted (number->string min-level))))
        (cons 'bufferspace (list (cons 'raw bufferspace) (cons 'formatted (number->string bufferspace))))
        (cons 'maxskew (list (cons 'raw maxskew) (cons 'formatted (number->string maxskew))))
        (cons 'first-packet (list (cons 'raw first-packet) (cons 'formatted (number->string first-packet))))
        (cons 'prev-packet (list (cons 'raw prev-packet) (cons 'formatted (number->string prev-packet))))
        (cons 'numacks (list (cons 'raw numacks) (cons 'formatted (number->string numacks))))
        (cons 'maxmtu (list (cons 'raw maxmtu) (cons 'formatted (number->string maxmtu))))
        (cons 'ifmtu (list (cons 'raw ifmtu) (cons 'formatted (number->string ifmtu))))
        (cons 'rwind (list (cons 'raw rwind) (cons 'formatted (number->string rwind))))
        (cons 'maxpackets (list (cons 'raw maxpackets) (cons 'formatted (number->string maxpackets))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flags-free-packet (list (cons 'raw flags-free-packet) (cons 'formatted (if (= flags-free-packet 0) "Not set" "Set"))))
        (cons 'flags-more-packets (list (cons 'raw flags-more-packets) (cons 'formatted (if (= flags-more-packets 0) "Not set" "Set"))))
        (cons 'flags-last-packet (list (cons 'raw flags-last-packet) (cons 'formatted (if (= flags-last-packet 0) "Not set" "Set"))))
        (cons 'flags-request-ack (list (cons 'raw flags-request-ack) (cons 'formatted (if (= flags-request-ack 0) "Not set" "Set"))))
        (cons 'flags-clientinit (list (cons 'raw flags-clientinit) (cons 'formatted (if (= flags-clientinit 0) "Not set" "Set"))))
        )))

    (catch (e)
      (err (str "RX parse error: " e)))))

;; dissect-rx: parse RX from bytevector
;; Returns (ok fields-alist) or (err message)