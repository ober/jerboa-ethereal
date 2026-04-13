;; packet-netbios.c
;; Routines for NetBIOS protocol packet disassembly
;; Jeff Foster <jfoste@woodward.com>
;; Copyright 1999 Jeffrey C. Foster
;;
;; derived from the packet-nbns.c
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/netbios.ss
;; Auto-generated from wireshark/epan/dissectors/packet-netbios.c

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
(def (dissect-netbios buffer)
  "NetBIOS"
  (try
    (let* (
           (flags (unwrap (read-u8 buffer 0)))
           (no-receive-flags (unwrap (read-u8 buffer 0)))
           (xmit-corrl (unwrap (read-u16be buffer 0)))
           (resp-corrl (unwrap (read-u16be buffer 0)))
           (local-ses-no (unwrap (read-u8 buffer 0)))
           (remote-ses-no (unwrap (read-u8 buffer 0)))
           (resync-indicator (unwrap (read-u16be buffer 0)))
           (status-request (unwrap (read-u8 buffer 0)))
           (local-session-no (unwrap (read-u8 buffer 0)))
           (state-of-name (unwrap (read-u8 buffer 0)))
           (status-response (unwrap (read-u8 buffer 0)))
           (data2 (unwrap (read-u16be buffer 0)))
           (data2-frame (unwrap (read-u8 buffer 0)))
           (data2-user (unwrap (read-u8 buffer 0)))
           (data2-status (unwrap (read-u16be buffer 0)))
           (hdr-len (unwrap (read-u16be buffer 0)))
           (delimiter (unwrap (read-u16be buffer 0)))
           (nb-name (unwrap (slice buffer 2 15)))
           )

      (ok (list
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'no-receive-flags (list (cons 'raw no-receive-flags) (cons 'formatted (fmt-hex no-receive-flags))))
        (cons 'xmit-corrl (list (cons 'raw xmit-corrl) (cons 'formatted (fmt-hex xmit-corrl))))
        (cons 'resp-corrl (list (cons 'raw resp-corrl) (cons 'formatted (fmt-hex resp-corrl))))
        (cons 'local-ses-no (list (cons 'raw local-ses-no) (cons 'formatted (fmt-hex local-ses-no))))
        (cons 'remote-ses-no (list (cons 'raw remote-ses-no) (cons 'formatted (fmt-hex remote-ses-no))))
        (cons 'resync-indicator (list (cons 'raw resync-indicator) (cons 'formatted (fmt-hex resync-indicator))))
        (cons 'status-request (list (cons 'raw status-request) (cons 'formatted (number->string status-request))))
        (cons 'local-session-no (list (cons 'raw local-session-no) (cons 'formatted (fmt-hex local-session-no))))
        (cons 'state-of-name (list (cons 'raw state-of-name) (cons 'formatted (fmt-hex state-of-name))))
        (cons 'status-response (list (cons 'raw status-response) (cons 'formatted (number->string status-response))))
        (cons 'data2 (list (cons 'raw data2) (cons 'formatted (fmt-hex data2))))
        (cons 'data2-frame (list (cons 'raw data2-frame) (cons 'formatted (if (= data2-frame 0) "False" "True"))))
        (cons 'data2-user (list (cons 'raw data2-user) (cons 'formatted (if (= data2-user 0) "False" "True"))))
        (cons 'data2-status (list (cons 'raw data2-status) (cons 'formatted (number->string data2-status))))
        (cons 'hdr-len (list (cons 'raw hdr-len) (cons 'formatted (number->string hdr-len))))
        (cons 'delimiter (list (cons 'raw delimiter) (cons 'formatted (fmt-hex delimiter))))
        (cons 'nb-name (list (cons 'raw nb-name) (cons 'formatted (utf8->string nb-name))))
        )))

    (catch (e)
      (err (str "NETBIOS parse error: " e)))))

;; dissect-netbios: parse NETBIOS from bytevector
;; Returns (ok fields-alist) or (err message)