;;
;; packet-ieee80211-netmon.c
;; Decode packets with a Network Monitor 802.11 radio header
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ieee80211-netmon.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ieee80211_netmon.c

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
(def (dissect-ieee80211-netmon buffer)
  "NetMon 802.11 capture header"
  (try
    (let* (
           (802-11-length (unwrap (read-u16be buffer 1)))
           (802-11-op-mode (unwrap (read-u32be buffer 3)))
           (802-11-op-mode-sta (unwrap (read-u32be buffer 3)))
           (802-11-op-mode-ap (unwrap (read-u32be buffer 3)))
           (802-11-op-mode-sta-ext (unwrap (read-u32be buffer 3)))
           (802-11-op-mode-mon (unwrap (read-u32be buffer 3)))
           (802-11-channel (unwrap (read-u32be buffer 15)))
           (802-11-rssi (unwrap (read-u32be buffer 19)))
           (802-11-datarate (unwrap (read-u32be buffer 23)))
           (802-11-timestamp (unwrap (read-u64be buffer 37)))
           (802-11-version (unwrap (read-u8 buffer 45)))
           )

      (ok (list
        (cons '802-11-length (list (cons 'raw 802-11-length) (cons 'formatted (number->string 802-11-length))))
        (cons '802-11-op-mode (list (cons 'raw 802-11-op-mode) (cons 'formatted (fmt-hex 802-11-op-mode))))
        (cons '802-11-op-mode-sta (list (cons 'raw 802-11-op-mode-sta) (cons 'formatted (fmt-hex 802-11-op-mode-sta))))
        (cons '802-11-op-mode-ap (list (cons 'raw 802-11-op-mode-ap) (cons 'formatted (fmt-hex 802-11-op-mode-ap))))
        (cons '802-11-op-mode-sta-ext (list (cons 'raw 802-11-op-mode-sta-ext) (cons 'formatted (fmt-hex 802-11-op-mode-sta-ext))))
        (cons '802-11-op-mode-mon (list (cons 'raw 802-11-op-mode-mon) (cons 'formatted (fmt-hex 802-11-op-mode-mon))))
        (cons '802-11-channel (list (cons 'raw 802-11-channel) (cons 'formatted (number->string 802-11-channel))))
        (cons '802-11-rssi (list (cons 'raw 802-11-rssi) (cons 'formatted (number->string 802-11-rssi))))
        (cons '802-11-datarate (list (cons 'raw 802-11-datarate) (cons 'formatted (number->string 802-11-datarate))))
        (cons '802-11-timestamp (list (cons 'raw 802-11-timestamp) (cons 'formatted (number->string 802-11-timestamp))))
        (cons '802-11-version (list (cons 'raw 802-11-version) (cons 'formatted (number->string 802-11-version))))
        )))

    (catch (e)
      (err (str "IEEE80211-NETMON parse error: " e)))))

;; dissect-ieee80211-netmon: parse IEEE80211-NETMON from bytevector
;; Returns (ok fields-alist) or (err message)