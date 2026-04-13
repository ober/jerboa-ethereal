;; packet-ieee80211-wlancap.c
;; Routines for AVS linux-wlan monitoring mode header dissection
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from README.developer
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ieee80211-wlancap.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ieee80211_wlancap.c

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
(def (dissect-ieee80211-wlancap buffer)
  "AVS WLAN Capture header"
  (try
    (let* (
           (version (unwrap (read-u32be buffer 0)))
           (length (unwrap (read-u32be buffer 4)))
           (mactime (unwrap (read-u64be buffer 8)))
           (hosttime (unwrap (read-u64be buffer 16)))
           (hop-set (unwrap (read-u8 buffer 28)))
           (hop-pattern (unwrap (read-u8 buffer 28)))
           (hop-index (unwrap (read-u8 buffer 28)))
           (channel (unwrap (read-u8 buffer 28)))
           (channel-frequency (unwrap (read-u32be buffer 28)))
           (data-rate (unwrap (read-u64be buffer 32)))
           (antenna (unwrap (read-u32be buffer 36)))
           (priority (unwrap (read-u32be buffer 40)))
           (normrssi-antsignal (unwrap (read-u32be buffer 48)))
           (dbm-antsignal (unwrap (read-u32be buffer 48)))
           (rawrssi-antsignal (unwrap (read-u32be buffer 48)))
           (normrssi-antnoise (unwrap (read-u32be buffer 52)))
           (dbm-antnoise (unwrap (read-u32be buffer 52)))
           (rawrssi-antnoise (unwrap (read-u32be buffer 52)))
           (sequence (unwrap (read-u32be buffer 64)))
           (drops (unwrap (read-u32be buffer 68)))
           (receiver-addr (unwrap (slice buffer 72 6)))
           (padding (unwrap (slice buffer 78 2)))
           (magic (unwrap (read-u32be buffer 80)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'mactime (list (cons 'raw mactime) (cons 'formatted (number->string mactime))))
        (cons 'hosttime (list (cons 'raw hosttime) (cons 'formatted (number->string hosttime))))
        (cons 'hop-set (list (cons 'raw hop-set) (cons 'formatted (fmt-hex hop-set))))
        (cons 'hop-pattern (list (cons 'raw hop-pattern) (cons 'formatted (fmt-hex hop-pattern))))
        (cons 'hop-index (list (cons 'raw hop-index) (cons 'formatted (fmt-hex hop-index))))
        (cons 'channel (list (cons 'raw channel) (cons 'formatted (number->string channel))))
        (cons 'channel-frequency (list (cons 'raw channel-frequency) (cons 'formatted (number->string channel-frequency))))
        (cons 'data-rate (list (cons 'raw data-rate) (cons 'formatted (number->string data-rate))))
        (cons 'antenna (list (cons 'raw antenna) (cons 'formatted (number->string antenna))))
        (cons 'priority (list (cons 'raw priority) (cons 'formatted (number->string priority))))
        (cons 'normrssi-antsignal (list (cons 'raw normrssi-antsignal) (cons 'formatted (number->string normrssi-antsignal))))
        (cons 'dbm-antsignal (list (cons 'raw dbm-antsignal) (cons 'formatted (number->string dbm-antsignal))))
        (cons 'rawrssi-antsignal (list (cons 'raw rawrssi-antsignal) (cons 'formatted (number->string rawrssi-antsignal))))
        (cons 'normrssi-antnoise (list (cons 'raw normrssi-antnoise) (cons 'formatted (number->string normrssi-antnoise))))
        (cons 'dbm-antnoise (list (cons 'raw dbm-antnoise) (cons 'formatted (number->string dbm-antnoise))))
        (cons 'rawrssi-antnoise (list (cons 'raw rawrssi-antnoise) (cons 'formatted (number->string rawrssi-antnoise))))
        (cons 'sequence (list (cons 'raw sequence) (cons 'formatted (number->string sequence))))
        (cons 'drops (list (cons 'raw drops) (cons 'formatted (number->string drops))))
        (cons 'receiver-addr (list (cons 'raw receiver-addr) (cons 'formatted (fmt-mac receiver-addr))))
        (cons 'padding (list (cons 'raw padding) (cons 'formatted (fmt-bytes padding))))
        (cons 'magic (list (cons 'raw magic) (cons 'formatted (fmt-hex magic))))
        )))

    (catch (e)
      (err (str "IEEE80211-WLANCAP parse error: " e)))))

;; dissect-ieee80211-wlancap: parse IEEE80211-WLANCAP from bytevector
;; Returns (ok fields-alist) or (err message)