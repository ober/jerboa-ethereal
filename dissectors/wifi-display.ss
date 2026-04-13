;; packet-wifi-display.c
;;
;; Wi-Fi Display
;;
;; Copyright 2011-2013 Qualcomm Atheros, Inc.
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/wifi-display.ss
;; Auto-generated from wireshark/epan/dissectors/packet-wifi_display.c

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
(def (dissect-wifi-display buffer)
  "Wi-Fi Display"
  (try
    (let* (
           (subelem-dev-info-coupled-sink-source (unwrap (read-u8 buffer 0)))
           (subelem-dev-info-coupled-sink-sink (unwrap (read-u8 buffer 0)))
           (subelem-dev-info-wsd (unwrap (read-u8 buffer 0)))
           (subelem-dev-info-content-protection (unwrap (read-u8 buffer 0)))
           (subelem-dev-info-time-sync (unwrap (read-u8 buffer 0)))
           (subelem-dev-info-audio-unsupp-pri-sink (unwrap (read-u8 buffer 0)))
           (subelem-dev-info-audio-only-supp-source (unwrap (read-u8 buffer 0)))
           (subelem-dev-info-tdls-persistent-group (unwrap (read-u8 buffer 0)))
           (subelem-dev-info-tdls-persistent-group-reinvoke (unwrap (read-u8 buffer 0)))
           (subelem-dev-info-reserved (unwrap (read-u16be buffer 0)))
           (subelem-len (unwrap (read-u16be buffer 0)))
           (subelem-dev-info-control-port (unwrap (read-u16be buffer 2)))
           (subelem-dev-info-max-throughput (unwrap (read-u16be buffer 4)))
           (subelem-assoc-bssid (unwrap (slice buffer 4 6)))
           (subelem-coupled-sink-reserved (unwrap (read-u8 buffer 4)))
           (subelem-coupled-sink-mac-addr (unwrap (slice buffer 4 6)))
           (subelem-session-descr-len (unwrap (read-u8 buffer 4)))
           (subelem-session-dev-addr (unwrap (slice buffer 4 6)))
           (subelem-session-assoc-bssid (unwrap (slice buffer 10 6)))
           (subelem-session-dev-info-coupled-sink-source (unwrap (read-u8 buffer 16)))
           (subelem-session-dev-info-coupled-sink-sink (unwrap (read-u8 buffer 16)))
           (subelem-session-dev-info-wsd (unwrap (read-u8 buffer 16)))
           (subelem-session-dev-info-content-protection (unwrap (read-u8 buffer 16)))
           (subelem-session-dev-info-time-sync (unwrap (read-u8 buffer 16)))
           (subelem-session-dev-info-audio-unsupp-pri-sink (unwrap (read-u8 buffer 16)))
           (subelem-session-dev-info-audio-only-supp-source (unwrap (read-u8 buffer 16)))
           (subelem-session-dev-info-tdls-persistent-group (unwrap (read-u8 buffer 16)))
           (subelem-session-dev-info-tdls-persistent-group-reinvoke (unwrap (read-u8 buffer 16)))
           (subelem-session-dev-info-reserved (unwrap (read-u16be buffer 16)))
           (subelem-session-dev-info-max-throughput (unwrap (read-u16be buffer 18)))
           (subelem-session-coupled-sink-reserved (unwrap (read-u8 buffer 20)))
           (subelem-session-coupled-sink-addr (unwrap (slice buffer 20 6)))
           (subelem-session-extra-info (unwrap (slice buffer 26 1)))
           (subelem-ext-capab (unwrap (read-u16be buffer 26)))
           (subelem-ext-capab-reserved (unwrap (read-u16be buffer 26)))
           (subelem-alt-mac-addr (unwrap (slice buffer 26 6)))
           )

      (ok (list
        (cons 'subelem-dev-info-coupled-sink-source (list (cons 'raw subelem-dev-info-coupled-sink-source) (cons 'formatted (number->string subelem-dev-info-coupled-sink-source))))
        (cons 'subelem-dev-info-coupled-sink-sink (list (cons 'raw subelem-dev-info-coupled-sink-sink) (cons 'formatted (number->string subelem-dev-info-coupled-sink-sink))))
        (cons 'subelem-dev-info-wsd (list (cons 'raw subelem-dev-info-wsd) (cons 'formatted (number->string subelem-dev-info-wsd))))
        (cons 'subelem-dev-info-content-protection (list (cons 'raw subelem-dev-info-content-protection) (cons 'formatted (number->string subelem-dev-info-content-protection))))
        (cons 'subelem-dev-info-time-sync (list (cons 'raw subelem-dev-info-time-sync) (cons 'formatted (number->string subelem-dev-info-time-sync))))
        (cons 'subelem-dev-info-audio-unsupp-pri-sink (list (cons 'raw subelem-dev-info-audio-unsupp-pri-sink) (cons 'formatted (number->string subelem-dev-info-audio-unsupp-pri-sink))))
        (cons 'subelem-dev-info-audio-only-supp-source (list (cons 'raw subelem-dev-info-audio-only-supp-source) (cons 'formatted (number->string subelem-dev-info-audio-only-supp-source))))
        (cons 'subelem-dev-info-tdls-persistent-group (list (cons 'raw subelem-dev-info-tdls-persistent-group) (cons 'formatted (number->string subelem-dev-info-tdls-persistent-group))))
        (cons 'subelem-dev-info-tdls-persistent-group-reinvoke (list (cons 'raw subelem-dev-info-tdls-persistent-group-reinvoke) (cons 'formatted (number->string subelem-dev-info-tdls-persistent-group-reinvoke))))
        (cons 'subelem-dev-info-reserved (list (cons 'raw subelem-dev-info-reserved) (cons 'formatted (number->string subelem-dev-info-reserved))))
        (cons 'subelem-len (list (cons 'raw subelem-len) (cons 'formatted (number->string subelem-len))))
        (cons 'subelem-dev-info-control-port (list (cons 'raw subelem-dev-info-control-port) (cons 'formatted (number->string subelem-dev-info-control-port))))
        (cons 'subelem-dev-info-max-throughput (list (cons 'raw subelem-dev-info-max-throughput) (cons 'formatted (number->string subelem-dev-info-max-throughput))))
        (cons 'subelem-assoc-bssid (list (cons 'raw subelem-assoc-bssid) (cons 'formatted (fmt-mac subelem-assoc-bssid))))
        (cons 'subelem-coupled-sink-reserved (list (cons 'raw subelem-coupled-sink-reserved) (cons 'formatted (number->string subelem-coupled-sink-reserved))))
        (cons 'subelem-coupled-sink-mac-addr (list (cons 'raw subelem-coupled-sink-mac-addr) (cons 'formatted (fmt-mac subelem-coupled-sink-mac-addr))))
        (cons 'subelem-session-descr-len (list (cons 'raw subelem-session-descr-len) (cons 'formatted (number->string subelem-session-descr-len))))
        (cons 'subelem-session-dev-addr (list (cons 'raw subelem-session-dev-addr) (cons 'formatted (fmt-mac subelem-session-dev-addr))))
        (cons 'subelem-session-assoc-bssid (list (cons 'raw subelem-session-assoc-bssid) (cons 'formatted (fmt-mac subelem-session-assoc-bssid))))
        (cons 'subelem-session-dev-info-coupled-sink-source (list (cons 'raw subelem-session-dev-info-coupled-sink-source) (cons 'formatted (number->string subelem-session-dev-info-coupled-sink-source))))
        (cons 'subelem-session-dev-info-coupled-sink-sink (list (cons 'raw subelem-session-dev-info-coupled-sink-sink) (cons 'formatted (number->string subelem-session-dev-info-coupled-sink-sink))))
        (cons 'subelem-session-dev-info-wsd (list (cons 'raw subelem-session-dev-info-wsd) (cons 'formatted (number->string subelem-session-dev-info-wsd))))
        (cons 'subelem-session-dev-info-content-protection (list (cons 'raw subelem-session-dev-info-content-protection) (cons 'formatted (number->string subelem-session-dev-info-content-protection))))
        (cons 'subelem-session-dev-info-time-sync (list (cons 'raw subelem-session-dev-info-time-sync) (cons 'formatted (number->string subelem-session-dev-info-time-sync))))
        (cons 'subelem-session-dev-info-audio-unsupp-pri-sink (list (cons 'raw subelem-session-dev-info-audio-unsupp-pri-sink) (cons 'formatted (number->string subelem-session-dev-info-audio-unsupp-pri-sink))))
        (cons 'subelem-session-dev-info-audio-only-supp-source (list (cons 'raw subelem-session-dev-info-audio-only-supp-source) (cons 'formatted (number->string subelem-session-dev-info-audio-only-supp-source))))
        (cons 'subelem-session-dev-info-tdls-persistent-group (list (cons 'raw subelem-session-dev-info-tdls-persistent-group) (cons 'formatted (number->string subelem-session-dev-info-tdls-persistent-group))))
        (cons 'subelem-session-dev-info-tdls-persistent-group-reinvoke (list (cons 'raw subelem-session-dev-info-tdls-persistent-group-reinvoke) (cons 'formatted (number->string subelem-session-dev-info-tdls-persistent-group-reinvoke))))
        (cons 'subelem-session-dev-info-reserved (list (cons 'raw subelem-session-dev-info-reserved) (cons 'formatted (number->string subelem-session-dev-info-reserved))))
        (cons 'subelem-session-dev-info-max-throughput (list (cons 'raw subelem-session-dev-info-max-throughput) (cons 'formatted (number->string subelem-session-dev-info-max-throughput))))
        (cons 'subelem-session-coupled-sink-reserved (list (cons 'raw subelem-session-coupled-sink-reserved) (cons 'formatted (number->string subelem-session-coupled-sink-reserved))))
        (cons 'subelem-session-coupled-sink-addr (list (cons 'raw subelem-session-coupled-sink-addr) (cons 'formatted (fmt-mac subelem-session-coupled-sink-addr))))
        (cons 'subelem-session-extra-info (list (cons 'raw subelem-session-extra-info) (cons 'formatted (fmt-bytes subelem-session-extra-info))))
        (cons 'subelem-ext-capab (list (cons 'raw subelem-ext-capab) (cons 'formatted (fmt-hex subelem-ext-capab))))
        (cons 'subelem-ext-capab-reserved (list (cons 'raw subelem-ext-capab-reserved) (cons 'formatted (fmt-hex subelem-ext-capab-reserved))))
        (cons 'subelem-alt-mac-addr (list (cons 'raw subelem-alt-mac-addr) (cons 'formatted (fmt-mac subelem-alt-mac-addr))))
        )))

    (catch (e)
      (err (str "WIFI-DISPLAY parse error: " e)))))

;; dissect-wifi-display: parse WIFI-DISPLAY from bytevector
;; Returns (ok fields-alist) or (err message)