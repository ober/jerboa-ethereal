;; packet-someip-sd.c
;; SOME/IP-SD dissector.
;; By Dr. Lars Voelker <lars.voelker@technica-engineering.de> / <lars.voelker@bmw.de>
;; Copyright 2012-2024 Dr. Lars Voelker
;; Copyright 2020      Ayoub Kaanich
;; Copyright 2019      Ana Pantar
;; Copyright 2019      Guenter Ebermann
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/someip-sd.ss
;; Auto-generated from wireshark/epan/dissectors/packet-someip_sd.c

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
(def (dissect-someip-sd buffer)
  "SOME/IP Service Discovery Protocol"
  (try
    (let* (
           (sd-flags (unwrap (read-u8 buffer 0)))
           (sd-rebootflag (extract-bits sd-flags 0x0 0))
           (sd-unicastflag (extract-bits sd-flags 0x0 0))
           (sd-explicitiniteventflag (extract-bits sd-flags 0x0 0))
           (sd-reserved (unwrap (read-u24be buffer 1)))
           (sd-option-config-string (unwrap (slice buffer 4 1)))
           (sd-option-config-string-element (unwrap (slice buffer 4 1)))
           (sd-length-entriesarray (unwrap (read-u32be buffer 4)))
           (sd-option-lb-priority (unwrap (read-u16be buffer 8)))
           (sd-length-optionsarray (unwrap (read-u32be buffer 8)))
           (sd-option-lb-weight (unwrap (read-u16be buffer 10)))
           (sd-option-ipv4 (unwrap (read-u32be buffer 14)))
           (sd-option-ipv6 (unwrap (slice buffer 24 16)))
           (sd-option-reserved2 (unwrap (slice buffer 40 1)))
           (sd-option-proto (unwrap (read-u8 buffer 41)))
           (sd-option-port (unwrap (read-u16be buffer 42)))
           (sd-option-length (unwrap (read-u16be buffer 42)))
           (sd-option-type (unwrap (read-u8 buffer 44)))
           (sd-option-reserved (unwrap (slice buffer 45 1)))
           (sd-option-data (unwrap (slice buffer 46 1)))
           (sd-entry-type (unwrap (read-u8 buffer 46)))
           (sd-entry-index1 (unwrap (read-u8 buffer 47)))
           (sd-entry-index2 (unwrap (read-u8 buffer 48)))
           (sd-entry-numopt1 (unwrap (read-u8 buffer 49)))
           (sd-entry-numopt2 (unwrap (read-u8 buffer 49)))
           (sd-entry-opts-referenced (unwrap (slice buffer 50 3)))
           (sd-entry-servicename (unwrap (slice buffer 50 2)))
           (sd-entry-ttl (unwrap (read-u24be buffer 55)))
           (sd-entry-reserved (unwrap (read-u8 buffer 58)))
           (sd-entry-intial-event-flag (unwrap (read-u8 buffer 59)))
           (sd-entry-reserved2 (unwrap (read-u8 buffer 59)))
           (sd-entry-counter (unwrap (read-u8 buffer 59)))
           (sd-entry-eventgroupname (unwrap (slice buffer 60 2)))
           )

      (ok (list
        (cons 'sd-flags (list (cons 'raw sd-flags) (cons 'formatted (fmt-hex sd-flags))))
        (cons 'sd-rebootflag (list (cons 'raw sd-rebootflag) (cons 'formatted (if (= sd-rebootflag 0) "Session ID rolled over since last reboot" "Session ID did not roll over since last reboot"))))
        (cons 'sd-unicastflag (list (cons 'raw sd-unicastflag) (cons 'formatted (if (= sd-unicastflag 0) "Unicast messages not supported (deprecated)" "Unicast messages support"))))
        (cons 'sd-explicitiniteventflag (list (cons 'raw sd-explicitiniteventflag) (cons 'formatted (if (= sd-explicitiniteventflag 0) "Explicit Initial Event control not supported" "Explicit Initial Event control supported"))))
        (cons 'sd-reserved (list (cons 'raw sd-reserved) (cons 'formatted (fmt-hex sd-reserved))))
        (cons 'sd-option-config-string (list (cons 'raw sd-option-config-string) (cons 'formatted (utf8->string sd-option-config-string))))
        (cons 'sd-option-config-string-element (list (cons 'raw sd-option-config-string-element) (cons 'formatted (utf8->string sd-option-config-string-element))))
        (cons 'sd-length-entriesarray (list (cons 'raw sd-length-entriesarray) (cons 'formatted (number->string sd-length-entriesarray))))
        (cons 'sd-option-lb-priority (list (cons 'raw sd-option-lb-priority) (cons 'formatted (number->string sd-option-lb-priority))))
        (cons 'sd-length-optionsarray (list (cons 'raw sd-length-optionsarray) (cons 'formatted (number->string sd-length-optionsarray))))
        (cons 'sd-option-lb-weight (list (cons 'raw sd-option-lb-weight) (cons 'formatted (number->string sd-option-lb-weight))))
        (cons 'sd-option-ipv4 (list (cons 'raw sd-option-ipv4) (cons 'formatted (fmt-ipv4 sd-option-ipv4))))
        (cons 'sd-option-ipv6 (list (cons 'raw sd-option-ipv6) (cons 'formatted (fmt-ipv6-address sd-option-ipv6))))
        (cons 'sd-option-reserved2 (list (cons 'raw sd-option-reserved2) (cons 'formatted (fmt-bytes sd-option-reserved2))))
        (cons 'sd-option-proto (list (cons 'raw sd-option-proto) (cons 'formatted (number->string sd-option-proto))))
        (cons 'sd-option-port (list (cons 'raw sd-option-port) (cons 'formatted (number->string sd-option-port))))
        (cons 'sd-option-length (list (cons 'raw sd-option-length) (cons 'formatted (number->string sd-option-length))))
        (cons 'sd-option-type (list (cons 'raw sd-option-type) (cons 'formatted (number->string sd-option-type))))
        (cons 'sd-option-reserved (list (cons 'raw sd-option-reserved) (cons 'formatted (fmt-bytes sd-option-reserved))))
        (cons 'sd-option-data (list (cons 'raw sd-option-data) (cons 'formatted (fmt-bytes sd-option-data))))
        (cons 'sd-entry-type (list (cons 'raw sd-entry-type) (cons 'formatted (fmt-hex sd-entry-type))))
        (cons 'sd-entry-index1 (list (cons 'raw sd-entry-index1) (cons 'formatted (fmt-hex sd-entry-index1))))
        (cons 'sd-entry-index2 (list (cons 'raw sd-entry-index2) (cons 'formatted (fmt-hex sd-entry-index2))))
        (cons 'sd-entry-numopt1 (list (cons 'raw sd-entry-numopt1) (cons 'formatted (fmt-hex sd-entry-numopt1))))
        (cons 'sd-entry-numopt2 (list (cons 'raw sd-entry-numopt2) (cons 'formatted (fmt-hex sd-entry-numopt2))))
        (cons 'sd-entry-opts-referenced (list (cons 'raw sd-entry-opts-referenced) (cons 'formatted (utf8->string sd-entry-opts-referenced))))
        (cons 'sd-entry-servicename (list (cons 'raw sd-entry-servicename) (cons 'formatted (utf8->string sd-entry-servicename))))
        (cons 'sd-entry-ttl (list (cons 'raw sd-entry-ttl) (cons 'formatted (number->string sd-entry-ttl))))
        (cons 'sd-entry-reserved (list (cons 'raw sd-entry-reserved) (cons 'formatted (fmt-hex sd-entry-reserved))))
        (cons 'sd-entry-intial-event-flag (list (cons 'raw sd-entry-intial-event-flag) (cons 'formatted (number->string sd-entry-intial-event-flag))))
        (cons 'sd-entry-reserved2 (list (cons 'raw sd-entry-reserved2) (cons 'formatted (fmt-hex sd-entry-reserved2))))
        (cons 'sd-entry-counter (list (cons 'raw sd-entry-counter) (cons 'formatted (fmt-hex sd-entry-counter))))
        (cons 'sd-entry-eventgroupname (list (cons 'raw sd-entry-eventgroupname) (cons 'formatted (utf8->string sd-entry-eventgroupname))))
        )))

    (catch (e)
      (err (str "SOMEIP-SD parse error: " e)))))

;; dissect-someip-sd: parse SOMEIP-SD from bytevector
;; Returns (ok fields-alist) or (err message)