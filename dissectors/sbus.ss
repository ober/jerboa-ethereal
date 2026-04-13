;; packet-sbus.c
;; Routines for Ether-S-Bus dissection
;; Copyright 2010, Christian Durrer <christian.durrer@sensemail.ch>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/sbus.ss
;; Auto-generated from wireshark/epan/dissectors/packet-sbus.c

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
(def (dissect-sbus buffer)
  "SAIA S-Bus"
  (try
    (let* (
           (rdwr-block-length-ext (unwrap (read-u32be buffer 0)))
           (request-in (unwrap (read-u32be buffer 0)))
           (length (unwrap (read-u32be buffer 0)))
           (version (unwrap (read-u8 buffer 4)))
           (protocol (unwrap (read-u8 buffer 5)))
           (sequence (unwrap (read-u16be buffer 6)))
           (dest (unwrap (read-u8 buffer 9)))
           (data-rtc (unwrap (read-u32be buffer 30)))
           (wcount-calculated (unwrap (read-u8 buffer 38)))
           (wcount (unwrap (read-u8 buffer 38)))
           (command-extension (unwrap (read-u8 buffer 43)))
           (rcount (unwrap (read-u8 buffer 44)))
           (addr-eeprom (unwrap (read-u16be buffer 45)))
           (sysinfo-nr (unwrap (read-u8 buffer 47)))
           (rdwr-block-addr (unwrap (read-u32be buffer 101)))
           (rdwr-file-name (unwrap (slice buffer 110 1)))
           (display-register (unwrap (read-u32be buffer 113)))
           (week-day (unwrap (read-u16be buffer 117)))
           (date (unwrap (read-u24be buffer 119)))
           (time (unwrap (read-u24be buffer 122)))
           (multimedia-length (unwrap (read-u8 buffer 125)))
           (sub-length (unwrap (read-u8 buffer 130)))
           (address (unwrap (read-u8 buffer 133)))
           (cpu-type (unwrap (slice buffer 134 5)))
           (fw-version (unwrap (slice buffer 139 3)))
           (flags-accu (unwrap (read-u8 buffer 143)))
           (flags-error (unwrap (read-u8 buffer 143)))
           (flags-negative (unwrap (read-u8 buffer 143)))
           (flags-zero (unwrap (read-u8 buffer 143)))
           (data-byte-hex (unwrap (read-u8 buffer 145)))
           (addr-prog (unwrap (read-u24be buffer 146)))
           (addr-68k (unwrap (read-u24be buffer 149)))
           (nbr-elements (unwrap (read-u16be buffer 152)))
           (sysinfo0-1 (unwrap (read-u8 buffer 158)))
           (sysinfo0-2 (unwrap (read-u8 buffer 158)))
           (sysinfo0-3 (unwrap (read-u8 buffer 158)))
           (sysinfo0-4 (unwrap (read-u8 buffer 158)))
           (sysinfo0-5 (unwrap (read-u8 buffer 158)))
           (web-size (unwrap (read-u8 buffer 159)))
           (web-aid (unwrap (read-u8 buffer 160)))
           (web-seq (unwrap (read-u8 buffer 161)))
           (data-byte (unwrap (read-u8 buffer 162)))
           (rdwr-block-length (unwrap (read-u8 buffer 163)))
           (rdwr-telegram-sequence (unwrap (read-u8 buffer 171)))
           (block-nr (unwrap (read-u16be buffer 181)))
           (rdwr-block-size (unwrap (read-u32be buffer 183)))
           )

      (ok (list
        (cons 'rdwr-block-length-ext (list (cons 'raw rdwr-block-length-ext) (cons 'formatted (number->string rdwr-block-length-ext))))
        (cons 'request-in (list (cons 'raw request-in) (cons 'formatted (number->string request-in))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'protocol (list (cons 'raw protocol) (cons 'formatted (number->string protocol))))
        (cons 'sequence (list (cons 'raw sequence) (cons 'formatted (number->string sequence))))
        (cons 'dest (list (cons 'raw dest) (cons 'formatted (number->string dest))))
        (cons 'data-rtc (list (cons 'raw data-rtc) (cons 'formatted (number->string data-rtc))))
        (cons 'wcount-calculated (list (cons 'raw wcount-calculated) (cons 'formatted (number->string wcount-calculated))))
        (cons 'wcount (list (cons 'raw wcount) (cons 'formatted (number->string wcount))))
        (cons 'command-extension (list (cons 'raw command-extension) (cons 'formatted (fmt-hex command-extension))))
        (cons 'rcount (list (cons 'raw rcount) (cons 'formatted (number->string rcount))))
        (cons 'addr-eeprom (list (cons 'raw addr-eeprom) (cons 'formatted (number->string addr-eeprom))))
        (cons 'sysinfo-nr (list (cons 'raw sysinfo-nr) (cons 'formatted (fmt-hex sysinfo-nr))))
        (cons 'rdwr-block-addr (list (cons 'raw rdwr-block-addr) (cons 'formatted (number->string rdwr-block-addr))))
        (cons 'rdwr-file-name (list (cons 'raw rdwr-file-name) (cons 'formatted (utf8->string rdwr-file-name))))
        (cons 'display-register (list (cons 'raw display-register) (cons 'formatted (number->string display-register))))
        (cons 'week-day (list (cons 'raw week-day) (cons 'formatted (fmt-hex week-day))))
        (cons 'date (list (cons 'raw date) (cons 'formatted (fmt-hex date))))
        (cons 'time (list (cons 'raw time) (cons 'formatted (fmt-hex time))))
        (cons 'multimedia-length (list (cons 'raw multimedia-length) (cons 'formatted (number->string multimedia-length))))
        (cons 'sub-length (list (cons 'raw sub-length) (cons 'formatted (number->string sub-length))))
        (cons 'address (list (cons 'raw address) (cons 'formatted (number->string address))))
        (cons 'cpu-type (list (cons 'raw cpu-type) (cons 'formatted (utf8->string cpu-type))))
        (cons 'fw-version (list (cons 'raw fw-version) (cons 'formatted (utf8->string fw-version))))
        (cons 'flags-accu (list (cons 'raw flags-accu) (cons 'formatted (if (= flags-accu 0) "Is low" "Is high"))))
        (cons 'flags-error (list (cons 'raw flags-error) (cons 'formatted (if (= flags-error 0) "Is low" "Is high"))))
        (cons 'flags-negative (list (cons 'raw flags-negative) (cons 'formatted (if (= flags-negative 0) "Is low" "Is high"))))
        (cons 'flags-zero (list (cons 'raw flags-zero) (cons 'formatted (if (= flags-zero 0) "Is low" "Is high"))))
        (cons 'data-byte-hex (list (cons 'raw data-byte-hex) (cons 'formatted (fmt-hex data-byte-hex))))
        (cons 'addr-prog (list (cons 'raw addr-prog) (cons 'formatted (number->string addr-prog))))
        (cons 'addr-68k (list (cons 'raw addr-68k) (cons 'formatted (fmt-hex addr-68k))))
        (cons 'nbr-elements (list (cons 'raw nbr-elements) (cons 'formatted (number->string nbr-elements))))
        (cons 'sysinfo0-1 (list (cons 'raw sysinfo0-1) (cons 'formatted (if (= sysinfo0-1 0) "Is not present" "Is present"))))
        (cons 'sysinfo0-2 (list (cons 'raw sysinfo0-2) (cons 'formatted (if (= sysinfo0-2 0) "Is not present" "Is present"))))
        (cons 'sysinfo0-3 (list (cons 'raw sysinfo0-3) (cons 'formatted (if (= sysinfo0-3 0) "Is not present" "Is present"))))
        (cons 'sysinfo0-4 (list (cons 'raw sysinfo0-4) (cons 'formatted (if (= sysinfo0-4 0) "Is not present" "Is present"))))
        (cons 'sysinfo0-5 (list (cons 'raw sysinfo0-5) (cons 'formatted (if (= sysinfo0-5 0) "Is not present" "Is present"))))
        (cons 'web-size (list (cons 'raw web-size) (cons 'formatted (fmt-hex web-size))))
        (cons 'web-aid (list (cons 'raw web-aid) (cons 'formatted (fmt-hex web-aid))))
        (cons 'web-seq (list (cons 'raw web-seq) (cons 'formatted (fmt-hex web-seq))))
        (cons 'data-byte (list (cons 'raw data-byte) (cons 'formatted (number->string data-byte))))
        (cons 'rdwr-block-length (list (cons 'raw rdwr-block-length) (cons 'formatted (number->string rdwr-block-length))))
        (cons 'rdwr-telegram-sequence (list (cons 'raw rdwr-telegram-sequence) (cons 'formatted (number->string rdwr-telegram-sequence))))
        (cons 'block-nr (list (cons 'raw block-nr) (cons 'formatted (number->string block-nr))))
        (cons 'rdwr-block-size (list (cons 'raw rdwr-block-size) (cons 'formatted (number->string rdwr-block-size))))
        )))

    (catch (e)
      (err (str "SBUS parse error: " e)))))

;; dissect-sbus: parse SBUS from bytevector
;; Returns (ok fields-alist) or (err message)