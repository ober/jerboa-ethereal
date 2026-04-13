;; packet-silabs-dch.c
;; Routines for Silicon Labs Debug Channel dissection
;; Copyright 2023, Dhruv Chandwani <dhchandw@silabs.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/silabs-dch.ss
;; Auto-generated from wireshark/epan/dissectors/packet-silabs_dch.c

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
(def (dissect-silabs-dch buffer)
  "Silabs Debug Channel"
  (try
    (let* (
           (2bytephr (unwrap (read-u16be buffer 1)))
           (4bytephr (unwrap (read-u32be buffer 1)))
           (rssi (unwrap (read-u8 buffer 2)))
           (syncword (unwrap (read-u32be buffer 2)))
           (radiocfg (unwrap (read-u8 buffer 2)))
           (radiocfg-addedbytes (extract-bits radiocfg 0x0 0))
           (radiocfg-blephyid (extract-bits radiocfg 0x0 0))
           (phyid (unwrap (read-u8 buffer 3)))
           (radioinfo (unwrap (read-u8 buffer 4)))
           (radioinfo-antenna (extract-bits radioinfo 0x0 0))
           (radioinfo-syncword (extract-bits radioinfo 0x0 0))
           (radioinfo-channel (extract-bits radioinfo 0x0 0))
           (status (unwrap (read-u8 buffer 5)))
           (status-errorcode (extract-bits status 0x0 0))
           (appendedinfocfg (unwrap (read-u8 buffer 6)))
           (appendedinfocfg-length (extract-bits appendedinfocfg 0x0 0))
           (appendedinfocfg-version (extract-bits appendedinfocfg 0x0 0))
           (phr (unwrap (read-u8 buffer 9)))
           (channel (unwrap (read-u16be buffer 9)))
           (flags (unwrap (read-u32be buffer 18)))
           (sequence (unwrap (read-u16be buffer 22)))
           (version (unwrap (read-u16be buffer 24)))
           )

      (ok (list
        (cons '2bytephr (list (cons 'raw 2bytephr) (cons 'formatted (number->string 2bytephr))))
        (cons '4bytephr (list (cons 'raw 4bytephr) (cons 'formatted (number->string 4bytephr))))
        (cons 'rssi (list (cons 'raw rssi) (cons 'formatted (number->string rssi))))
        (cons 'syncword (list (cons 'raw syncword) (cons 'formatted (fmt-hex syncword))))
        (cons 'radiocfg (list (cons 'raw radiocfg) (cons 'formatted (fmt-hex radiocfg))))
        (cons 'radiocfg-addedbytes (list (cons 'raw radiocfg-addedbytes) (cons 'formatted (if (= radiocfg-addedbytes 0) "Not set" "Set"))))
        (cons 'radiocfg-blephyid (list (cons 'raw radiocfg-blephyid) (cons 'formatted (if (= radiocfg-blephyid 0) "Not set" "Set"))))
        (cons 'phyid (list (cons 'raw phyid) (cons 'formatted (fmt-hex phyid))))
        (cons 'radioinfo (list (cons 'raw radioinfo) (cons 'formatted (fmt-hex radioinfo))))
        (cons 'radioinfo-antenna (list (cons 'raw radioinfo-antenna) (cons 'formatted (if (= radioinfo-antenna 0) "Not set" "Set"))))
        (cons 'radioinfo-syncword (list (cons 'raw radioinfo-syncword) (cons 'formatted (if (= radioinfo-syncword 0) "Not set" "Set"))))
        (cons 'radioinfo-channel (list (cons 'raw radioinfo-channel) (cons 'formatted (if (= radioinfo-channel 0) "Not set" "Set"))))
        (cons 'status (list (cons 'raw status) (cons 'formatted (fmt-hex status))))
        (cons 'status-errorcode (list (cons 'raw status-errorcode) (cons 'formatted (if (= status-errorcode 0) "Not set" "Set"))))
        (cons 'appendedinfocfg (list (cons 'raw appendedinfocfg) (cons 'formatted (fmt-hex appendedinfocfg))))
        (cons 'appendedinfocfg-length (list (cons 'raw appendedinfocfg-length) (cons 'formatted (if (= appendedinfocfg-length 0) "Not set" "Set"))))
        (cons 'appendedinfocfg-version (list (cons 'raw appendedinfocfg-version) (cons 'formatted (if (= appendedinfocfg-version 0) "Not set" "Set"))))
        (cons 'phr (list (cons 'raw phr) (cons 'formatted (number->string phr))))
        (cons 'channel (list (cons 'raw channel) (cons 'formatted (number->string channel))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'sequence (list (cons 'raw sequence) (cons 'formatted (number->string sequence))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        )))

    (catch (e)
      (err (str "SILABS-DCH parse error: " e)))))

;; dissect-silabs-dch: parse SILABS-DCH from bytevector
;; Returns (ok fields-alist) or (err message)