;; packet-snort.c
;;
;; Copyright 2011, Jakub Zawadzki <darkjames-ws@darkjames.pl>
;; Copyright 2016, Martin Mathieson
;;
;; Google Summer of Code 2011 for The Honeynet Project
;; Mentors:
;; Guillaume Arcas <guillaume.arcas (at) retiaire.org>
;; Jeff Nathan <jeffnathan (at) gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/snort.ss
;; Auto-generated from wireshark/epan/dissectors/packet-snort.c

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
(def (dissect-snort buffer)
  "Snort Alerts"
  (try
    (let* (
           (global-stats-rule-match-number (unwrap (read-u32be buffer 0)))
           (global-stats-rule-alerts-count (unwrap (read-u32be buffer 0)))
           (global-stats-alert-match-number (unwrap (read-u32be buffer 0)))
           (global-stats-total-alerts-count (unwrap (read-u32be buffer 0)))
           (global-stats-rule-count (unwrap (read-u32be buffer 0)))
           (global-stats-rule-file-count (unwrap (read-u32be buffer 0)))
           (global-stats (unwrap (slice buffer 0 1)))
           (reference (unwrap (slice buffer 0 1)))
           (rule-line-number (unwrap (read-u32be buffer 0)))
           (rule-filename (unwrap (slice buffer 0 1)))
           (rule-protocol (unwrap (slice buffer 0 1)))
           (rule-string (unwrap (slice buffer 0 1)))
           (priority (unwrap (read-u32be buffer 0)))
           (generator (unwrap (read-u32be buffer 0)))
           (rev (unwrap (read-u32be buffer 0)))
           (sid (unwrap (read-u32be buffer 0)))
           (msg (unwrap (slice buffer 0 1)))
           (rule (unwrap (slice buffer 0 1)))
           (classification (unwrap (slice buffer 0 1)))
           (raw-alert (unwrap (slice buffer 0 1)))
           (reassembled-from (unwrap (read-u32be buffer 0)))
           (reassembled-in (unwrap (read-u32be buffer 0)))
           )

      (ok (list
        (cons 'global-stats-rule-match-number (list (cons 'raw global-stats-rule-match-number) (cons 'formatted (number->string global-stats-rule-match-number))))
        (cons 'global-stats-rule-alerts-count (list (cons 'raw global-stats-rule-alerts-count) (cons 'formatted (number->string global-stats-rule-alerts-count))))
        (cons 'global-stats-alert-match-number (list (cons 'raw global-stats-alert-match-number) (cons 'formatted (number->string global-stats-alert-match-number))))
        (cons 'global-stats-total-alerts-count (list (cons 'raw global-stats-total-alerts-count) (cons 'formatted (number->string global-stats-total-alerts-count))))
        (cons 'global-stats-rule-count (list (cons 'raw global-stats-rule-count) (cons 'formatted (number->string global-stats-rule-count))))
        (cons 'global-stats-rule-file-count (list (cons 'raw global-stats-rule-file-count) (cons 'formatted (number->string global-stats-rule-file-count))))
        (cons 'global-stats (list (cons 'raw global-stats) (cons 'formatted (utf8->string global-stats))))
        (cons 'reference (list (cons 'raw reference) (cons 'formatted (utf8->string reference))))
        (cons 'rule-line-number (list (cons 'raw rule-line-number) (cons 'formatted (number->string rule-line-number))))
        (cons 'rule-filename (list (cons 'raw rule-filename) (cons 'formatted (utf8->string rule-filename))))
        (cons 'rule-protocol (list (cons 'raw rule-protocol) (cons 'formatted (utf8->string rule-protocol))))
        (cons 'rule-string (list (cons 'raw rule-string) (cons 'formatted (utf8->string rule-string))))
        (cons 'priority (list (cons 'raw priority) (cons 'formatted (number->string priority))))
        (cons 'generator (list (cons 'raw generator) (cons 'formatted (number->string generator))))
        (cons 'rev (list (cons 'raw rev) (cons 'formatted (number->string rev))))
        (cons 'sid (list (cons 'raw sid) (cons 'formatted (number->string sid))))
        (cons 'msg (list (cons 'raw msg) (cons 'formatted (utf8->string msg))))
        (cons 'rule (list (cons 'raw rule) (cons 'formatted (utf8->string rule))))
        (cons 'classification (list (cons 'raw classification) (cons 'formatted (utf8->string classification))))
        (cons 'raw-alert (list (cons 'raw raw-alert) (cons 'formatted (utf8->string raw-alert))))
        (cons 'reassembled-from (list (cons 'raw reassembled-from) (cons 'formatted (number->string reassembled-from))))
        (cons 'reassembled-in (list (cons 'raw reassembled-in) (cons 'formatted (number->string reassembled-in))))
        )))

    (catch (e)
      (err (str "SNORT parse error: " e)))))

;; dissect-snort: parse SNORT from bytevector
;; Returns (ok fields-alist) or (err message)