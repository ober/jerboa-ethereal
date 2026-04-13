;; packet-ismp.c
;; Routines for ISMP dissection
;; Enterasys Networks Home: http://www.enterasys.com/
;; Copyright 2003, Joshua Craig Douglas <jdouglas@enterasys.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ismp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ismp.c

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
(def (dissect-ismp buffer)
  "InterSwitch Message Protocol"
  (try
    (let* (
           (edp (unwrap (slice buffer 0 1)))
           (edp-version (unwrap (read-u16be buffer 0)))
           (edp-module-ip (unwrap (read-u32be buffer 2)))
           (version (unwrap (read-u16be buffer 3)))
           (message-type (unwrap (read-u16be buffer 5)))
           (edp-module-mac (unwrap (slice buffer 6 6)))
           (seq-num (unwrap (read-u16be buffer 7)))
           (code-length (unwrap (read-u8 buffer 9)))
           (auth-data (unwrap (slice buffer 10 1)))
           (edp-module-port (unwrap (read-u32be buffer 12)))
           (edp-chassis-mac (unwrap (slice buffer 16 6)))
           (edp-chassis-ip (unwrap (read-u32be buffer 22)))
           (edp-module-rev (unwrap (read-u32be buffer 28)))
           (edp-options (unwrap (read-u32be buffer 32)))
           (edp-end-station-option-ad (extract-bits edp-options 0x0 0))
           (edp-end-station-option-dns (extract-bits edp-options 0x0 0))
           (edp-end-station-option-dhcp (extract-bits edp-options 0x0 0))
           (edp-num-neighbors (unwrap (read-u16be buffer 36)))
           (edp-neighbors (unwrap (slice buffer 38 1)))
           (neighborhood-mac-address (unwrap (slice buffer 38 6)))
           (assigned-neighbor-state (unwrap (read-u32be buffer 38)))
           (edp-num-tuples (unwrap (read-u16be buffer 48)))
           (edp-tuples (unwrap (slice buffer 50 1)))
           (tuple-length (unwrap (read-u16be buffer 52)))
           (hold-time (unwrap (read-u16be buffer 54)))
           (interface-name (unwrap (slice buffer 54 1)))
           (system-description (unwrap (slice buffer 54 1)))
           (interface-ipx-address (unwrap (slice buffer 54 1)))
           (unknown-tuple-data (unwrap (slice buffer 54 1)))
           )

      (ok (list
        (cons 'edp (list (cons 'raw edp) (cons 'formatted (fmt-bytes edp))))
        (cons 'edp-version (list (cons 'raw edp-version) (cons 'formatted (number->string edp-version))))
        (cons 'edp-module-ip (list (cons 'raw edp-module-ip) (cons 'formatted (fmt-ipv4 edp-module-ip))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'message-type (list (cons 'raw message-type) (cons 'formatted (number->string message-type))))
        (cons 'edp-module-mac (list (cons 'raw edp-module-mac) (cons 'formatted (fmt-mac edp-module-mac))))
        (cons 'seq-num (list (cons 'raw seq-num) (cons 'formatted (number->string seq-num))))
        (cons 'code-length (list (cons 'raw code-length) (cons 'formatted (number->string code-length))))
        (cons 'auth-data (list (cons 'raw auth-data) (cons 'formatted (fmt-bytes auth-data))))
        (cons 'edp-module-port (list (cons 'raw edp-module-port) (cons 'formatted (number->string edp-module-port))))
        (cons 'edp-chassis-mac (list (cons 'raw edp-chassis-mac) (cons 'formatted (fmt-mac edp-chassis-mac))))
        (cons 'edp-chassis-ip (list (cons 'raw edp-chassis-ip) (cons 'formatted (fmt-ipv4 edp-chassis-ip))))
        (cons 'edp-module-rev (list (cons 'raw edp-module-rev) (cons 'formatted (number->string edp-module-rev))))
        (cons 'edp-options (list (cons 'raw edp-options) (cons 'formatted (fmt-hex edp-options))))
        (cons 'edp-end-station-option-ad (list (cons 'raw edp-end-station-option-ad) (cons 'formatted (if (= edp-end-station-option-ad 0) "Not set" "Set"))))
        (cons 'edp-end-station-option-dns (list (cons 'raw edp-end-station-option-dns) (cons 'formatted (if (= edp-end-station-option-dns 0) "Not set" "Set"))))
        (cons 'edp-end-station-option-dhcp (list (cons 'raw edp-end-station-option-dhcp) (cons 'formatted (if (= edp-end-station-option-dhcp 0) "Not set" "Set"))))
        (cons 'edp-num-neighbors (list (cons 'raw edp-num-neighbors) (cons 'formatted (number->string edp-num-neighbors))))
        (cons 'edp-neighbors (list (cons 'raw edp-neighbors) (cons 'formatted (fmt-bytes edp-neighbors))))
        (cons 'neighborhood-mac-address (list (cons 'raw neighborhood-mac-address) (cons 'formatted (fmt-mac neighborhood-mac-address))))
        (cons 'assigned-neighbor-state (list (cons 'raw assigned-neighbor-state) (cons 'formatted (fmt-hex assigned-neighbor-state))))
        (cons 'edp-num-tuples (list (cons 'raw edp-num-tuples) (cons 'formatted (number->string edp-num-tuples))))
        (cons 'edp-tuples (list (cons 'raw edp-tuples) (cons 'formatted (fmt-bytes edp-tuples))))
        (cons 'tuple-length (list (cons 'raw tuple-length) (cons 'formatted (number->string tuple-length))))
        (cons 'hold-time (list (cons 'raw hold-time) (cons 'formatted (number->string hold-time))))
        (cons 'interface-name (list (cons 'raw interface-name) (cons 'formatted (utf8->string interface-name))))
        (cons 'system-description (list (cons 'raw system-description) (cons 'formatted (utf8->string system-description))))
        (cons 'interface-ipx-address (list (cons 'raw interface-ipx-address) (cons 'formatted (utf8->string interface-ipx-address))))
        (cons 'unknown-tuple-data (list (cons 'raw unknown-tuple-data) (cons 'formatted (utf8->string unknown-tuple-data))))
        )))

    (catch (e)
      (err (str "ISMP parse error: " e)))))

;; dissect-ismp: parse ISMP from bytevector
;; Returns (ok fields-alist) or (err message)