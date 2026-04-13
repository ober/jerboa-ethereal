;; packet-sercosiii.c
;; Routines for SERCOS III dissection
;;
;; Initial plugin code by,
;; Bosch Rexroth
;; Hilscher
;;
;; Hans-Peter Bock <hpbock@avaapgh.de>
;;
;; Convert to built-in dissector
;; Michael Mann * Copyright 2011
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/sercosiii.ss
;; Auto-generated from wireshark/epan/dissectors/packet-sercosiii.c

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
(def (dissect-sercosiii buffer)
  "SERCOS III V1.1"
  (try
    (let* (
           (at-dev-status (unwrap (read-u16le buffer 0)))
           (at-svch-stat (unwrap (read-u16le buffer 0)))
           (mdt-version (unwrap (read-u32le buffer 0)))
           (mdt-version-switch-off-sercos-telegrams (extract-bits mdt-version 0x400000 22))
           (mdt-version-fast-cp-switch (extract-bits mdt-version 0x200000 21))
           (mdt-version-transmission-of-communication-parameters-mdt0-cp0 (extract-bits mdt-version 0x100000 20))
           (mdt-version-initprocvers (extract-bits mdt-version 0xFF00 8))
           (mdt-svch-ctrl (unwrap (read-u16le buffer 0)))
           (at-svch-valid (extract-bits mdt-svch-ctrl 0x8 3))
           (at-svch-error (extract-bits mdt-svch-ctrl 0x4 2))
           (at-svch-busy (extract-bits mdt-svch-ctrl 0x2 1))
           (at-svch-ahs (extract-bits mdt-svch-ctrl 0x1 0))
           (mdt-dev-control (unwrap (read-u16le buffer 0)))
           (at-cp0-num-devices (unwrap (read-u16be buffer 0)))
           (at-hotplug-address (unwrap (read-u16be buffer 0)))
           (mdt-hotplug-address (unwrap (read-u16be buffer 0)))
           (mst-telno (unwrap (read-u8 buffer 0)))
           (mst-cyclecntvalid (unwrap (read-u8 buffer 0)))
           (mst-cyclecnt (unwrap (read-u8 buffer 1)))
           (at-hp-stat (unwrap (read-u16le buffer 2)))
           (at-hotplug-status-hp0-finished (extract-bits at-hp-stat 0x100 8))
           (mdt-hp-ctrl (unwrap (read-u16le buffer 2)))
           (at-dev-control-ident (extract-bits mdt-hp-ctrl 0x8000 15))
           (mdt-dev-control-change-topology (extract-bits mdt-hp-ctrl 0x1 0))
           (at-svch-info (unwrap (slice buffer 2 4)))
           (mdt-svch-info (unwrap (slice buffer 2 4)))
           (mst-crc32 (unwrap (read-u32be buffer 2)))
           (at-hp-info (unwrap (slice buffer 4 4)))
           (mdt-hp-info (unwrap (slice buffer 4 4)))
           )

      (ok (list
        (cons 'at-dev-status (list (cons 'raw at-dev-status) (cons 'formatted (fmt-hex at-dev-status))))
        (cons 'at-svch-stat (list (cons 'raw at-svch-stat) (cons 'formatted (fmt-hex at-svch-stat))))
        (cons 'mdt-version (list (cons 'raw mdt-version) (cons 'formatted (fmt-hex mdt-version))))
        (cons 'mdt-version-switch-off-sercos-telegrams (list (cons 'raw mdt-version-switch-off-sercos-telegrams) (cons 'formatted (if (= mdt-version-switch-off-sercos-telegrams 0) "Industrial Ethernet devices used by application" "Industrial Ethernet devices not used by application"))))
        (cons 'mdt-version-fast-cp-switch (list (cons 'raw mdt-version-fast-cp-switch) (cons 'formatted (if (= mdt-version-fast-cp-switch 0) "CPS delay time reduce to the re-configuration time of the master" "Transmission of MST (MDT0) interrupted during CP switch for CPS delay time (120ms)"))))
        (cons 'mdt-version-transmission-of-communication-parameters-mdt0-cp0 (list (cons 'raw mdt-version-transmission-of-communication-parameters-mdt0-cp0) (cons 'formatted (if (= mdt-version-transmission-of-communication-parameters-mdt0-cp0 0) "Not set" "Set"))))
        (cons 'mdt-version-initprocvers (list (cons 'raw mdt-version-initprocvers) (cons 'formatted (if (= mdt-version-initprocvers 0) "Remote address allocation" "No remote address allocation"))))
        (cons 'mdt-svch-ctrl (list (cons 'raw mdt-svch-ctrl) (cons 'formatted (fmt-hex mdt-svch-ctrl))))
        (cons 'at-svch-valid (list (cons 'raw at-svch-valid) (cons 'formatted (if (= at-svch-valid 0) "Not set" "Set"))))
        (cons 'at-svch-error (list (cons 'raw at-svch-error) (cons 'formatted (if (= at-svch-error 0) "Error in SVC" "No error"))))
        (cons 'at-svch-busy (list (cons 'raw at-svch-busy) (cons 'formatted (if (= at-svch-busy 0) "Step in process, new step not allowed" "Step finished, slave ready for new step"))))
        (cons 'at-svch-ahs (list (cons 'raw at-svch-ahs) (cons 'formatted (if (= at-svch-ahs 0) "Not set" "Set"))))
        (cons 'mdt-dev-control (list (cons 'raw mdt-dev-control) (cons 'formatted (number->string mdt-dev-control))))
        (cons 'at-cp0-num-devices (list (cons 'raw at-cp0-num-devices) (cons 'formatted (number->string at-cp0-num-devices))))
        (cons 'at-hotplug-address (list (cons 'raw at-hotplug-address) (cons 'formatted (fmt-hex at-hotplug-address))))
        (cons 'mdt-hotplug-address (list (cons 'raw mdt-hotplug-address) (cons 'formatted (fmt-hex mdt-hotplug-address))))
        (cons 'mst-telno (list (cons 'raw mst-telno) (cons 'formatted (number->string mst-telno))))
        (cons 'mst-cyclecntvalid (list (cons 'raw mst-cyclecntvalid) (cons 'formatted (if (= mst-cyclecntvalid 0) "False" "True"))))
        (cons 'mst-cyclecnt (list (cons 'raw mst-cyclecnt) (cons 'formatted (number->string mst-cyclecnt))))
        (cons 'at-hp-stat (list (cons 'raw at-hp-stat) (cons 'formatted (fmt-hex at-hp-stat))))
        (cons 'at-hotplug-status-hp0-finished (list (cons 'raw at-hotplug-status-hp0-finished) (cons 'formatted (if (= at-hotplug-status-hp0-finished 0) "Not set" "Set"))))
        (cons 'mdt-hp-ctrl (list (cons 'raw mdt-hp-ctrl) (cons 'formatted (fmt-hex mdt-hp-ctrl))))
        (cons 'at-dev-control-ident (list (cons 'raw at-dev-control-ident) (cons 'formatted (if (= at-dev-control-ident 0) "Not set" "Set"))))
        (cons 'mdt-dev-control-change-topology (list (cons 'raw mdt-dev-control-change-topology) (cons 'formatted (if (= mdt-dev-control-change-topology 0) "Not set" "Set"))))
        (cons 'at-svch-info (list (cons 'raw at-svch-info) (cons 'formatted (fmt-bytes at-svch-info))))
        (cons 'mdt-svch-info (list (cons 'raw mdt-svch-info) (cons 'formatted (fmt-bytes mdt-svch-info))))
        (cons 'mst-crc32 (list (cons 'raw mst-crc32) (cons 'formatted (fmt-hex mst-crc32))))
        (cons 'at-hp-info (list (cons 'raw at-hp-info) (cons 'formatted (fmt-bytes at-hp-info))))
        (cons 'mdt-hp-info (list (cons 'raw mdt-hp-info) (cons 'formatted (fmt-bytes mdt-hp-info))))
        )))

    (catch (e)
      (err (str "SERCOSIII parse error: " e)))))

;; dissect-sercosiii: parse SERCOSIII from bytevector
;; Returns (ok fields-alist) or (err message)