;; packet-bthci_vendor_intel.c
;; Routines for the Bluetooth HCI Vendors Commands/Events
;;
;; Copyright 2014, Michal Labedzki for Tieto Corporation
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bthci-vendor-intel.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bthci_vendor_intel.c

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
(def (dissect-bthci-vendor-intel buffer)
  "Bluetooth Intel HCI"
  (try
    (let* (
           (number-of-allowed-command-packets (unwrap (read-u8 buffer 0)))
           (reset-boot-option (unwrap (read-u8 buffer 4)))
           (hardware-platform (unwrap (read-u8 buffer 4)))
           (parameter-length (unwrap (read-u8 buffer 4)))
           (reset-boot-address (unwrap (read-u32be buffer 5)))
           (hardware-variant (unwrap (read-u8 buffer 5)))
           (hardware-revision (unwrap (read-u8 buffer 6)))
           (firmware-variant (unwrap (read-u8 buffer 7)))
           (firmware-revision (unwrap (read-u8 buffer 8)))
           (firmware-build-version-nn (unwrap (read-u8 buffer 9)))
           (firmware-build-version-cw (unwrap (read-u8 buffer 10)))
           (firmware-build-version-yy (unwrap (read-u8 buffer 11)))
           (firmware-patch (unwrap (read-u8 buffer 12)))
           (identifier (unwrap (read-u16be buffer 13)))
           (line (unwrap (read-u16be buffer 15)))
           (zero (unwrap (read-u8 buffer 19)))
           (number-of-packets (unwrap (read-u8 buffer 20)))
           (transmit-traces (unwrap (read-u8 buffer 27)))
           (transmit-arq (unwrap (read-u8 buffer 28)))
           (receive-traces (unwrap (read-u8 buffer 29)))
           (set-event-mask (unwrap (read-u64le buffer 31)))
           (set-event-mask-reserved-15-63 (extract-bits set-event-mask 0x0 0))
           (set-event-mask-firmware-trace-string (extract-bits set-event-mask 0x4000 14))
           (set-event-mask-le-link-established (extract-bits set-event-mask 0x2000 13))
           (set-event-mask-reserved-12 (extract-bits set-event-mask 0x1000 12))
           (set-event-mask-system-exception (extract-bits set-event-mask 0x800 11))
           (set-event-mask-fatal-exception (extract-bits set-event-mask 0x400 10))
           (set-event-mask-debug-exception (extract-bits set-event-mask 0x200 9))
           (set-event-mask-reserved-8 (extract-bits set-event-mask 0x100 8))
           (set-event-mask-scan-status (extract-bits set-event-mask 0x80 7))
           (set-event-mask-reserved-3-6 (extract-bits set-event-mask 0x78 3))
           (set-event-mask-ptt-switch-notification (extract-bits set-event-mask 0x4 2))
           (set-event-mask-sco-rejected-via-lmp (extract-bits set-event-mask 0x2 1))
           (set-event-mask-bootup (extract-bits set-event-mask 0x1 0))
           (ddc-config-length (unwrap (read-u8 buffer 39)))
           (access-address (unwrap (read-u32be buffer 40)))
           (mem-address (unwrap (read-u32be buffer 42)))
           (scan-status (unwrap (read-u8 buffer 44)))
           (scan-status-reserved (extract-bits scan-status 0xFC 2))
           (scan-status-page-scan (extract-bits scan-status 0x2 1))
           (scan-status-inquiry-scan (extract-bits scan-status 0x1 0))
           (mem-length (unwrap (read-u8 buffer 47)))
           (link-clock (unwrap (read-u32be buffer 60)))
           (link-count (unwrap (read-u16be buffer 70)))
           (link-id (unwrap (read-u8 buffer 72)))
           (reason (unwrap (read-u8 buffer 74)))
           (handle (unwrap (read-u16be buffer 75)))
           )

      (ok (list
        (cons 'number-of-allowed-command-packets (list (cons 'raw number-of-allowed-command-packets) (cons 'formatted (number->string number-of-allowed-command-packets))))
        (cons 'reset-boot-option (list (cons 'raw reset-boot-option) (cons 'formatted (fmt-hex reset-boot-option))))
        (cons 'hardware-platform (list (cons 'raw hardware-platform) (cons 'formatted (fmt-hex hardware-platform))))
        (cons 'parameter-length (list (cons 'raw parameter-length) (cons 'formatted (number->string parameter-length))))
        (cons 'reset-boot-address (list (cons 'raw reset-boot-address) (cons 'formatted (fmt-hex reset-boot-address))))
        (cons 'hardware-variant (list (cons 'raw hardware-variant) (cons 'formatted (fmt-hex hardware-variant))))
        (cons 'hardware-revision (list (cons 'raw hardware-revision) (cons 'formatted (fmt-hex hardware-revision))))
        (cons 'firmware-variant (list (cons 'raw firmware-variant) (cons 'formatted (fmt-hex firmware-variant))))
        (cons 'firmware-revision (list (cons 'raw firmware-revision) (cons 'formatted (fmt-hex firmware-revision))))
        (cons 'firmware-build-version-nn (list (cons 'raw firmware-build-version-nn) (cons 'formatted (number->string firmware-build-version-nn))))
        (cons 'firmware-build-version-cw (list (cons 'raw firmware-build-version-cw) (cons 'formatted (number->string firmware-build-version-cw))))
        (cons 'firmware-build-version-yy (list (cons 'raw firmware-build-version-yy) (cons 'formatted (number->string firmware-build-version-yy))))
        (cons 'firmware-patch (list (cons 'raw firmware-patch) (cons 'formatted (number->string firmware-patch))))
        (cons 'identifier (list (cons 'raw identifier) (cons 'formatted (fmt-hex identifier))))
        (cons 'line (list (cons 'raw line) (cons 'formatted (number->string line))))
        (cons 'zero (list (cons 'raw zero) (cons 'formatted (fmt-hex zero))))
        (cons 'number-of-packets (list (cons 'raw number-of-packets) (cons 'formatted (number->string number-of-packets))))
        (cons 'transmit-traces (list (cons 'raw transmit-traces) (cons 'formatted (number->string transmit-traces))))
        (cons 'transmit-arq (list (cons 'raw transmit-arq) (cons 'formatted (fmt-hex transmit-arq))))
        (cons 'receive-traces (list (cons 'raw receive-traces) (cons 'formatted (number->string receive-traces))))
        (cons 'set-event-mask (list (cons 'raw set-event-mask) (cons 'formatted (fmt-hex set-event-mask))))
        (cons 'set-event-mask-reserved-15-63 (list (cons 'raw set-event-mask-reserved-15-63) (cons 'formatted (if (= set-event-mask-reserved-15-63 0) "Not set" "Set"))))
        (cons 'set-event-mask-firmware-trace-string (list (cons 'raw set-event-mask-firmware-trace-string) (cons 'formatted (if (= set-event-mask-firmware-trace-string 0) "Not set" "Set"))))
        (cons 'set-event-mask-le-link-established (list (cons 'raw set-event-mask-le-link-established) (cons 'formatted (if (= set-event-mask-le-link-established 0) "Not set" "Set"))))
        (cons 'set-event-mask-reserved-12 (list (cons 'raw set-event-mask-reserved-12) (cons 'formatted (if (= set-event-mask-reserved-12 0) "Not set" "Set"))))
        (cons 'set-event-mask-system-exception (list (cons 'raw set-event-mask-system-exception) (cons 'formatted (if (= set-event-mask-system-exception 0) "Not set" "Set"))))
        (cons 'set-event-mask-fatal-exception (list (cons 'raw set-event-mask-fatal-exception) (cons 'formatted (if (= set-event-mask-fatal-exception 0) "Not set" "Set"))))
        (cons 'set-event-mask-debug-exception (list (cons 'raw set-event-mask-debug-exception) (cons 'formatted (if (= set-event-mask-debug-exception 0) "Not set" "Set"))))
        (cons 'set-event-mask-reserved-8 (list (cons 'raw set-event-mask-reserved-8) (cons 'formatted (if (= set-event-mask-reserved-8 0) "Not set" "Set"))))
        (cons 'set-event-mask-scan-status (list (cons 'raw set-event-mask-scan-status) (cons 'formatted (if (= set-event-mask-scan-status 0) "Not set" "Set"))))
        (cons 'set-event-mask-reserved-3-6 (list (cons 'raw set-event-mask-reserved-3-6) (cons 'formatted (if (= set-event-mask-reserved-3-6 0) "Not set" "Set"))))
        (cons 'set-event-mask-ptt-switch-notification (list (cons 'raw set-event-mask-ptt-switch-notification) (cons 'formatted (if (= set-event-mask-ptt-switch-notification 0) "Not set" "Set"))))
        (cons 'set-event-mask-sco-rejected-via-lmp (list (cons 'raw set-event-mask-sco-rejected-via-lmp) (cons 'formatted (if (= set-event-mask-sco-rejected-via-lmp 0) "Not set" "Set"))))
        (cons 'set-event-mask-bootup (list (cons 'raw set-event-mask-bootup) (cons 'formatted (if (= set-event-mask-bootup 0) "Not set" "Set"))))
        (cons 'ddc-config-length (list (cons 'raw ddc-config-length) (cons 'formatted (number->string ddc-config-length))))
        (cons 'access-address (list (cons 'raw access-address) (cons 'formatted (fmt-hex access-address))))
        (cons 'mem-address (list (cons 'raw mem-address) (cons 'formatted (fmt-hex mem-address))))
        (cons 'scan-status (list (cons 'raw scan-status) (cons 'formatted (fmt-hex scan-status))))
        (cons 'scan-status-reserved (list (cons 'raw scan-status-reserved) (cons 'formatted (if (= scan-status-reserved 0) "Not set" "Set"))))
        (cons 'scan-status-page-scan (list (cons 'raw scan-status-page-scan) (cons 'formatted (if (= scan-status-page-scan 0) "Not set" "Set"))))
        (cons 'scan-status-inquiry-scan (list (cons 'raw scan-status-inquiry-scan) (cons 'formatted (if (= scan-status-inquiry-scan 0) "Not set" "Set"))))
        (cons 'mem-length (list (cons 'raw mem-length) (cons 'formatted (number->string mem-length))))
        (cons 'link-clock (list (cons 'raw link-clock) (cons 'formatted (fmt-hex link-clock))))
        (cons 'link-count (list (cons 'raw link-count) (cons 'formatted (number->string link-count))))
        (cons 'link-id (list (cons 'raw link-id) (cons 'formatted (fmt-hex link-id))))
        (cons 'reason (list (cons 'raw reason) (cons 'formatted (number->string reason))))
        (cons 'handle (list (cons 'raw handle) (cons 'formatted (fmt-hex handle))))
        )))

    (catch (e)
      (err (str "BTHCI-VENDOR-INTEL parse error: " e)))))

;; dissect-bthci-vendor-intel: parse BTHCI-VENDOR-INTEL from bytevector
;; Returns (ok fields-alist) or (err message)