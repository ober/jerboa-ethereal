;; packet-adwin-config.c
;; Routines for ADwin configuration protocol dissection
;; Copyright 2010, Thomas Boehne <TBoehne[AT]ADwin.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/adwin-config.ss
;; Auto-generated from wireshark/epan/dissectors/packet-adwin_config.c

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
(def (dissect-adwin-config buffer)
  "ADwin configuration protocol"
  (try
    (let* (
           (config-stream-length (unwrap (read-u32be buffer 0)))
           (config-reboot (unwrap (read-u8 buffer 4)))
           (config-version (unwrap (read-u32be buffer 4)))
           (config-eeprom-support (unwrap (read-u8 buffer 4)))
           (config-path (unwrap (slice buffer 4 1)))
           (config-filesize (unwrap (read-u32be buffer 4)))
           (config-status (unwrap (read-u32be buffer 12)))
           (config-server-version-beta (unwrap (read-u32be buffer 12)))
           (config-server-version (unwrap (read-u32be buffer 14)))
           (config-timeout (unwrap (read-u32be buffer 16)))
           (config-server-ip (unwrap (read-u32be buffer 16)))
           (config-description (unwrap (slice buffer 16 16)))
           (config-xilinx-version (unwrap (read-u32be buffer 16)))
           (config-filename (unwrap (slice buffer 20 24)))
           (config-mac (unwrap (slice buffer 20 6)))
           (config-netmask (unwrap (read-u32be buffer 24)))
           (config-port16 (unwrap (read-u16be buffer 28)))
           (config-dhcp (unwrap (read-u8 buffer 30)))
           (config-netmask-count (unwrap (read-u8 buffer 31)))
           (config-timerresets (unwrap (read-u32be buffer 32)))
           (config-gateway (unwrap (read-u32be buffer 32)))
           (config-socketshutdowns (unwrap (read-u32be buffer 36)))
           (config-disk-free (unwrap (read-u32be buffer 40)))
           (config-port32 (unwrap (read-u32be buffer 44)))
           (config-disk-size (unwrap (read-u32be buffer 44)))
           (config-password (unwrap (slice buffer 48 10)))
           (config-date (unwrap (slice buffer 48 8)))
           (config-scan-id (unwrap (read-u32be buffer 48)))
           (config-revision (unwrap (slice buffer 56 8)))
           (config-bootloader (unwrap (read-u8 buffer 58)))
           (config-processor-type (unwrap (slice buffer 64 2)))
           (config-processor-type-raw (unwrap (slice buffer 64 2)))
           (config-system-type (unwrap (slice buffer 66 2)))
           (config-system-type-raw (unwrap (slice buffer 66 2)))
           )

      (ok (list
        (cons 'config-stream-length (list (cons 'raw config-stream-length) (cons 'formatted (number->string config-stream-length))))
        (cons 'config-reboot (list (cons 'raw config-reboot) (cons 'formatted (number->string config-reboot))))
        (cons 'config-version (list (cons 'raw config-version) (cons 'formatted (number->string config-version))))
        (cons 'config-eeprom-support (list (cons 'raw config-eeprom-support) (cons 'formatted (if (= config-eeprom-support 0) "False" "True"))))
        (cons 'config-path (list (cons 'raw config-path) (cons 'formatted (utf8->string config-path))))
        (cons 'config-filesize (list (cons 'raw config-filesize) (cons 'formatted (number->string config-filesize))))
        (cons 'config-status (list (cons 'raw config-status) (cons 'formatted (fmt-hex config-status))))
        (cons 'config-server-version-beta (list (cons 'raw config-server-version-beta) (cons 'formatted (number->string config-server-version-beta))))
        (cons 'config-server-version (list (cons 'raw config-server-version) (cons 'formatted (number->string config-server-version))))
        (cons 'config-timeout (list (cons 'raw config-timeout) (cons 'formatted (number->string config-timeout))))
        (cons 'config-server-ip (list (cons 'raw config-server-ip) (cons 'formatted (fmt-ipv4 config-server-ip))))
        (cons 'config-description (list (cons 'raw config-description) (cons 'formatted (utf8->string config-description))))
        (cons 'config-xilinx-version (list (cons 'raw config-xilinx-version) (cons 'formatted (fmt-hex config-xilinx-version))))
        (cons 'config-filename (list (cons 'raw config-filename) (cons 'formatted (utf8->string config-filename))))
        (cons 'config-mac (list (cons 'raw config-mac) (cons 'formatted (fmt-mac config-mac))))
        (cons 'config-netmask (list (cons 'raw config-netmask) (cons 'formatted (fmt-ipv4 config-netmask))))
        (cons 'config-port16 (list (cons 'raw config-port16) (cons 'formatted (number->string config-port16))))
        (cons 'config-dhcp (list (cons 'raw config-dhcp) (cons 'formatted (number->string config-dhcp))))
        (cons 'config-netmask-count (list (cons 'raw config-netmask-count) (cons 'formatted (number->string config-netmask-count))))
        (cons 'config-timerresets (list (cons 'raw config-timerresets) (cons 'formatted (number->string config-timerresets))))
        (cons 'config-gateway (list (cons 'raw config-gateway) (cons 'formatted (fmt-ipv4 config-gateway))))
        (cons 'config-socketshutdowns (list (cons 'raw config-socketshutdowns) (cons 'formatted (number->string config-socketshutdowns))))
        (cons 'config-disk-free (list (cons 'raw config-disk-free) (cons 'formatted (number->string config-disk-free))))
        (cons 'config-port32 (list (cons 'raw config-port32) (cons 'formatted (number->string config-port32))))
        (cons 'config-disk-size (list (cons 'raw config-disk-size) (cons 'formatted (number->string config-disk-size))))
        (cons 'config-password (list (cons 'raw config-password) (cons 'formatted (utf8->string config-password))))
        (cons 'config-date (list (cons 'raw config-date) (cons 'formatted (utf8->string config-date))))
        (cons 'config-scan-id (list (cons 'raw config-scan-id) (cons 'formatted (fmt-hex config-scan-id))))
        (cons 'config-revision (list (cons 'raw config-revision) (cons 'formatted (utf8->string config-revision))))
        (cons 'config-bootloader (list (cons 'raw config-bootloader) (cons 'formatted (number->string config-bootloader))))
        (cons 'config-processor-type (list (cons 'raw config-processor-type) (cons 'formatted (utf8->string config-processor-type))))
        (cons 'config-processor-type-raw (list (cons 'raw config-processor-type-raw) (cons 'formatted (utf8->string config-processor-type-raw))))
        (cons 'config-system-type (list (cons 'raw config-system-type) (cons 'formatted (utf8->string config-system-type))))
        (cons 'config-system-type-raw (list (cons 'raw config-system-type-raw) (cons 'formatted (utf8->string config-system-type-raw))))
        )))

    (catch (e)
      (err (str "ADWIN-CONFIG parse error: " e)))))

;; dissect-adwin-config: parse ADWIN-CONFIG from bytevector
;; Returns (ok fields-alist) or (err message)