;; packet-zbee-zcl-misc.c
;; Dissector routines for the ZigBee ZCL SE clusters like
;; Messaging
;; By Fabio Tarabelloni <fabio.tarabelloni@reloc.it>
;; Copyright 2013 RELOC s.r.l.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/zbee-zcl-misc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-zbee_zcl_misc.c

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
(def (dissect-zbee-zcl-misc buffer)
  "ZigBee ZCL Thermostat"
  (try
    (let* (
           (zcl-thermostat-schedule-day-sequence (unwrap (read-u8 buffer 0)))
           (zcl-thermostat-schedule-day-sunday (extract-bits zcl-thermostat-schedule-day-sequence 0x1 0))
           (zcl-thermostat-schedule-day-monday (extract-bits zcl-thermostat-schedule-day-sequence 0x2 1))
           (zcl-thermostat-schedule-day-tuesday (extract-bits zcl-thermostat-schedule-day-sequence 0x4 2))
           (zcl-thermostat-schedule-day-wednesday (extract-bits zcl-thermostat-schedule-day-sequence 0x8 3))
           (zcl-thermostat-schedule-day-thursday (extract-bits zcl-thermostat-schedule-day-sequence 0x10 4))
           (zcl-thermostat-schedule-day-friday (extract-bits zcl-thermostat-schedule-day-sequence 0x20 5))
           (zcl-thermostat-schedule-day-saturday (extract-bits zcl-thermostat-schedule-day-sequence 0x40 6))
           (zcl-thermostat-schedule-day-vacation (extract-bits zcl-thermostat-schedule-day-sequence 0x80 7))
           (zcl-thermostat-schedule-mode-sequence (unwrap (read-u8 buffer 0)))
           (zcl-thermostat-schedule-mode-heat (extract-bits zcl-thermostat-schedule-mode-sequence 0x1 0))
           (zcl-thermostat-schedule-mode-cool (extract-bits zcl-thermostat-schedule-mode-sequence 0x2 1))
           (zcl-thermostat-schedule-num-trans (unwrap (read-u8 buffer 0)))
           (zcl-thermostat-setpoint-amount (unwrap (read-u32be buffer 0)))
           (zcl-ias-zone-status (unwrap (read-u16le buffer 0)))
           (zcl-ias-zone-status-alarm1 (extract-bits zcl-ias-zone-status 0x0 0))
           (zcl-ias-zone-status-alarm2 (extract-bits zcl-ias-zone-status 0x0 0))
           (zcl-ias-zone-status-tamper (extract-bits zcl-ias-zone-status 0x0 0))
           (zcl-ias-zone-status-battery (extract-bits zcl-ias-zone-status 0x0 0))
           (zcl-ias-zone-status-supervision-reports (extract-bits zcl-ias-zone-status 0x0 0))
           (zcl-ias-zone-status-restore-reports (extract-bits zcl-ias-zone-status 0x0 0))
           (zcl-ias-zone-status-trouble (extract-bits zcl-ias-zone-status 0x0 0))
           (zcl-ias-zone-status-ac-mains (extract-bits zcl-ias-zone-status 0x0 0))
           (zcl-thermostat-schedule-heat (unwrap (read-u32be buffer 2)))
           (zcl-ias-zone-ext-status (unwrap (read-u8 buffer 2)))
           (zcl-ias-zone-zone-id (unwrap (read-u8 buffer 3)))
           (zcl-thermostat-schedule-cool (unwrap (read-u32be buffer 4)))
           (zcl-ias-zone-delay (unwrap (read-u16be buffer 4)))
           )

      (ok (list
        (cons 'zcl-thermostat-schedule-day-sequence (list (cons 'raw zcl-thermostat-schedule-day-sequence) (cons 'formatted (fmt-hex zcl-thermostat-schedule-day-sequence))))
        (cons 'zcl-thermostat-schedule-day-sunday (list (cons 'raw zcl-thermostat-schedule-day-sunday) (cons 'formatted (if (= zcl-thermostat-schedule-day-sunday 0) "Not set" "Set"))))
        (cons 'zcl-thermostat-schedule-day-monday (list (cons 'raw zcl-thermostat-schedule-day-monday) (cons 'formatted (if (= zcl-thermostat-schedule-day-monday 0) "Not set" "Set"))))
        (cons 'zcl-thermostat-schedule-day-tuesday (list (cons 'raw zcl-thermostat-schedule-day-tuesday) (cons 'formatted (if (= zcl-thermostat-schedule-day-tuesday 0) "Not set" "Set"))))
        (cons 'zcl-thermostat-schedule-day-wednesday (list (cons 'raw zcl-thermostat-schedule-day-wednesday) (cons 'formatted (if (= zcl-thermostat-schedule-day-wednesday 0) "Not set" "Set"))))
        (cons 'zcl-thermostat-schedule-day-thursday (list (cons 'raw zcl-thermostat-schedule-day-thursday) (cons 'formatted (if (= zcl-thermostat-schedule-day-thursday 0) "Not set" "Set"))))
        (cons 'zcl-thermostat-schedule-day-friday (list (cons 'raw zcl-thermostat-schedule-day-friday) (cons 'formatted (if (= zcl-thermostat-schedule-day-friday 0) "Not set" "Set"))))
        (cons 'zcl-thermostat-schedule-day-saturday (list (cons 'raw zcl-thermostat-schedule-day-saturday) (cons 'formatted (if (= zcl-thermostat-schedule-day-saturday 0) "Not set" "Set"))))
        (cons 'zcl-thermostat-schedule-day-vacation (list (cons 'raw zcl-thermostat-schedule-day-vacation) (cons 'formatted (if (= zcl-thermostat-schedule-day-vacation 0) "Not set" "Set"))))
        (cons 'zcl-thermostat-schedule-mode-sequence (list (cons 'raw zcl-thermostat-schedule-mode-sequence) (cons 'formatted (fmt-hex zcl-thermostat-schedule-mode-sequence))))
        (cons 'zcl-thermostat-schedule-mode-heat (list (cons 'raw zcl-thermostat-schedule-mode-heat) (cons 'formatted (if (= zcl-thermostat-schedule-mode-heat 0) "Not set" "Set"))))
        (cons 'zcl-thermostat-schedule-mode-cool (list (cons 'raw zcl-thermostat-schedule-mode-cool) (cons 'formatted (if (= zcl-thermostat-schedule-mode-cool 0) "Not set" "Set"))))
        (cons 'zcl-thermostat-schedule-num-trans (list (cons 'raw zcl-thermostat-schedule-num-trans) (cons 'formatted (fmt-hex zcl-thermostat-schedule-num-trans))))
        (cons 'zcl-thermostat-setpoint-amount (list (cons 'raw zcl-thermostat-setpoint-amount) (cons 'formatted (number->string zcl-thermostat-setpoint-amount))))
        (cons 'zcl-ias-zone-status (list (cons 'raw zcl-ias-zone-status) (cons 'formatted (fmt-hex zcl-ias-zone-status))))
        (cons 'zcl-ias-zone-status-alarm1 (list (cons 'raw zcl-ias-zone-status-alarm1) (cons 'formatted (if (= zcl-ias-zone-status-alarm1 0) "Closed or not alarmed" "Opened or alarmed"))))
        (cons 'zcl-ias-zone-status-alarm2 (list (cons 'raw zcl-ias-zone-status-alarm2) (cons 'formatted (if (= zcl-ias-zone-status-alarm2 0) "Closed or not alarmed" "Opened or alarmed"))))
        (cons 'zcl-ias-zone-status-tamper (list (cons 'raw zcl-ias-zone-status-tamper) (cons 'formatted (if (= zcl-ias-zone-status-tamper 0) "Not tampered" "Tampered"))))
        (cons 'zcl-ias-zone-status-battery (list (cons 'raw zcl-ias-zone-status-battery) (cons 'formatted (if (= zcl-ias-zone-status-battery 0) "Battery OK" "Low battery"))))
        (cons 'zcl-ias-zone-status-supervision-reports (list (cons 'raw zcl-ias-zone-status-supervision-reports) (cons 'formatted (if (= zcl-ias-zone-status-supervision-reports 0) "Does not report" "Reports"))))
        (cons 'zcl-ias-zone-status-restore-reports (list (cons 'raw zcl-ias-zone-status-restore-reports) (cons 'formatted (if (= zcl-ias-zone-status-restore-reports 0) "Does not report restore" "Reports restore"))))
        (cons 'zcl-ias-zone-status-trouble (list (cons 'raw zcl-ias-zone-status-trouble) (cons 'formatted (if (= zcl-ias-zone-status-trouble 0) "OK" "Trouble/Failure"))))
        (cons 'zcl-ias-zone-status-ac-mains (list (cons 'raw zcl-ias-zone-status-ac-mains) (cons 'formatted (if (= zcl-ias-zone-status-ac-mains 0) "AC/Mains OK" "AC/Mains fault"))))
        (cons 'zcl-thermostat-schedule-heat (list (cons 'raw zcl-thermostat-schedule-heat) (cons 'formatted (number->string zcl-thermostat-schedule-heat))))
        (cons 'zcl-ias-zone-ext-status (list (cons 'raw zcl-ias-zone-ext-status) (cons 'formatted (fmt-hex zcl-ias-zone-ext-status))))
        (cons 'zcl-ias-zone-zone-id (list (cons 'raw zcl-ias-zone-zone-id) (cons 'formatted (fmt-hex zcl-ias-zone-zone-id))))
        (cons 'zcl-thermostat-schedule-cool (list (cons 'raw zcl-thermostat-schedule-cool) (cons 'formatted (number->string zcl-thermostat-schedule-cool))))
        (cons 'zcl-ias-zone-delay (list (cons 'raw zcl-ias-zone-delay) (cons 'formatted (number->string zcl-ias-zone-delay))))
        )))

    (catch (e)
      (err (str "ZBEE-ZCL-MISC parse error: " e)))))

;; dissect-zbee-zcl-misc: parse ZBEE-ZCL-MISC from bytevector
;; Returns (ok fields-alist) or (err message)