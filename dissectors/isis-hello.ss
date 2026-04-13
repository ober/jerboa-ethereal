;; packet-isis-hello.c
;; Routines for decoding isis hello packets and their CLVs
;;
;; Stuart Stanley <stuarts@mxmail.net>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/isis-hello.ss
;; Auto-generated from wireshark/epan/dissectors/packet-isis_hello.c

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
(def (dissect-isis-hello buffer)
  "ISIS HELLO"
  (try
    (let* (
           (hello-aux-mcid (unwrap (slice buffer 0 1)))
           (hello-digest-v (unwrap (read-u8 buffer 0)))
           (hello-digest-a (unwrap (read-u8 buffer 0)))
           (hello-digest-d (unwrap (read-u8 buffer 0)))
           (hello-digest (unwrap (slice buffer 0 1)))
           (hello-vlan-flags-port-id (unwrap (read-u16be buffer 0)))
           (hello-vlan-flags-nickname (unwrap (read-u16be buffer 2)))
           (hello-vlan-flags-af (unwrap (read-u8 buffer 4)))
           (hello-vlan-flags-ac (unwrap (read-u8 buffer 4)))
           (hello-vlan-flags-vm (unwrap (read-u8 buffer 4)))
           (hello-vlan-flags-by (unwrap (read-u8 buffer 4)))
           (hello-vlan-flags-outer-vlan (unwrap (read-u16be buffer 4)))
           (hello-vlan-flags-tr (unwrap (read-u8 buffer 6)))
           (hello-vlan-flags-reserved (unwrap (read-u8 buffer 6)))
           (hello-vlan-flags-designated-vlan (unwrap (read-u16be buffer 6)))
           (hello-enabled-vlans (unwrap (slice buffer 8 1)))
           (hello-af-nickname (unwrap (read-u16be buffer 8)))
           (hello-af-start-vlan (unwrap (read-u16be buffer 8)))
           (hello-af-end-vlan (unwrap (read-u16be buffer 8)))
           (hello-trill-version (unwrap (read-u8 buffer 14)))
           (hello-trill-hello-reduction (unwrap (read-u8 buffer 14)))
           (hello-trill-unassigned-1 (unwrap (read-u8 buffer 14)))
           (hello-trill-hop-by-hop-flags (unwrap (read-u8 buffer 14)))
           (hello-trill-unassigned-2 (unwrap (read-u8 buffer 14)))
           (hello-appointed-vlans (unwrap (slice buffer 16 1)))
           (hello-clv-restart-flags (unwrap (read-u8 buffer 20)))
           (hello-clv-restart-remain-time (unwrap (read-u16be buffer 20)))
           (hello-clv-ip-authentication (unwrap (slice buffer 20 1)))
           (hello-trill-neighbor-sf (unwrap (read-u8 buffer 20)))
           (hello-trill-neighbor-lf (unwrap (read-u8 buffer 20)))
           (hello-trill-neighbor-size (unwrap (read-u8 buffer 20)))
           (hello-trill-neighbor-ff (unwrap (read-u8 buffer 20)))
           (hello-trill-neighbor-of (unwrap (read-u8 buffer 20)))
           (hello-trill-neighbor-reserved (unwrap (read-u8 buffer 20)))
           (hello-trill-neighbor-mtu (unwrap (read-u16be buffer 20)))
           (hello-reverse-metric-flags (unwrap (read-u8 buffer 28)))
           (hello-reverse-metric-flag-reserved (extract-bits hello-reverse-metric-flags 0xFC 2))
           (hello-reverse-metric-flag-u (extract-bits hello-reverse-metric-flags 0x2 1))
           (hello-reverse-metric-flag-w (extract-bits hello-reverse-metric-flags 0x1 0))
           (hello-reverse-metric-metric (unwrap (read-u24be buffer 29)))
           (hello-reverse-metric-sub-length (unwrap (read-u8 buffer 32)))
           (hello-reverse-metric-sub-data (unwrap (slice buffer 33 1)))
           (hello-extended-local-circuit-id (unwrap (read-u32be buffer 36)))
           (hello-is-neighbor (unwrap (slice buffer 36 6)))
           (hello-circuit-reserved (unwrap (read-u8 buffer 50)))
           (hello-holding-timer (unwrap (read-u16be buffer 51)))
           (hello-pdu-length (unwrap (read-u16be buffer 53)))
           (hello-local-circuit-id (unwrap (read-u8 buffer 55)))
           (hello-priority (unwrap (read-u8 buffer 56)))
           (hello-priority-reserved (unwrap (read-u8 buffer 56)))
           (hello-mcid (unwrap (slice buffer 57 1)))
           )

      (ok (list
        (cons 'hello-aux-mcid (list (cons 'raw hello-aux-mcid) (cons 'formatted (fmt-bytes hello-aux-mcid))))
        (cons 'hello-digest-v (list (cons 'raw hello-digest-v) (cons 'formatted (number->string hello-digest-v))))
        (cons 'hello-digest-a (list (cons 'raw hello-digest-a) (cons 'formatted (number->string hello-digest-a))))
        (cons 'hello-digest-d (list (cons 'raw hello-digest-d) (cons 'formatted (number->string hello-digest-d))))
        (cons 'hello-digest (list (cons 'raw hello-digest) (cons 'formatted (fmt-bytes hello-digest))))
        (cons 'hello-vlan-flags-port-id (list (cons 'raw hello-vlan-flags-port-id) (cons 'formatted (number->string hello-vlan-flags-port-id))))
        (cons 'hello-vlan-flags-nickname (list (cons 'raw hello-vlan-flags-nickname) (cons 'formatted (fmt-hex hello-vlan-flags-nickname))))
        (cons 'hello-vlan-flags-af (list (cons 'raw hello-vlan-flags-af) (cons 'formatted (if (= hello-vlan-flags-af 0) "False" "True"))))
        (cons 'hello-vlan-flags-ac (list (cons 'raw hello-vlan-flags-ac) (cons 'formatted (if (= hello-vlan-flags-ac 0) "False" "True"))))
        (cons 'hello-vlan-flags-vm (list (cons 'raw hello-vlan-flags-vm) (cons 'formatted (if (= hello-vlan-flags-vm 0) "False" "True"))))
        (cons 'hello-vlan-flags-by (list (cons 'raw hello-vlan-flags-by) (cons 'formatted (if (= hello-vlan-flags-by 0) "False" "True"))))
        (cons 'hello-vlan-flags-outer-vlan (list (cons 'raw hello-vlan-flags-outer-vlan) (cons 'formatted (number->string hello-vlan-flags-outer-vlan))))
        (cons 'hello-vlan-flags-tr (list (cons 'raw hello-vlan-flags-tr) (cons 'formatted (if (= hello-vlan-flags-tr 0) "False" "True"))))
        (cons 'hello-vlan-flags-reserved (list (cons 'raw hello-vlan-flags-reserved) (cons 'formatted (if (= hello-vlan-flags-reserved 0) "False" "True"))))
        (cons 'hello-vlan-flags-designated-vlan (list (cons 'raw hello-vlan-flags-designated-vlan) (cons 'formatted (number->string hello-vlan-flags-designated-vlan))))
        (cons 'hello-enabled-vlans (list (cons 'raw hello-enabled-vlans) (cons 'formatted (utf8->string hello-enabled-vlans))))
        (cons 'hello-af-nickname (list (cons 'raw hello-af-nickname) (cons 'formatted (fmt-hex hello-af-nickname))))
        (cons 'hello-af-start-vlan (list (cons 'raw hello-af-start-vlan) (cons 'formatted (number->string hello-af-start-vlan))))
        (cons 'hello-af-end-vlan (list (cons 'raw hello-af-end-vlan) (cons 'formatted (number->string hello-af-end-vlan))))
        (cons 'hello-trill-version (list (cons 'raw hello-trill-version) (cons 'formatted (number->string hello-trill-version))))
        (cons 'hello-trill-hello-reduction (list (cons 'raw hello-trill-hello-reduction) (cons 'formatted (if (= hello-trill-hello-reduction 0) "False" "True"))))
        (cons 'hello-trill-unassigned-1 (list (cons 'raw hello-trill-unassigned-1) (cons 'formatted (if (= hello-trill-unassigned-1 0) "False" "True"))))
        (cons 'hello-trill-hop-by-hop-flags (list (cons 'raw hello-trill-hop-by-hop-flags) (cons 'formatted (if (= hello-trill-hop-by-hop-flags 0) "False" "True"))))
        (cons 'hello-trill-unassigned-2 (list (cons 'raw hello-trill-unassigned-2) (cons 'formatted (if (= hello-trill-unassigned-2 0) "False" "True"))))
        (cons 'hello-appointed-vlans (list (cons 'raw hello-appointed-vlans) (cons 'formatted (utf8->string hello-appointed-vlans))))
        (cons 'hello-clv-restart-flags (list (cons 'raw hello-clv-restart-flags) (cons 'formatted (fmt-hex hello-clv-restart-flags))))
        (cons 'hello-clv-restart-remain-time (list (cons 'raw hello-clv-restart-remain-time) (cons 'formatted (number->string hello-clv-restart-remain-time))))
        (cons 'hello-clv-ip-authentication (list (cons 'raw hello-clv-ip-authentication) (cons 'formatted (utf8->string hello-clv-ip-authentication))))
        (cons 'hello-trill-neighbor-sf (list (cons 'raw hello-trill-neighbor-sf) (cons 'formatted (if (= hello-trill-neighbor-sf 0) "False" "True"))))
        (cons 'hello-trill-neighbor-lf (list (cons 'raw hello-trill-neighbor-lf) (cons 'formatted (if (= hello-trill-neighbor-lf 0) "False" "True"))))
        (cons 'hello-trill-neighbor-size (list (cons 'raw hello-trill-neighbor-size) (cons 'formatted (number->string hello-trill-neighbor-size))))
        (cons 'hello-trill-neighbor-ff (list (cons 'raw hello-trill-neighbor-ff) (cons 'formatted (if (= hello-trill-neighbor-ff 0) "False" "True"))))
        (cons 'hello-trill-neighbor-of (list (cons 'raw hello-trill-neighbor-of) (cons 'formatted (if (= hello-trill-neighbor-of 0) "False" "True"))))
        (cons 'hello-trill-neighbor-reserved (list (cons 'raw hello-trill-neighbor-reserved) (cons 'formatted (number->string hello-trill-neighbor-reserved))))
        (cons 'hello-trill-neighbor-mtu (list (cons 'raw hello-trill-neighbor-mtu) (cons 'formatted (number->string hello-trill-neighbor-mtu))))
        (cons 'hello-reverse-metric-flags (list (cons 'raw hello-reverse-metric-flags) (cons 'formatted (fmt-hex hello-reverse-metric-flags))))
        (cons 'hello-reverse-metric-flag-reserved (list (cons 'raw hello-reverse-metric-flag-reserved) (cons 'formatted (if (= hello-reverse-metric-flag-reserved 0) "Not set" "Set"))))
        (cons 'hello-reverse-metric-flag-u (list (cons 'raw hello-reverse-metric-flag-u) (cons 'formatted (if (= hello-reverse-metric-flag-u 0) "Not set" "Set"))))
        (cons 'hello-reverse-metric-flag-w (list (cons 'raw hello-reverse-metric-flag-w) (cons 'formatted (if (= hello-reverse-metric-flag-w 0) "Not set" "Set"))))
        (cons 'hello-reverse-metric-metric (list (cons 'raw hello-reverse-metric-metric) (cons 'formatted (number->string hello-reverse-metric-metric))))
        (cons 'hello-reverse-metric-sub-length (list (cons 'raw hello-reverse-metric-sub-length) (cons 'formatted (number->string hello-reverse-metric-sub-length))))
        (cons 'hello-reverse-metric-sub-data (list (cons 'raw hello-reverse-metric-sub-data) (cons 'formatted (fmt-bytes hello-reverse-metric-sub-data))))
        (cons 'hello-extended-local-circuit-id (list (cons 'raw hello-extended-local-circuit-id) (cons 'formatted (fmt-hex hello-extended-local-circuit-id))))
        (cons 'hello-is-neighbor (list (cons 'raw hello-is-neighbor) (cons 'formatted (fmt-mac hello-is-neighbor))))
        (cons 'hello-circuit-reserved (list (cons 'raw hello-circuit-reserved) (cons 'formatted (fmt-hex hello-circuit-reserved))))
        (cons 'hello-holding-timer (list (cons 'raw hello-holding-timer) (cons 'formatted (number->string hello-holding-timer))))
        (cons 'hello-pdu-length (list (cons 'raw hello-pdu-length) (cons 'formatted (number->string hello-pdu-length))))
        (cons 'hello-local-circuit-id (list (cons 'raw hello-local-circuit-id) (cons 'formatted (number->string hello-local-circuit-id))))
        (cons 'hello-priority (list (cons 'raw hello-priority) (cons 'formatted (number->string hello-priority))))
        (cons 'hello-priority-reserved (list (cons 'raw hello-priority-reserved) (cons 'formatted (number->string hello-priority-reserved))))
        (cons 'hello-mcid (list (cons 'raw hello-mcid) (cons 'formatted (fmt-bytes hello-mcid))))
        )))

    (catch (e)
      (err (str "ISIS-HELLO parse error: " e)))))

;; dissect-isis-hello: parse ISIS-HELLO from bytevector
;; Returns (ok fields-alist) or (err message)