;; packet-lacp.c
;; Routines for Link Aggregation Control Protocol dissection.
;; IEEE Std 802.1AX-2014 Section 6.4.2.3
;; Split from IEEE Std 802.3-2005 and named IEEE 802.3ad before that
;;
;; Copyright 2002 Steve Housley <steve_housley@3com.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/lacp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-lacp.c

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
(def (dissect-lacp buffer)
  "Link Aggregation Control Protocol"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 1)))
           (actor-sysid-priority (unwrap (read-u16be buffer 4)))
           (actor-sysid (unwrap (slice buffer 6 6)))
           (actor-key (unwrap (read-u16be buffer 12)))
           (actor-port-priority (unwrap (read-u16be buffer 14)))
           (actor-port (unwrap (read-u16be buffer 16)))
           (actor-state (unwrap (read-u8 buffer 18)))
           (flags-a-activity (extract-bits actor-state 0x0 0))
           (flags-a-timeout (extract-bits actor-state 0x0 0))
           (flags-a-aggregation (extract-bits actor-state 0x0 0))
           (flags-a-sync (extract-bits actor-state 0x0 0))
           (flags-a-collecting (extract-bits actor-state 0x0 0))
           (flags-a-distrib (extract-bits actor-state 0x0 0))
           (flags-a-defaulted (extract-bits actor-state 0x0 0))
           (flags-a-expired (extract-bits actor-state 0x0 0))
           (actor-state-str (unwrap (slice buffer 18 1)))
           (actor-reserved (unwrap (slice buffer 19 3)))
           (partner-sysid-priority (unwrap (read-u16be buffer 24)))
           (partner-sysid (unwrap (slice buffer 26 6)))
           (partner-key (unwrap (read-u16be buffer 32)))
           (partner-port-priority (unwrap (read-u16be buffer 34)))
           (partner-port (unwrap (read-u16be buffer 36)))
           (partner-state (unwrap (read-u8 buffer 38)))
           (flags-p-activity (extract-bits partner-state 0x0 0))
           (flags-p-timeout (extract-bits partner-state 0x0 0))
           (flags-p-aggregation (extract-bits partner-state 0x0 0))
           (flags-p-sync (extract-bits partner-state 0x0 0))
           (flags-p-collecting (extract-bits partner-state 0x0 0))
           (flags-p-distrib (extract-bits partner-state 0x0 0))
           (flags-p-defaulted (extract-bits partner-state 0x0 0))
           (flags-p-expired (extract-bits partner-state 0x0 0))
           (partner-state-str (unwrap (slice buffer 38 1)))
           (partner-reserved (unwrap (slice buffer 39 3)))
           (coll-max-delay (unwrap (read-u16be buffer 44)))
           (coll-reserved (unwrap (slice buffer 46 12)))
           (tlv-length (unwrap (read-u8 buffer 61)))
           (vendor (unwrap (slice buffer 62 1)))
           (vendor-hp-length (unwrap (read-u8 buffer 63)))
           (vendor-hp-irf-domain (unwrap (read-u16be buffer 66)))
           (vendor-hp-irf-mac (unwrap (slice buffer 68 6)))
           (vendor-hp-irf-switch (unwrap (read-u16be buffer 82)))
           (vendor-hp-irf-port (unwrap (read-u16be buffer 84)))
           (vendor-hp-unknown (unwrap (slice buffer 86 2)))
           (vlacp-subtype (unwrap (read-u8 buffer 88)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (fmt-hex version))))
        (cons 'actor-sysid-priority (list (cons 'raw actor-sysid-priority) (cons 'formatted (number->string actor-sysid-priority))))
        (cons 'actor-sysid (list (cons 'raw actor-sysid) (cons 'formatted (fmt-mac actor-sysid))))
        (cons 'actor-key (list (cons 'raw actor-key) (cons 'formatted (number->string actor-key))))
        (cons 'actor-port-priority (list (cons 'raw actor-port-priority) (cons 'formatted (number->string actor-port-priority))))
        (cons 'actor-port (list (cons 'raw actor-port) (cons 'formatted (number->string actor-port))))
        (cons 'actor-state (list (cons 'raw actor-state) (cons 'formatted (fmt-hex actor-state))))
        (cons 'flags-a-activity (list (cons 'raw flags-a-activity) (cons 'formatted (if (= flags-a-activity 0) "Passive" "Active"))))
        (cons 'flags-a-timeout (list (cons 'raw flags-a-timeout) (cons 'formatted (if (= flags-a-timeout 0) "Long Timeout" "Short Timeout"))))
        (cons 'flags-a-aggregation (list (cons 'raw flags-a-aggregation) (cons 'formatted (if (= flags-a-aggregation 0) "Individual" "Aggregatable"))))
        (cons 'flags-a-sync (list (cons 'raw flags-a-sync) (cons 'formatted (if (= flags-a-sync 0) "Out of Sync" "In Sync"))))
        (cons 'flags-a-collecting (list (cons 'raw flags-a-collecting) (cons 'formatted (if (= flags-a-collecting 0) "Not set" "Set"))))
        (cons 'flags-a-distrib (list (cons 'raw flags-a-distrib) (cons 'formatted (if (= flags-a-distrib 0) "Not set" "Set"))))
        (cons 'flags-a-defaulted (list (cons 'raw flags-a-defaulted) (cons 'formatted (if (= flags-a-defaulted 0) "Not set" "Set"))))
        (cons 'flags-a-expired (list (cons 'raw flags-a-expired) (cons 'formatted (if (= flags-a-expired 0) "Not set" "Set"))))
        (cons 'actor-state-str (list (cons 'raw actor-state-str) (cons 'formatted (utf8->string actor-state-str))))
        (cons 'actor-reserved (list (cons 'raw actor-reserved) (cons 'formatted (fmt-bytes actor-reserved))))
        (cons 'partner-sysid-priority (list (cons 'raw partner-sysid-priority) (cons 'formatted (number->string partner-sysid-priority))))
        (cons 'partner-sysid (list (cons 'raw partner-sysid) (cons 'formatted (fmt-mac partner-sysid))))
        (cons 'partner-key (list (cons 'raw partner-key) (cons 'formatted (number->string partner-key))))
        (cons 'partner-port-priority (list (cons 'raw partner-port-priority) (cons 'formatted (number->string partner-port-priority))))
        (cons 'partner-port (list (cons 'raw partner-port) (cons 'formatted (number->string partner-port))))
        (cons 'partner-state (list (cons 'raw partner-state) (cons 'formatted (fmt-hex partner-state))))
        (cons 'flags-p-activity (list (cons 'raw flags-p-activity) (cons 'formatted (if (= flags-p-activity 0) "Passive" "Active"))))
        (cons 'flags-p-timeout (list (cons 'raw flags-p-timeout) (cons 'formatted (if (= flags-p-timeout 0) "Long Timeout" "Short Timeout"))))
        (cons 'flags-p-aggregation (list (cons 'raw flags-p-aggregation) (cons 'formatted (if (= flags-p-aggregation 0) "Individual" "Aggregatable"))))
        (cons 'flags-p-sync (list (cons 'raw flags-p-sync) (cons 'formatted (if (= flags-p-sync 0) "Out of Sync" "In Sync"))))
        (cons 'flags-p-collecting (list (cons 'raw flags-p-collecting) (cons 'formatted (if (= flags-p-collecting 0) "Not set" "Set"))))
        (cons 'flags-p-distrib (list (cons 'raw flags-p-distrib) (cons 'formatted (if (= flags-p-distrib 0) "Not set" "Set"))))
        (cons 'flags-p-defaulted (list (cons 'raw flags-p-defaulted) (cons 'formatted (if (= flags-p-defaulted 0) "Not set" "Set"))))
        (cons 'flags-p-expired (list (cons 'raw flags-p-expired) (cons 'formatted (if (= flags-p-expired 0) "Not set" "Set"))))
        (cons 'partner-state-str (list (cons 'raw partner-state-str) (cons 'formatted (utf8->string partner-state-str))))
        (cons 'partner-reserved (list (cons 'raw partner-reserved) (cons 'formatted (fmt-bytes partner-reserved))))
        (cons 'coll-max-delay (list (cons 'raw coll-max-delay) (cons 'formatted (number->string coll-max-delay))))
        (cons 'coll-reserved (list (cons 'raw coll-reserved) (cons 'formatted (fmt-bytes coll-reserved))))
        (cons 'tlv-length (list (cons 'raw tlv-length) (cons 'formatted (fmt-hex tlv-length))))
        (cons 'vendor (list (cons 'raw vendor) (cons 'formatted (fmt-bytes vendor))))
        (cons 'vendor-hp-length (list (cons 'raw vendor-hp-length) (cons 'formatted (number->string vendor-hp-length))))
        (cons 'vendor-hp-irf-domain (list (cons 'raw vendor-hp-irf-domain) (cons 'formatted (number->string vendor-hp-irf-domain))))
        (cons 'vendor-hp-irf-mac (list (cons 'raw vendor-hp-irf-mac) (cons 'formatted (fmt-mac vendor-hp-irf-mac))))
        (cons 'vendor-hp-irf-switch (list (cons 'raw vendor-hp-irf-switch) (cons 'formatted (number->string vendor-hp-irf-switch))))
        (cons 'vendor-hp-irf-port (list (cons 'raw vendor-hp-irf-port) (cons 'formatted (number->string vendor-hp-irf-port))))
        (cons 'vendor-hp-unknown (list (cons 'raw vendor-hp-unknown) (cons 'formatted (fmt-bytes vendor-hp-unknown))))
        (cons 'vlacp-subtype (list (cons 'raw vlacp-subtype) (cons 'formatted (number->string vlacp-subtype))))
        )))

    (catch (e)
      (err (str "LACP parse error: " e)))))

;; dissect-lacp: parse LACP from bytevector
;; Returns (ok fields-alist) or (err message)