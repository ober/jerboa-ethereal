;; packet-reload.c
;; Routines for REsource LOcation And Discovery (RELOAD) Base Protocol
;; Author: Stephane Bryant <sbryant@glycon.org>
;; Copyright 2010 Stonyfish Inc.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; Please refer to the following specs for protocol detail:
;; - RFC 6940
;; - RFC 7904
;; - RFC 7374
;; - RFC 7363
;; - RFC 7851
;; - RFC 7263
;;

;; jerboa-ethereal/dissectors/reload.ss
;; Auto-generated from wireshark/epan/dissectors/packet-reload.c
;; RFC 6940

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
(def (dissect-reload buffer)
  "REsource LOcation And Discovery"
  (try
    (let* (
           (duplicate (unwrap (read-u32be buffer 0)))
           (token (unwrap (read-u32be buffer 0)))
           (destination-compressed-id (unwrap (read-u16be buffer 0)))
           (responsible-set (unwrap (read-u32be buffer 0)))
           (num-resources (unwrap (read-u32be buffer 0)))
           (ipv4addr (unwrap (read-u32be buffer 2)))
           (port (unwrap (read-u16be buffer 2)))
           (ipv6addr (unwrap (slice buffer 2 16)))
           (overlay (unwrap (read-u32be buffer 4)))
           (configuration-sequence (unwrap (read-u16be buffer 8)))
           (length-uint16 (unwrap (read-u16be buffer 9)))
           (ttl (unwrap (read-u8 buffer 11)))
           (fragment-flag (unwrap (read-u32be buffer 12)))
           (fragment-offset (unwrap (read-u32be buffer 13)))
           (trans-id (unwrap (read-u64be buffer 20)))
           (max-response-length (unwrap (read-u32be buffer 28)))
           (via-list-length (unwrap (read-u16be buffer 32)))
           (destination-list-length (unwrap (read-u16be buffer 34)))
           (turnserver-iteration (unwrap (read-u8 buffer 34)))
           (redirserviceproviderdata-level (unwrap (read-u16be buffer 35)))
           (options-length (unwrap (read-u16be buffer 36)))
           (redirserviceproviderdata-node (unwrap (read-u16be buffer 37)))
           (datavalue-exists (unwrap (read-u8 buffer 39)))
           (metadata-value-length (unwrap (read-u32be buffer 39)))
           (arrayentry-index (unwrap (read-u32be buffer 39)))
           (storeddata-lifetime (unwrap (read-u32be buffer 58)))
           (store-replica-num (unwrap (read-u8 buffer 89)))
           (generation-counter (unwrap (read-u64be buffer 94)))
           (uptime (unwrap (read-u32be buffer 108)))
           (self-tuning-data-network-size (unwrap (read-u32be buffer 114)))
           (self-tuning-data-join-rate (unwrap (read-u32be buffer 114)))
           (self-tuning-data-leave-rate (unwrap (read-u32be buffer 114)))
           (dmflags (unwrap (read-u64be buffer 121)))
           (diagnosticextension-type (unwrap (read-u16be buffer 121)))
           (diagnosticinfo-congestion-status (unwrap (read-u8 buffer 147)))
           (diagnosticinfo-number-peers (unwrap (read-u32be buffer 147)))
           (diagnosticinfo-processing-power (unwrap (read-u32be buffer 147)))
           (diagnosticinfo-bandwidth (unwrap (read-u32be buffer 147)))
           (diagnosticinfo-software-version (unwrap (slice buffer 147 1)))
           (diagnosticinfo-machine-uptime (unwrap (read-u64be buffer 147)))
           (diagnosticinfo-app-uptime (unwrap (read-u64be buffer 147)))
           (diagnosticinfo-memory-footprint (unwrap (read-u32be buffer 147)))
           (diagnosticinfo-datasize-stored (unwrap (read-u64be buffer 147)))
           (diagnosticinfo-ewma-bytes-sent (unwrap (read-u32be buffer 177)))
           (diagnosticinfo-ewma-bytes-rcvd (unwrap (read-u32be buffer 177)))
           (diagnosticinfo-underlay-hops (unwrap (read-u8 buffer 177)))
           (diagnosticinfo-battery-status (unwrap (read-u8 buffer 177)))
           (opaque-data (unwrap (slice buffer 177 1)))
           (diagnosticresponse-hopcounter (unwrap (read-u8 buffer 193)))
           (length-uint8 (unwrap (read-u8 buffer 199)))
           (sendupdate (unwrap (read-u8 buffer 206)))
           (ping-response-id (unwrap (read-u64be buffer 208)))
           (length-uint24 (unwrap (read-u32be buffer 213)))
           (message-code (unwrap (read-u16be buffer 213)))
           (opaque-string (unwrap (slice buffer 219 32)))
           (length-uint32 (unwrap (read-u32be buffer 219)))
           )

      (ok (list
        (cons 'duplicate (list (cons 'raw duplicate) (cons 'formatted (number->string duplicate))))
        (cons 'token (list (cons 'raw token) (cons 'formatted (fmt-hex token))))
        (cons 'destination-compressed-id (list (cons 'raw destination-compressed-id) (cons 'formatted (fmt-hex destination-compressed-id))))
        (cons 'responsible-set (list (cons 'raw responsible-set) (cons 'formatted (fmt-hex responsible-set))))
        (cons 'num-resources (list (cons 'raw num-resources) (cons 'formatted (number->string num-resources))))
        (cons 'ipv4addr (list (cons 'raw ipv4addr) (cons 'formatted (fmt-ipv4 ipv4addr))))
        (cons 'port (list (cons 'raw port) (cons 'formatted (number->string port))))
        (cons 'ipv6addr (list (cons 'raw ipv6addr) (cons 'formatted (fmt-ipv6-address ipv6addr))))
        (cons 'overlay (list (cons 'raw overlay) (cons 'formatted (fmt-hex overlay))))
        (cons 'configuration-sequence (list (cons 'raw configuration-sequence) (cons 'formatted (number->string configuration-sequence))))
        (cons 'length-uint16 (list (cons 'raw length-uint16) (cons 'formatted (number->string length-uint16))))
        (cons 'ttl (list (cons 'raw ttl) (cons 'formatted (number->string ttl))))
        (cons 'fragment-flag (list (cons 'raw fragment-flag) (cons 'formatted (fmt-hex fragment-flag))))
        (cons 'fragment-offset (list (cons 'raw fragment-offset) (cons 'formatted (number->string fragment-offset))))
        (cons 'trans-id (list (cons 'raw trans-id) (cons 'formatted (fmt-hex trans-id))))
        (cons 'max-response-length (list (cons 'raw max-response-length) (cons 'formatted (number->string max-response-length))))
        (cons 'via-list-length (list (cons 'raw via-list-length) (cons 'formatted (number->string via-list-length))))
        (cons 'destination-list-length (list (cons 'raw destination-list-length) (cons 'formatted (number->string destination-list-length))))
        (cons 'turnserver-iteration (list (cons 'raw turnserver-iteration) (cons 'formatted (number->string turnserver-iteration))))
        (cons 'redirserviceproviderdata-level (list (cons 'raw redirserviceproviderdata-level) (cons 'formatted (number->string redirserviceproviderdata-level))))
        (cons 'options-length (list (cons 'raw options-length) (cons 'formatted (number->string options-length))))
        (cons 'redirserviceproviderdata-node (list (cons 'raw redirserviceproviderdata-node) (cons 'formatted (number->string redirserviceproviderdata-node))))
        (cons 'datavalue-exists (list (cons 'raw datavalue-exists) (cons 'formatted (number->string datavalue-exists))))
        (cons 'metadata-value-length (list (cons 'raw metadata-value-length) (cons 'formatted (number->string metadata-value-length))))
        (cons 'arrayentry-index (list (cons 'raw arrayentry-index) (cons 'formatted (number->string arrayentry-index))))
        (cons 'storeddata-lifetime (list (cons 'raw storeddata-lifetime) (cons 'formatted (number->string storeddata-lifetime))))
        (cons 'store-replica-num (list (cons 'raw store-replica-num) (cons 'formatted (number->string store-replica-num))))
        (cons 'generation-counter (list (cons 'raw generation-counter) (cons 'formatted (number->string generation-counter))))
        (cons 'uptime (list (cons 'raw uptime) (cons 'formatted (number->string uptime))))
        (cons 'self-tuning-data-network-size (list (cons 'raw self-tuning-data-network-size) (cons 'formatted (number->string self-tuning-data-network-size))))
        (cons 'self-tuning-data-join-rate (list (cons 'raw self-tuning-data-join-rate) (cons 'formatted (number->string self-tuning-data-join-rate))))
        (cons 'self-tuning-data-leave-rate (list (cons 'raw self-tuning-data-leave-rate) (cons 'formatted (number->string self-tuning-data-leave-rate))))
        (cons 'dmflags (list (cons 'raw dmflags) (cons 'formatted (fmt-hex dmflags))))
        (cons 'diagnosticextension-type (list (cons 'raw diagnosticextension-type) (cons 'formatted (number->string diagnosticextension-type))))
        (cons 'diagnosticinfo-congestion-status (list (cons 'raw diagnosticinfo-congestion-status) (cons 'formatted (number->string diagnosticinfo-congestion-status))))
        (cons 'diagnosticinfo-number-peers (list (cons 'raw diagnosticinfo-number-peers) (cons 'formatted (number->string diagnosticinfo-number-peers))))
        (cons 'diagnosticinfo-processing-power (list (cons 'raw diagnosticinfo-processing-power) (cons 'formatted (number->string diagnosticinfo-processing-power))))
        (cons 'diagnosticinfo-bandwidth (list (cons 'raw diagnosticinfo-bandwidth) (cons 'formatted (number->string diagnosticinfo-bandwidth))))
        (cons 'diagnosticinfo-software-version (list (cons 'raw diagnosticinfo-software-version) (cons 'formatted (utf8->string diagnosticinfo-software-version))))
        (cons 'diagnosticinfo-machine-uptime (list (cons 'raw diagnosticinfo-machine-uptime) (cons 'formatted (number->string diagnosticinfo-machine-uptime))))
        (cons 'diagnosticinfo-app-uptime (list (cons 'raw diagnosticinfo-app-uptime) (cons 'formatted (number->string diagnosticinfo-app-uptime))))
        (cons 'diagnosticinfo-memory-footprint (list (cons 'raw diagnosticinfo-memory-footprint) (cons 'formatted (number->string diagnosticinfo-memory-footprint))))
        (cons 'diagnosticinfo-datasize-stored (list (cons 'raw diagnosticinfo-datasize-stored) (cons 'formatted (number->string diagnosticinfo-datasize-stored))))
        (cons 'diagnosticinfo-ewma-bytes-sent (list (cons 'raw diagnosticinfo-ewma-bytes-sent) (cons 'formatted (number->string diagnosticinfo-ewma-bytes-sent))))
        (cons 'diagnosticinfo-ewma-bytes-rcvd (list (cons 'raw diagnosticinfo-ewma-bytes-rcvd) (cons 'formatted (number->string diagnosticinfo-ewma-bytes-rcvd))))
        (cons 'diagnosticinfo-underlay-hops (list (cons 'raw diagnosticinfo-underlay-hops) (cons 'formatted (number->string diagnosticinfo-underlay-hops))))
        (cons 'diagnosticinfo-battery-status (list (cons 'raw diagnosticinfo-battery-status) (cons 'formatted (number->string diagnosticinfo-battery-status))))
        (cons 'opaque-data (list (cons 'raw opaque-data) (cons 'formatted (fmt-bytes opaque-data))))
        (cons 'diagnosticresponse-hopcounter (list (cons 'raw diagnosticresponse-hopcounter) (cons 'formatted (number->string diagnosticresponse-hopcounter))))
        (cons 'length-uint8 (list (cons 'raw length-uint8) (cons 'formatted (number->string length-uint8))))
        (cons 'sendupdate (list (cons 'raw sendupdate) (cons 'formatted (number->string sendupdate))))
        (cons 'ping-response-id (list (cons 'raw ping-response-id) (cons 'formatted (number->string ping-response-id))))
        (cons 'length-uint24 (list (cons 'raw length-uint24) (cons 'formatted (number->string length-uint24))))
        (cons 'message-code (list (cons 'raw message-code) (cons 'formatted (number->string message-code))))
        (cons 'opaque-string (list (cons 'raw opaque-string) (cons 'formatted (utf8->string opaque-string))))
        (cons 'length-uint32 (list (cons 'raw length-uint32) (cons 'formatted (number->string length-uint32))))
        )))

    (catch (e)
      (err (str "RELOAD parse error: " e)))))

;; dissect-reload: parse RELOAD from bytevector
;; Returns (ok fields-alist) or (err message)