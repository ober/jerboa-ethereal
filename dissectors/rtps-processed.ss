;; packet-rtps-processed.c
;; Dissector for the Real-Time Publish-Subscribe (RTPS) Processed Protocol.
;;
;; (c) 2020 Copyright, Real-Time Innovations, Inc.
;; Real-Time Innovations, Inc.
;; 232 East Java Drive
;; Sunnyvale, CA 94089
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; -----------------------------------------------------------------------------
;; RTI Connext DDS can capture RTPS-related traffic by using the Network Capture
;; Utility. The generated .pcap capture files will follow a format that
;; defines how information must be saved, and then parsed.
;;
;; The format is divided into two layers/protocols: virtual transport
;; (packet-rtps-virtual-transport.c) and processed (packet-rtps-processed.c).
;; This file is about the processed dissector. For a general introduction and
;; information about the virtual transport dissector, read the documentation at
;; the beginning of packet-rtps-virtual-transport.c.
;;
;; The processed dissector is called by the transport dissector. It should never
;; be called directly by Wireshark without going through the transport
;; dissector first.
;;
;; The advanced information contains one parameter that it is really important
;; (and compulsory). This parameter is the "main frame", i.e. the frame that
;; would usually be captured over the wire. This frame is encrypted if security
;; applies.
;;
;; Then we have two optional fields: advanced frame0 and frame1.
;; - frame0: Contains the RTPS frame with submessage protection (but
;; decrypted at the RTPS level).
;; - frame1:
;; - Inbound traffic: A list of decrypted RTPS submessages (the protected
;; ones from frame0).
;; - Outbound traffic: The RTPS message before any kind of protection.
;; The contents encrypted at RTPS message level can be found in the main frame.
;;
;; We can see there is a difference between frame1 (the parameter containing the
;; decrypted RTPS submessages): inbound traffic has a list of submessages (no
;; RTPS header) but outbound traffic has a RTPS message. The reason behind
;; this is related to how RTI Connext DDS handles protected inbound traffic.
;;
;; An alternative would be to build the RTPS message from frame0 and frame1 and
;; then pass it to the RTPS dissector. This solution would be cleaner but would
;; require to keep a buffer and information between parameters.
;; The current solution is kept for the moment.
;;

;; jerboa-ethereal/dissectors/rtps-processed.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rtps_processed.c

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
(def (dissect-rtps-processed buffer)
  "Real-Time Publish-Subscribe Wire Protocol (processed)"
  (try
    (let* (
           (param-id (unwrap (read-u16be buffer 8)))
           (param-length (unwrap (read-u16be buffer 10)))
           )

      (ok (list
        (cons 'param-id (list (cons 'raw param-id) (cons 'formatted (number->string param-id))))
        (cons 'param-length (list (cons 'raw param-length) (cons 'formatted (number->string param-length))))
        )))

    (catch (e)
      (err (str "RTPS-PROCESSED parse error: " e)))))

;; dissect-rtps-processed: parse RTPS-PROCESSED from bytevector
;; Returns (ok fields-alist) or (err message)