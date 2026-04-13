;; packet-rtps-virtual-transport.c
;; Dissector for the Real-Time Publish-Subscribe (RTPS) Virtual Transport
;; Protocol.
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
;; Utility. The generated .pcap capture files will follow the RTPS-VT protocol,
;; which establishes a format for how information must be saved, and then
;; parsed.
;;
;; The protocol is divided into two layers: transport
;; (packet-rtps-virtual-transport.c) and advanced (packet-rtps-processed.c).
;; This file is about the transport dissector. For more information about the
;; advanced dissector, read the documentation at the beginning of
;; packet-rtps-processed.c.
;;
;; Every packet saved in the capture file follows the PCAP file format.
;; As a consequence, there are two headers: a global one (unique per file) and
;; a per-packet header. These headers have the typical content described in the
;; PCAP format: a magic number, version number, some timestamps, information
;; describing the length of the packet and the data link layer (0x000000fc, i.e.
;; custom protocol), etc. Then, we have a header that indicates Wireshark the
;; name of the protocol: "rtpsvt". The transport dissector is called when
;; Wireshark finds "rtpsvt" as the protocol name.
;;
;; After the RTPS-VT header, we have the frame type. The frame type determines
;; what kind of information has the dumped packet. RTPS-VT data comes as a
;; series of [parameter identifier, content length, content]. Depending on the
;; type of frame (RTPS or lossInfo), the dissector will expect some parameters
;; or others.
;;
;; If the frame type is RTPS, we will continue parsing transport-layer data.
;; The transport layer contains all information about the source and destination
;; of a packet. This corresponds to data typically found on Network or Transport
;; protocols. However, because RTI Connext DDS generates the capture file
;; directly at application-level, this information is added at the moment of
;; writing the capture file.
;; After the transport-layer information, we will call the advanced dissector.
;;
;; If the frame type is lossInfo, the dissector will generate a packet
;; indicating that there were missing frames (and the range of sequence
;; numbers).
;;

;; jerboa-ethereal/dissectors/rtps-virtual-transport.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rtps_virtual_transport.c

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
(def (dissect-rtps-virtual-transport buffer)
  "Real-Time Publish-Subscribe Virtual Transport"
  (try
    (let* (
           (version-major (unwrap (read-u8 buffer 0)))
           (version-minor (unwrap (read-u8 buffer 0)))
           (content-kind (unwrap (read-u8 buffer 2)))
           (class (unwrap (slice buffer 11 1)))
           (monitoring-guid (unwrap (slice buffer 15 1)))
           (monitoring-seqNr (unwrap (read-u64be buffer 19)))
           (source-port (unwrap (read-u32be buffer 27)))
           (destination-port (unwrap (read-u32be buffer 35)))
           (param-id (unwrap (read-u16be buffer 35)))
           (param-length (unwrap (read-u16be buffer 37)))
           (version (unwrap (read-u16be buffer 39)))
           )

      (ok (list
        (cons 'version-major (list (cons 'raw version-major) (cons 'formatted (number->string version-major))))
        (cons 'version-minor (list (cons 'raw version-minor) (cons 'formatted (number->string version-minor))))
        (cons 'content-kind (list (cons 'raw content-kind) (cons 'formatted (number->string content-kind))))
        (cons 'class (list (cons 'raw class) (cons 'formatted (utf8->string class))))
        (cons 'monitoring-guid (list (cons 'raw monitoring-guid) (cons 'formatted (fmt-bytes monitoring-guid))))
        (cons 'monitoring-seqNr (list (cons 'raw monitoring-seqNr) (cons 'formatted (number->string monitoring-seqNr))))
        (cons 'source-port (list (cons 'raw source-port) (cons 'formatted (number->string source-port))))
        (cons 'destination-port (list (cons 'raw destination-port) (cons 'formatted (number->string destination-port))))
        (cons 'param-id (list (cons 'raw param-id) (cons 'formatted (number->string param-id))))
        (cons 'param-length (list (cons 'raw param-length) (cons 'formatted (number->string param-length))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (fmt-hex version))))
        )))

    (catch (e)
      (err (str "RTPS-VIRTUAL-TRANSPORT parse error: " e)))))

;; dissect-rtps-virtual-transport: parse RTPS-VIRTUAL-TRANSPORT from bytevector
;; Returns (ok fields-alist) or (err message)