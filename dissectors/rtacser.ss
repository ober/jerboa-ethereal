;; packet-rtacser.c
;; Routines for Schweitzer Engineering Laboratories "Real-Time Automation Controller" (RTAC) Serial Line Dissection
;; By Chris Bontje (cbontje[AT]gmail.com)
;; Copyright May 2013
;;
;; ***********************************************************************************************
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; ***********************************************************************************************
;; Dissector Notes:
;;
;; The RTAC product family (SEL-3530, SEL-2241, SEL-3505) is a Linux-based Automation Controller
;; product that is capable of interfacing with SEL and 3rd-party equipment using a variety of
;; standard industrial protocols such as SEL FM, DNP3, Modbus, C37.118, Telegyr 8979 and others.
;; Each protocol instance (master/client or slave/server) is configured to utilize either Ethernet
;; or EIA-232/485 serial connectivity with protocol variations for each medium taken into account.
;;
;; The configuration software for the RTAC platform is named AcSELerator RTAC (SEL-5033) and
;; is used to set up all communications and user logic for the controller as well as provide
;; downloading and online debugging facilities.  One particularly useful aspect of the online
;; debugging capabilities is a robust Communication Monitor tool that can show raw data streams
;; from either serial or Ethernet interfaces.  Many similar products have this same capability
;; but the RTAC software goes a step beyond by providing a "save-as" function to save all captured
;; data into pcap format for further analysis in Wireshark.
;;
;; All Ethernet-style capture files will have a packets with a "Linux Cooked Capture" header
;; including the "source" MAC address of the device responsible for the generation of the message
;; and the TCP/IP header(s) maintained from the original conversation.  The application data from the
;; message will follow as per a standard Wireshark packet.
;;
;; Serial-based pcap capture files were originally stored using "User 0" DLT type 147 to specify a
;; user-defined dissector for pcap data but this format was later modified to specify a custom DLT type
;; known as LINKTYPE_RTAC_SERIAL (DLT 250). The pcap file data portion contains a standard 12-byte serial
;; header followed by the application payload data from actual rx/tx activity on the line.  Some useful
;; information can be retrieved from the 12-byte header information, such as conversation time-stamps,
;; UART function and EIA-232 serial control line states at the time of the message.
;;
;; This dissector will automatically be used for any newer-style DLT 250 files, and the payload protocol
;; can be configured via built-in preferences to use whatever standardized industrial protocol is present
;; on the line for attempted dissection (selfm, mbrtu, dnp3.udp, synphasor).  Older pcap files of DLT type 147
;; can be used by setting the DLT_USER preferences configuration of User 0 (DLT=147) with a 'Header Size'
;; of '12' and a 'Header Protocol' of 'rtacser'.  The payload protocol should be set to use the protocol
;; dissector for the data that is present on the line (again, selfm, mbrtu, dnp3.udp or synphasor).

;; jerboa-ethereal/dissectors/rtacser.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rtacser.c

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
(def (dissect-rtacser buffer)
  "RTAC Serial"
  (try
    (let* (
           (ctrl-cts (unwrap (read-u8 buffer 9)))
           (ctrl-dcd (unwrap (read-u8 buffer 9)))
           (ctrl-dsr (unwrap (read-u8 buffer 9)))
           (ctrl-rts (unwrap (read-u8 buffer 9)))
           (ctrl-dtr (unwrap (read-u8 buffer 9)))
           (ctrl-ring (unwrap (read-u8 buffer 9)))
           (ctrl-mbok (unwrap (read-u8 buffer 9)))
           (footer (unwrap (read-u16be buffer 10)))
           )

      (ok (list
        (cons 'ctrl-cts (list (cons 'raw ctrl-cts) (cons 'formatted (number->string ctrl-cts))))
        (cons 'ctrl-dcd (list (cons 'raw ctrl-dcd) (cons 'formatted (number->string ctrl-dcd))))
        (cons 'ctrl-dsr (list (cons 'raw ctrl-dsr) (cons 'formatted (number->string ctrl-dsr))))
        (cons 'ctrl-rts (list (cons 'raw ctrl-rts) (cons 'formatted (number->string ctrl-rts))))
        (cons 'ctrl-dtr (list (cons 'raw ctrl-dtr) (cons 'formatted (number->string ctrl-dtr))))
        (cons 'ctrl-ring (list (cons 'raw ctrl-ring) (cons 'formatted (number->string ctrl-ring))))
        (cons 'ctrl-mbok (list (cons 'raw ctrl-mbok) (cons 'formatted (number->string ctrl-mbok))))
        (cons 'footer (list (cons 'raw footer) (cons 'formatted (fmt-hex footer))))
        )))

    (catch (e)
      (err (str "RTACSER parse error: " e)))))

;; dissect-rtacser: parse RTACSER from bytevector
;; Returns (ok fields-alist) or (err message)