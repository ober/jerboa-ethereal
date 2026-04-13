;; packet-selfm.c
;; Routines for Schweitzer Engineering Laboratories (SEL) Protocols Dissection
;; By Chris Bontje (cbontje[AT]gmail.com
;; Copyright 2012-2021,
;;
;; ***********************************************************************************************
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; ***********************************************************************************************
;; Schweitzer Engineering Labs ("SEL") manufactures and sells digital protective relay equipment
;; for use in industrial high-voltage installations.  SEL Protocol evolved over time as a
;; (semi)proprietary method for auto-configuration of connected SEL devices for retrieval of
;; analog and digital status data.  The protocol itself supports embedded binary messages
;; (which are what this dissector looks for) slip-streamed in the data stream with normal
;; ASCII text data.  A combination of both are used for full auto-configuration of devices,
;; but a wealth of information can be extracted from the binary messages alone.
;;
;; 'SEL Protocol' encompasses several message types, including
;; - Fast Meter
;; - Fast Operate
;; - Fast SER
;; - Fast Message
;;
;; Documentation on Fast Meter and Fast Message standards available from www.selinc.com in
;; SEL Application Guides AG95-10_20091109.pdf and AG_200214.pdf
;; ***********************************************************************************************
;; Dissector Notes:
;;
;; 1) All SEL Protocol messages over TCP are normally tunneled via a Telnet connection.  As Telnet
;; has special handling for the 0xFF character ("IAC"), normally a pair of 0xFF's are inserted
;; to represent an actual payload byte of 0xFF.  A function from the packet-telnet.c dissector has
;; been borrowed to automatically pre-process any Ethernet-based packet and remove these 'extra'
;; 0xFF bytes.  Wireshark Notes on Telnet 0xFF doubling are discussed here:
;; https://lists.wireshark.org/archives/wireshark-bugs/201204/msg00198.html
;;
;; 2) The auto-configuration process for Fast Meter will exchange several "configuration" messages
;; that describe various data regions (METER, DEMAND, PEAK, etc) that will later have corresponding
;; "data" messages.  This dissector code will currently save and accurately retrieve the 3 sets
;; of these exchanges:
;; 0xA5C1, 0xA5D1, "METER" region
;; 0xA5C2, 0xA5D2, "DEMAND" region
;; 0xA5C3, 0xA5D3, "PEAK" region
;; The configuration messages are stored in structs that are managed using the wmem library and
;; the Wireshark conversation functionality.
;;

;; jerboa-ethereal/dissectors/selfm.ss
;; Auto-generated from wireshark/epan/dissectors/packet-selfm.c

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
(def (dissect-selfm buffer)
  "SEL Protocol"
  (try
    (let* (
           (relaydef-numproto (unwrap (read-u8 buffer 26)))
           (relaydef-numfm (unwrap (read-u8 buffer 26)))
           (relaydef-numflags (unwrap (read-u8 buffer 26)))
           (relaydef-fmcfg-cmd (unwrap (read-u16be buffer 30)))
           (relaydef-fmdata-cmd (unwrap (read-u16be buffer 30)))
           (relaydef-statbit (unwrap (read-u16be buffer 34)))
           (relaydef-statbit-cmd (unwrap (slice buffer 34 6)))
           (fmconfig-len (unwrap (read-u8 buffer 46)))
           (fmconfig-numflags (unwrap (read-u8 buffer 46)))
           (fmconfig-num-sf (unwrap (read-u8 buffer 46)))
           (fmconfig-num-ai (unwrap (read-u8 buffer 46)))
           (fmconfig-num-samp (unwrap (read-u8 buffer 46)))
           (fmconfig-num-dig (unwrap (read-u8 buffer 46)))
           (fmconfig-num-calc (unwrap (read-u8 buffer 46)))
           (fmconfig-ofs-ai (unwrap (read-u16be buffer 54)))
           (fmconfig-ofs-ts (unwrap (read-u16be buffer 54)))
           (fmconfig-ofs-dig (unwrap (read-u16be buffer 54)))
           (fmconfig-ai-channel (unwrap (slice buffer 60 6)))
           (fmconfig-ai-sf-ofs (unwrap (read-u16be buffer 60)))
           (fmconfig-cblk-deskew-ofs (unwrap (read-u16be buffer 70)))
           (fmconfig-cblk-rs-ofs (unwrap (read-u16be buffer 70)))
           (fmconfig-cblk-xs-ofs (unwrap (read-u16be buffer 70)))
           (fmconfig-cblk-ia-idx (unwrap (read-u8 buffer 70)))
           (fmconfig-cblk-ib-idx (unwrap (read-u8 buffer 70)))
           (fmconfig-cblk-ic-idx (unwrap (read-u8 buffer 70)))
           (fmconfig-cblk-va-idx (unwrap (read-u8 buffer 70)))
           (fmconfig-cblk-vb-idx (unwrap (read-u8 buffer 70)))
           (fmconfig-cblk-vc-idx (unwrap (read-u8 buffer 70)))
           (fmconfig-ai-sf-float (unwrap (read-u32be buffer 84)))
           (fmdata-len (unwrap (read-u8 buffer 90)))
           (fmdata-flagbyte (unwrap (read-u8 buffer 91)))
           (fmdata-ai-sf-fp (unwrap (read-u32be buffer 92)))
           (fmdata-ai-value16 (unwrap (read-u32be buffer 92)))
           (fmdata-ai-scale-factor (unwrap (read-u32be buffer 92)))
           (fmdata-ai-value-float (unwrap (read-u32be buffer 92)))
           (fmdata-ai-value-double (unwrap (read-u64be buffer 92)))
           (fmdata-dig-b0 (unwrap (read-u8 buffer 100)))
           (fmdata-dig-b1 (unwrap (read-u8 buffer 100)))
           (fmdata-dig-b2 (unwrap (read-u8 buffer 100)))
           (fmdata-dig-b3 (unwrap (read-u8 buffer 100)))
           (fmdata-dig-b4 (unwrap (read-u8 buffer 100)))
           (fmdata-dig-b5 (unwrap (read-u8 buffer 100)))
           (fmdata-dig-b6 (unwrap (read-u8 buffer 100)))
           (fmdata-dig-b7 (unwrap (read-u8 buffer 100)))
           (foconfig-len (unwrap (read-u8 buffer 103)))
           (foconfig-num-brkr (unwrap (read-u8 buffer 103)))
           (foconfig-num-rb (unwrap (read-u16be buffer 103)))
           (foconfig-reserved (unwrap (read-u8 buffer 103)))
           (padbyte (unwrap (read-u8 buffer 116)))
           (alt-foconfig-len (unwrap (read-u8 buffer 118)))
           (alt-foconfig-num-ports (unwrap (read-u8 buffer 118)))
           (alt-foconfig-num-brkr (unwrap (read-u8 buffer 118)))
           (alt-foconfig-num-rb (unwrap (read-u8 buffer 118)))
           (fastop-len (unwrap (read-u8 buffer 118)))
           (fastop-valid (unwrap (read-u8 buffer 120)))
           (alt-fastop-len (unwrap (read-u8 buffer 122)))
           (alt-fastop-code (unwrap (read-u16be buffer 123)))
           (alt-fastop-valid (unwrap (read-u16be buffer 125)))
           (fastmsg-len (unwrap (read-u8 buffer 133)))
           (fastmsg-routing-addr (unwrap (slice buffer 133 5)))
           (fastmsg-status (unwrap (read-u8 buffer 139)))
           (fastmsg-seq (unwrap (read-u8 buffer 141)))
           (fastmsg-seq-fir (extract-bits fastmsg-seq 0x0 0))
           (fastmsg-seq-fin (extract-bits fastmsg-seq 0x0 0))
           (fastmsg-seq-cnt (extract-bits fastmsg-seq 0x0 0))
           (fastmsg-resp-num (unwrap (read-u8 buffer 142)))
           (fastmsg-uns-en-fc-data (unwrap (slice buffer 143 3)))
           (fastmsg-uns-dis-fc-data (unwrap (slice buffer 147 1)))
           (fastmsg-soe-req-orig (unwrap (slice buffer 157 4)))
           (fastmsg-unsresp-orig (unwrap (slice buffer 161 4)))
           (fastmsg-unsresp-doy (unwrap (read-u16be buffer 165)))
           (fastmsg-unsresp-year (unwrap (read-u16be buffer 165)))
           (fastmsg-unsresp-todms (unwrap (read-u32be buffer 165)))
           (fastmsg-unsresp-elmt-idx (unwrap (read-u8 buffer 173)))
           (fastmsg-unsresp-elmt-ts-ofs (unwrap (read-u32be buffer 173)))
           (fastmsg-unsresp-elmt-ts-ofs-decoded (unwrap (read-u24be buffer 173)))
           (fastmsg-unsresp-eor (unwrap (slice buffer 177 4)))
           (fastmsg-unsresp-elmt-statword (unwrap (read-u32be buffer 181)))
           (fastmsg-unswrite-addr2 (unwrap (read-u16be buffer 185)))
           (fastmsg-unswrite-num-reg (unwrap (read-u16be buffer 185)))
           (fastmsg-unswrite-reg-val (unwrap (read-u16be buffer 191)))
           (fastmsg-def-route-sup (unwrap (read-u8 buffer 201)))
           (fastmsg-def-rx-stat (unwrap (read-u8 buffer 202)))
           (fastmsg-def-tx-stat (unwrap (read-u8 buffer 202)))
           (fastmsg-def-rx-maxfr (unwrap (read-u8 buffer 204)))
           (fastmsg-def-tx-maxfr (unwrap (read-u8 buffer 204)))
           (fastmsg-def-rx-num-fc (unwrap (read-u8 buffer 212)))
           (fastmsg-def-tx-num-fc (unwrap (read-u8 buffer 215)))
           (fastmsg-soe-resp-numblks (unwrap (read-u16be buffer 218)))
           (fastmsg-soe-resp-orig (unwrap (slice buffer 220 4)))
           (fastmsg-soe-resp-numbits (unwrap (read-u8 buffer 220)))
           (fastmsg-soe-resp-pad (unwrap (read-u8 buffer 220)))
           (fastmsg-soe-resp-doy (unwrap (read-u16be buffer 220)))
           (fastmsg-soe-resp-year (unwrap (read-u16be buffer 220)))
           (fastmsg-soe-resp-tod (unwrap (read-u32be buffer 220)))
           (fastmsg-soe-resp-data (unwrap (read-u16be buffer 234)))
           (fid (unwrap (slice buffer 236 50)))
           (rid (unwrap (slice buffer 236 40)))
           (fastmsg-devdesc-num-region (unwrap (read-u16be buffer 326)))
           (fastmsg-devdesc-num-ctrl (unwrap (read-u16be buffer 328)))
           (fastmsg-data-region-name (unwrap (slice buffer 330 10)))
           (fastmsg-numwords (unwrap (read-u16be buffer 344)))
           (fastmsg-flags (unwrap (read-u16be buffer 346)))
           (fastmsg-baseaddr (unwrap (read-u32be buffer 356)))
           (fastmsg-datafmt-resp-numitem (unwrap (read-u16be buffer 360)))
           (fastmsg-dataitem-qty (unwrap (read-u16be buffer 362)))
           (fastmsg-crc16 (unwrap (read-u16be buffer 376)))
           (relaydef-len (unwrap (read-u8 buffer 378)))
           )

      (ok (list
        (cons 'relaydef-numproto (list (cons 'raw relaydef-numproto) (cons 'formatted (number->string relaydef-numproto))))
        (cons 'relaydef-numfm (list (cons 'raw relaydef-numfm) (cons 'formatted (number->string relaydef-numfm))))
        (cons 'relaydef-numflags (list (cons 'raw relaydef-numflags) (cons 'formatted (number->string relaydef-numflags))))
        (cons 'relaydef-fmcfg-cmd (list (cons 'raw relaydef-fmcfg-cmd) (cons 'formatted (fmt-hex relaydef-fmcfg-cmd))))
        (cons 'relaydef-fmdata-cmd (list (cons 'raw relaydef-fmdata-cmd) (cons 'formatted (fmt-hex relaydef-fmdata-cmd))))
        (cons 'relaydef-statbit (list (cons 'raw relaydef-statbit) (cons 'formatted (fmt-hex relaydef-statbit))))
        (cons 'relaydef-statbit-cmd (list (cons 'raw relaydef-statbit-cmd) (cons 'formatted (fmt-bytes relaydef-statbit-cmd))))
        (cons 'fmconfig-len (list (cons 'raw fmconfig-len) (cons 'formatted (number->string fmconfig-len))))
        (cons 'fmconfig-numflags (list (cons 'raw fmconfig-numflags) (cons 'formatted (number->string fmconfig-numflags))))
        (cons 'fmconfig-num-sf (list (cons 'raw fmconfig-num-sf) (cons 'formatted (number->string fmconfig-num-sf))))
        (cons 'fmconfig-num-ai (list (cons 'raw fmconfig-num-ai) (cons 'formatted (number->string fmconfig-num-ai))))
        (cons 'fmconfig-num-samp (list (cons 'raw fmconfig-num-samp) (cons 'formatted (number->string fmconfig-num-samp))))
        (cons 'fmconfig-num-dig (list (cons 'raw fmconfig-num-dig) (cons 'formatted (number->string fmconfig-num-dig))))
        (cons 'fmconfig-num-calc (list (cons 'raw fmconfig-num-calc) (cons 'formatted (number->string fmconfig-num-calc))))
        (cons 'fmconfig-ofs-ai (list (cons 'raw fmconfig-ofs-ai) (cons 'formatted (number->string fmconfig-ofs-ai))))
        (cons 'fmconfig-ofs-ts (list (cons 'raw fmconfig-ofs-ts) (cons 'formatted (number->string fmconfig-ofs-ts))))
        (cons 'fmconfig-ofs-dig (list (cons 'raw fmconfig-ofs-dig) (cons 'formatted (number->string fmconfig-ofs-dig))))
        (cons 'fmconfig-ai-channel (list (cons 'raw fmconfig-ai-channel) (cons 'formatted (utf8->string fmconfig-ai-channel))))
        (cons 'fmconfig-ai-sf-ofs (list (cons 'raw fmconfig-ai-sf-ofs) (cons 'formatted (number->string fmconfig-ai-sf-ofs))))
        (cons 'fmconfig-cblk-deskew-ofs (list (cons 'raw fmconfig-cblk-deskew-ofs) (cons 'formatted (number->string fmconfig-cblk-deskew-ofs))))
        (cons 'fmconfig-cblk-rs-ofs (list (cons 'raw fmconfig-cblk-rs-ofs) (cons 'formatted (number->string fmconfig-cblk-rs-ofs))))
        (cons 'fmconfig-cblk-xs-ofs (list (cons 'raw fmconfig-cblk-xs-ofs) (cons 'formatted (number->string fmconfig-cblk-xs-ofs))))
        (cons 'fmconfig-cblk-ia-idx (list (cons 'raw fmconfig-cblk-ia-idx) (cons 'formatted (number->string fmconfig-cblk-ia-idx))))
        (cons 'fmconfig-cblk-ib-idx (list (cons 'raw fmconfig-cblk-ib-idx) (cons 'formatted (number->string fmconfig-cblk-ib-idx))))
        (cons 'fmconfig-cblk-ic-idx (list (cons 'raw fmconfig-cblk-ic-idx) (cons 'formatted (number->string fmconfig-cblk-ic-idx))))
        (cons 'fmconfig-cblk-va-idx (list (cons 'raw fmconfig-cblk-va-idx) (cons 'formatted (number->string fmconfig-cblk-va-idx))))
        (cons 'fmconfig-cblk-vb-idx (list (cons 'raw fmconfig-cblk-vb-idx) (cons 'formatted (number->string fmconfig-cblk-vb-idx))))
        (cons 'fmconfig-cblk-vc-idx (list (cons 'raw fmconfig-cblk-vc-idx) (cons 'formatted (number->string fmconfig-cblk-vc-idx))))
        (cons 'fmconfig-ai-sf-float (list (cons 'raw fmconfig-ai-sf-float) (cons 'formatted (number->string fmconfig-ai-sf-float))))
        (cons 'fmdata-len (list (cons 'raw fmdata-len) (cons 'formatted (number->string fmdata-len))))
        (cons 'fmdata-flagbyte (list (cons 'raw fmdata-flagbyte) (cons 'formatted (number->string fmdata-flagbyte))))
        (cons 'fmdata-ai-sf-fp (list (cons 'raw fmdata-ai-sf-fp) (cons 'formatted (number->string fmdata-ai-sf-fp))))
        (cons 'fmdata-ai-value16 (list (cons 'raw fmdata-ai-value16) (cons 'formatted (number->string fmdata-ai-value16))))
        (cons 'fmdata-ai-scale-factor (list (cons 'raw fmdata-ai-scale-factor) (cons 'formatted (number->string fmdata-ai-scale-factor))))
        (cons 'fmdata-ai-value-float (list (cons 'raw fmdata-ai-value-float) (cons 'formatted (number->string fmdata-ai-value-float))))
        (cons 'fmdata-ai-value-double (list (cons 'raw fmdata-ai-value-double) (cons 'formatted (number->string fmdata-ai-value-double))))
        (cons 'fmdata-dig-b0 (list (cons 'raw fmdata-dig-b0) (cons 'formatted (number->string fmdata-dig-b0))))
        (cons 'fmdata-dig-b1 (list (cons 'raw fmdata-dig-b1) (cons 'formatted (number->string fmdata-dig-b1))))
        (cons 'fmdata-dig-b2 (list (cons 'raw fmdata-dig-b2) (cons 'formatted (number->string fmdata-dig-b2))))
        (cons 'fmdata-dig-b3 (list (cons 'raw fmdata-dig-b3) (cons 'formatted (number->string fmdata-dig-b3))))
        (cons 'fmdata-dig-b4 (list (cons 'raw fmdata-dig-b4) (cons 'formatted (number->string fmdata-dig-b4))))
        (cons 'fmdata-dig-b5 (list (cons 'raw fmdata-dig-b5) (cons 'formatted (number->string fmdata-dig-b5))))
        (cons 'fmdata-dig-b6 (list (cons 'raw fmdata-dig-b6) (cons 'formatted (number->string fmdata-dig-b6))))
        (cons 'fmdata-dig-b7 (list (cons 'raw fmdata-dig-b7) (cons 'formatted (number->string fmdata-dig-b7))))
        (cons 'foconfig-len (list (cons 'raw foconfig-len) (cons 'formatted (number->string foconfig-len))))
        (cons 'foconfig-num-brkr (list (cons 'raw foconfig-num-brkr) (cons 'formatted (number->string foconfig-num-brkr))))
        (cons 'foconfig-num-rb (list (cons 'raw foconfig-num-rb) (cons 'formatted (number->string foconfig-num-rb))))
        (cons 'foconfig-reserved (list (cons 'raw foconfig-reserved) (cons 'formatted (number->string foconfig-reserved))))
        (cons 'padbyte (list (cons 'raw padbyte) (cons 'formatted (fmt-hex padbyte))))
        (cons 'alt-foconfig-len (list (cons 'raw alt-foconfig-len) (cons 'formatted (number->string alt-foconfig-len))))
        (cons 'alt-foconfig-num-ports (list (cons 'raw alt-foconfig-num-ports) (cons 'formatted (number->string alt-foconfig-num-ports))))
        (cons 'alt-foconfig-num-brkr (list (cons 'raw alt-foconfig-num-brkr) (cons 'formatted (number->string alt-foconfig-num-brkr))))
        (cons 'alt-foconfig-num-rb (list (cons 'raw alt-foconfig-num-rb) (cons 'formatted (number->string alt-foconfig-num-rb))))
        (cons 'fastop-len (list (cons 'raw fastop-len) (cons 'formatted (number->string fastop-len))))
        (cons 'fastop-valid (list (cons 'raw fastop-valid) (cons 'formatted (fmt-hex fastop-valid))))
        (cons 'alt-fastop-len (list (cons 'raw alt-fastop-len) (cons 'formatted (number->string alt-fastop-len))))
        (cons 'alt-fastop-code (list (cons 'raw alt-fastop-code) (cons 'formatted (fmt-hex alt-fastop-code))))
        (cons 'alt-fastop-valid (list (cons 'raw alt-fastop-valid) (cons 'formatted (fmt-hex alt-fastop-valid))))
        (cons 'fastmsg-len (list (cons 'raw fastmsg-len) (cons 'formatted (number->string fastmsg-len))))
        (cons 'fastmsg-routing-addr (list (cons 'raw fastmsg-routing-addr) (cons 'formatted (fmt-bytes fastmsg-routing-addr))))
        (cons 'fastmsg-status (list (cons 'raw fastmsg-status) (cons 'formatted (number->string fastmsg-status))))
        (cons 'fastmsg-seq (list (cons 'raw fastmsg-seq) (cons 'formatted (fmt-hex fastmsg-seq))))
        (cons 'fastmsg-seq-fir (list (cons 'raw fastmsg-seq-fir) (cons 'formatted (if (= fastmsg-seq-fir 0) "Not set" "Set"))))
        (cons 'fastmsg-seq-fin (list (cons 'raw fastmsg-seq-fin) (cons 'formatted (if (= fastmsg-seq-fin 0) "Not set" "Set"))))
        (cons 'fastmsg-seq-cnt (list (cons 'raw fastmsg-seq-cnt) (cons 'formatted (if (= fastmsg-seq-cnt 0) "Not set" "Set"))))
        (cons 'fastmsg-resp-num (list (cons 'raw fastmsg-resp-num) (cons 'formatted (number->string fastmsg-resp-num))))
        (cons 'fastmsg-uns-en-fc-data (list (cons 'raw fastmsg-uns-en-fc-data) (cons 'formatted (fmt-bytes fastmsg-uns-en-fc-data))))
        (cons 'fastmsg-uns-dis-fc-data (list (cons 'raw fastmsg-uns-dis-fc-data) (cons 'formatted (fmt-bytes fastmsg-uns-dis-fc-data))))
        (cons 'fastmsg-soe-req-orig (list (cons 'raw fastmsg-soe-req-orig) (cons 'formatted (fmt-bytes fastmsg-soe-req-orig))))
        (cons 'fastmsg-unsresp-orig (list (cons 'raw fastmsg-unsresp-orig) (cons 'formatted (fmt-bytes fastmsg-unsresp-orig))))
        (cons 'fastmsg-unsresp-doy (list (cons 'raw fastmsg-unsresp-doy) (cons 'formatted (number->string fastmsg-unsresp-doy))))
        (cons 'fastmsg-unsresp-year (list (cons 'raw fastmsg-unsresp-year) (cons 'formatted (number->string fastmsg-unsresp-year))))
        (cons 'fastmsg-unsresp-todms (list (cons 'raw fastmsg-unsresp-todms) (cons 'formatted (number->string fastmsg-unsresp-todms))))
        (cons 'fastmsg-unsresp-elmt-idx (list (cons 'raw fastmsg-unsresp-elmt-idx) (cons 'formatted (number->string fastmsg-unsresp-elmt-idx))))
        (cons 'fastmsg-unsresp-elmt-ts-ofs (list (cons 'raw fastmsg-unsresp-elmt-ts-ofs) (cons 'formatted (number->string fastmsg-unsresp-elmt-ts-ofs))))
        (cons 'fastmsg-unsresp-elmt-ts-ofs-decoded (list (cons 'raw fastmsg-unsresp-elmt-ts-ofs-decoded) (cons 'formatted (number->string fastmsg-unsresp-elmt-ts-ofs-decoded))))
        (cons 'fastmsg-unsresp-eor (list (cons 'raw fastmsg-unsresp-eor) (cons 'formatted (fmt-bytes fastmsg-unsresp-eor))))
        (cons 'fastmsg-unsresp-elmt-statword (list (cons 'raw fastmsg-unsresp-elmt-statword) (cons 'formatted (fmt-hex fastmsg-unsresp-elmt-statword))))
        (cons 'fastmsg-unswrite-addr2 (list (cons 'raw fastmsg-unswrite-addr2) (cons 'formatted (fmt-hex fastmsg-unswrite-addr2))))
        (cons 'fastmsg-unswrite-num-reg (list (cons 'raw fastmsg-unswrite-num-reg) (cons 'formatted (number->string fastmsg-unswrite-num-reg))))
        (cons 'fastmsg-unswrite-reg-val (list (cons 'raw fastmsg-unswrite-reg-val) (cons 'formatted (number->string fastmsg-unswrite-reg-val))))
        (cons 'fastmsg-def-route-sup (list (cons 'raw fastmsg-def-route-sup) (cons 'formatted (number->string fastmsg-def-route-sup))))
        (cons 'fastmsg-def-rx-stat (list (cons 'raw fastmsg-def-rx-stat) (cons 'formatted (number->string fastmsg-def-rx-stat))))
        (cons 'fastmsg-def-tx-stat (list (cons 'raw fastmsg-def-tx-stat) (cons 'formatted (number->string fastmsg-def-tx-stat))))
        (cons 'fastmsg-def-rx-maxfr (list (cons 'raw fastmsg-def-rx-maxfr) (cons 'formatted (number->string fastmsg-def-rx-maxfr))))
        (cons 'fastmsg-def-tx-maxfr (list (cons 'raw fastmsg-def-tx-maxfr) (cons 'formatted (number->string fastmsg-def-tx-maxfr))))
        (cons 'fastmsg-def-rx-num-fc (list (cons 'raw fastmsg-def-rx-num-fc) (cons 'formatted (number->string fastmsg-def-rx-num-fc))))
        (cons 'fastmsg-def-tx-num-fc (list (cons 'raw fastmsg-def-tx-num-fc) (cons 'formatted (number->string fastmsg-def-tx-num-fc))))
        (cons 'fastmsg-soe-resp-numblks (list (cons 'raw fastmsg-soe-resp-numblks) (cons 'formatted (number->string fastmsg-soe-resp-numblks))))
        (cons 'fastmsg-soe-resp-orig (list (cons 'raw fastmsg-soe-resp-orig) (cons 'formatted (fmt-bytes fastmsg-soe-resp-orig))))
        (cons 'fastmsg-soe-resp-numbits (list (cons 'raw fastmsg-soe-resp-numbits) (cons 'formatted (number->string fastmsg-soe-resp-numbits))))
        (cons 'fastmsg-soe-resp-pad (list (cons 'raw fastmsg-soe-resp-pad) (cons 'formatted (number->string fastmsg-soe-resp-pad))))
        (cons 'fastmsg-soe-resp-doy (list (cons 'raw fastmsg-soe-resp-doy) (cons 'formatted (number->string fastmsg-soe-resp-doy))))
        (cons 'fastmsg-soe-resp-year (list (cons 'raw fastmsg-soe-resp-year) (cons 'formatted (number->string fastmsg-soe-resp-year))))
        (cons 'fastmsg-soe-resp-tod (list (cons 'raw fastmsg-soe-resp-tod) (cons 'formatted (number->string fastmsg-soe-resp-tod))))
        (cons 'fastmsg-soe-resp-data (list (cons 'raw fastmsg-soe-resp-data) (cons 'formatted (fmt-hex fastmsg-soe-resp-data))))
        (cons 'fid (list (cons 'raw fid) (cons 'formatted (utf8->string fid))))
        (cons 'rid (list (cons 'raw rid) (cons 'formatted (utf8->string rid))))
        (cons 'fastmsg-devdesc-num-region (list (cons 'raw fastmsg-devdesc-num-region) (cons 'formatted (number->string fastmsg-devdesc-num-region))))
        (cons 'fastmsg-devdesc-num-ctrl (list (cons 'raw fastmsg-devdesc-num-ctrl) (cons 'formatted (number->string fastmsg-devdesc-num-ctrl))))
        (cons 'fastmsg-data-region-name (list (cons 'raw fastmsg-data-region-name) (cons 'formatted (utf8->string fastmsg-data-region-name))))
        (cons 'fastmsg-numwords (list (cons 'raw fastmsg-numwords) (cons 'formatted (number->string fastmsg-numwords))))
        (cons 'fastmsg-flags (list (cons 'raw fastmsg-flags) (cons 'formatted (fmt-hex fastmsg-flags))))
        (cons 'fastmsg-baseaddr (list (cons 'raw fastmsg-baseaddr) (cons 'formatted (fmt-hex fastmsg-baseaddr))))
        (cons 'fastmsg-datafmt-resp-numitem (list (cons 'raw fastmsg-datafmt-resp-numitem) (cons 'formatted (number->string fastmsg-datafmt-resp-numitem))))
        (cons 'fastmsg-dataitem-qty (list (cons 'raw fastmsg-dataitem-qty) (cons 'formatted (number->string fastmsg-dataitem-qty))))
        (cons 'fastmsg-crc16 (list (cons 'raw fastmsg-crc16) (cons 'formatted (fmt-hex fastmsg-crc16))))
        (cons 'relaydef-len (list (cons 'raw relaydef-len) (cons 'formatted (number->string relaydef-len))))
        )))

    (catch (e)
      (err (str "SELFM parse error: " e)))))

;; dissect-selfm: parse SELFM from bytevector
;; Returns (ok fields-alist) or (err message)