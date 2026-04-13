;; packet-btlmp.c
;; Routines for the Bluetooth Link Manager Protocol
;;
;; Copyright 2020, Thomas Sailer <t.sailer@alumni.ethz.ch>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/btlmp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-btlmp.c

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
(def (dissect-btlmp buffer)
  "Bluetooth Link Manager Protocol"
  (try
    (let* (
           (namelength (unwrap (read-u8 buffer 2)))
           (namefragment (unwrap (slice buffer 2 1)))
           (rand (unwrap (slice buffer 4 16)))
           (key (unwrap (slice buffer 20 16)))
           (authresp (unwrap (read-u32be buffer 36)))
           (encryptionkeysize (unwrap (read-u8 buffer 40)))
           (futureuse1 (unwrap (read-u8 buffer 58)))
           (versnr (unwrap (read-u8 buffer 58)))
           (compid (unwrap (read-u16be buffer 58)))
           (subversnr (unwrap (read-u16be buffer 60)))
           (nbc (unwrap (read-u8 buffer 64)))
           (scohandle (unwrap (read-u8 buffer 64)))
           (bdaddr (unwrap (slice buffer 66 6)))
           (testscenario (unwrap (read-u8 buffer 74)))
           (testhoppingmode (unwrap (read-u8 buffer 74)))
           (testtxfrequency (unwrap (read-u8 buffer 74)))
           (testrxfrequency (unwrap (read-u8 buffer 74)))
           (testpowercontrolmode (unwrap (read-u8 buffer 74)))
           (testpollperiod (unwrap (read-u8 buffer 74)))
           (testpackettype (unwrap (read-u8 buffer 74)))
           (testdatalength (unwrap (read-u8 buffer 74)))
           (keysizemask (unwrap (read-u16be buffer 74)))
           (encapsulatedlength (unwrap (read-u8 buffer 80)))
           (encapsulateddata (unwrap (slice buffer 80 16)))
           (simplepaircommit (unwrap (slice buffer 96 16)))
           (simplepairnonce (unwrap (slice buffer 112 16)))
           (dhkeyconfirm (unwrap (slice buffer 128 16)))
           (features-page (unwrap (read-u8 buffer 144)))
           (max-supported-page (unwrap (read-u8 buffer 144)))
           (clkadjid (unwrap (read-u8 buffer 154)))
           (escoltaddr (unwrap (read-u8 buffer 156)))
           (escopacketlengthms (unwrap (read-u16be buffer 156)))
           (escopacketlengthsm (unwrap (read-u16be buffer 158)))
           (escohandle (unwrap (read-u8 buffer 160)))
           (maxsniffsubrate (unwrap (read-u8 buffer 164)))
           (sniffsubratinginstant (unwrap (read-u32be buffer 166)))
           (samtype0submap (unwrap (slice buffer 170 14)))
           (samnsm (unwrap (read-u8 buffer 184)))
           (samsubmaps (unwrap (slice buffer 184 12)))
           (samindex (unwrap (read-u8 buffer 196)))
           (samd (unwrap (read-u8 buffer 196)))
           (nameoffset (unwrap (read-u8 buffer 197)))
           )

      (ok (list
        (cons 'namelength (list (cons 'raw namelength) (cons 'formatted (fmt-hex namelength))))
        (cons 'namefragment (list (cons 'raw namefragment) (cons 'formatted (utf8->string namefragment))))
        (cons 'rand (list (cons 'raw rand) (cons 'formatted (fmt-bytes rand))))
        (cons 'key (list (cons 'raw key) (cons 'formatted (fmt-bytes key))))
        (cons 'authresp (list (cons 'raw authresp) (cons 'formatted (fmt-hex authresp))))
        (cons 'encryptionkeysize (list (cons 'raw encryptionkeysize) (cons 'formatted (fmt-hex encryptionkeysize))))
        (cons 'futureuse1 (list (cons 'raw futureuse1) (cons 'formatted (fmt-hex futureuse1))))
        (cons 'versnr (list (cons 'raw versnr) (cons 'formatted (fmt-hex versnr))))
        (cons 'compid (list (cons 'raw compid) (cons 'formatted (fmt-hex compid))))
        (cons 'subversnr (list (cons 'raw subversnr) (cons 'formatted (fmt-hex subversnr))))
        (cons 'nbc (list (cons 'raw nbc) (cons 'formatted (fmt-hex nbc))))
        (cons 'scohandle (list (cons 'raw scohandle) (cons 'formatted (fmt-hex scohandle))))
        (cons 'bdaddr (list (cons 'raw bdaddr) (cons 'formatted (fmt-mac bdaddr))))
        (cons 'testscenario (list (cons 'raw testscenario) (cons 'formatted (fmt-hex testscenario))))
        (cons 'testhoppingmode (list (cons 'raw testhoppingmode) (cons 'formatted (fmt-hex testhoppingmode))))
        (cons 'testtxfrequency (list (cons 'raw testtxfrequency) (cons 'formatted (fmt-hex testtxfrequency))))
        (cons 'testrxfrequency (list (cons 'raw testrxfrequency) (cons 'formatted (fmt-hex testrxfrequency))))
        (cons 'testpowercontrolmode (list (cons 'raw testpowercontrolmode) (cons 'formatted (fmt-hex testpowercontrolmode))))
        (cons 'testpollperiod (list (cons 'raw testpollperiod) (cons 'formatted (fmt-hex testpollperiod))))
        (cons 'testpackettype (list (cons 'raw testpackettype) (cons 'formatted (fmt-hex testpackettype))))
        (cons 'testdatalength (list (cons 'raw testdatalength) (cons 'formatted (fmt-hex testdatalength))))
        (cons 'keysizemask (list (cons 'raw keysizemask) (cons 'formatted (fmt-hex keysizemask))))
        (cons 'encapsulatedlength (list (cons 'raw encapsulatedlength) (cons 'formatted (fmt-hex encapsulatedlength))))
        (cons 'encapsulateddata (list (cons 'raw encapsulateddata) (cons 'formatted (fmt-bytes encapsulateddata))))
        (cons 'simplepaircommit (list (cons 'raw simplepaircommit) (cons 'formatted (fmt-bytes simplepaircommit))))
        (cons 'simplepairnonce (list (cons 'raw simplepairnonce) (cons 'formatted (fmt-bytes simplepairnonce))))
        (cons 'dhkeyconfirm (list (cons 'raw dhkeyconfirm) (cons 'formatted (fmt-bytes dhkeyconfirm))))
        (cons 'features-page (list (cons 'raw features-page) (cons 'formatted (fmt-hex features-page))))
        (cons 'max-supported-page (list (cons 'raw max-supported-page) (cons 'formatted (fmt-hex max-supported-page))))
        (cons 'clkadjid (list (cons 'raw clkadjid) (cons 'formatted (fmt-hex clkadjid))))
        (cons 'escoltaddr (list (cons 'raw escoltaddr) (cons 'formatted (fmt-hex escoltaddr))))
        (cons 'escopacketlengthms (list (cons 'raw escopacketlengthms) (cons 'formatted (fmt-hex escopacketlengthms))))
        (cons 'escopacketlengthsm (list (cons 'raw escopacketlengthsm) (cons 'formatted (fmt-hex escopacketlengthsm))))
        (cons 'escohandle (list (cons 'raw escohandle) (cons 'formatted (fmt-hex escohandle))))
        (cons 'maxsniffsubrate (list (cons 'raw maxsniffsubrate) (cons 'formatted (fmt-hex maxsniffsubrate))))
        (cons 'sniffsubratinginstant (list (cons 'raw sniffsubratinginstant) (cons 'formatted (fmt-hex sniffsubratinginstant))))
        (cons 'samtype0submap (list (cons 'raw samtype0submap) (cons 'formatted (fmt-bytes samtype0submap))))
        (cons 'samnsm (list (cons 'raw samnsm) (cons 'formatted (fmt-hex samnsm))))
        (cons 'samsubmaps (list (cons 'raw samsubmaps) (cons 'formatted (fmt-bytes samsubmaps))))
        (cons 'samindex (list (cons 'raw samindex) (cons 'formatted (fmt-hex samindex))))
        (cons 'samd (list (cons 'raw samd) (cons 'formatted (fmt-hex samd))))
        (cons 'nameoffset (list (cons 'raw nameoffset) (cons 'formatted (fmt-hex nameoffset))))
        )))

    (catch (e)
      (err (str "BTLMP parse error: " e)))))

;; dissect-btlmp: parse BTLMP from bytevector
;; Returns (ok fields-alist) or (err message)