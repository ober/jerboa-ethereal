;; packet-cemi.c
;; Routines for cEMI (Common External Message Interface) dissection
;; By Jan Kessler <kessler@ise.de>
;; Copyright 2004, Jan Kessler <kessler@ise.de>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/cemi.ss
;; Auto-generated from wireshark/epan/dissectors/packet-cemi.c

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
(def (dissect-cemi buffer)
  "Common External Message Interface"
  (try
    (let* (
           (ox (unwrap (read-u8 buffer 0)))
           (ai-length (unwrap (read-u8 buffer 1)))
           (pid (unwrap (read-u8 buffer 2)))
           (px (unwrap (read-u8 buffer 2)))
           (ne (unwrap (read-u8 buffer 2)))
           (sx (unwrap (read-u16be buffer 2)))
           (aie-type (unwrap (read-u8 buffer 2)))
           (aie-length (unwrap (read-u8 buffer 2)))
           (rep (unwrap (read-u8 buffer 2)))
           (ack (unwrap (read-u8 buffer 2)))
           (ce (unwrap (read-u8 buffer 2)))
           (hc (unwrap (read-u8 buffer 2)))
           (eff (unwrap (read-u8 buffer 2)))
           (sa (unwrap (read-u16be buffer 2)))
           (oi (unwrap (read-u8 buffer 3)))
           (pw (unwrap (read-u8 buffer 4)))
           (me (unwrap (read-u16be buffer 4)))
           (ra (unwrap (read-u8 buffer 4)))
           (wa (unwrap (read-u8 buffer 4)))
           (error (unwrap (read-u8 buffer 4)))
           (da (unwrap (read-u16be buffer 4)))
           (len (unwrap (read-u8 buffer 6)))
           (ext-oi (unwrap (read-u16be buffer 8)))
           (ext-pid (unwrap (read-u16be buffer 8)))
           (memory-address-ext (unwrap (read-u8 buffer 8)))
           (memory-length (unwrap (read-u8 buffer 8)))
           (ext-memory-length (unwrap (read-u8 buffer 11)))
           (ext-memory-address (unwrap (read-u24be buffer 11)))
           (level (unwrap (read-u8 buffer 14)))
           (snp-pid (unwrap (read-u16be buffer 22)))
           (snp-reserved (unwrap (read-u16be buffer 22)))
           (ext-ne (unwrap (read-u8 buffer 22)))
           (ext-sx (unwrap (read-u16be buffer 22)))
           (ext-dt (unwrap (read-u8 buffer 25)))
           (ext-px (unwrap (read-u16be buffer 25)))
           (dpt-major (unwrap (read-u16be buffer 27)))
           (dpt-minor (unwrap (read-u16be buffer 27)))
           (scf-t (unwrap (read-u8 buffer 31)))
           (scf-sbc (unwrap (read-u8 buffer 31)))
           (ad-memory-length (unwrap (read-u8 buffer 51)))
           (memory-address (unwrap (read-u16be buffer 51)))
           (ad-channel (unwrap (read-u8 buffer 53)))
           (adc-count (unwrap (read-u8 buffer 53)))
           (ad-type (unwrap (read-u8 buffer 53)))
           (ad (unwrap (read-u8 buffer 53)))
           (hf-bytes (unwrap (slice buffer 53 1)))
           (num (unwrap (read-u8 buffer 53)))
           )

      (ok (list
        (cons 'ox (list (cons 'raw ox) (cons 'formatted (number->string ox))))
        (cons 'ai-length (list (cons 'raw ai-length) (cons 'formatted (number->string ai-length))))
        (cons 'pid (list (cons 'raw pid) (cons 'formatted (number->string pid))))
        (cons 'px (list (cons 'raw px) (cons 'formatted (number->string px))))
        (cons 'ne (list (cons 'raw ne) (cons 'formatted (number->string ne))))
        (cons 'sx (list (cons 'raw sx) (cons 'formatted (number->string sx))))
        (cons 'aie-type (list (cons 'raw aie-type) (cons 'formatted (fmt-hex aie-type))))
        (cons 'aie-length (list (cons 'raw aie-length) (cons 'formatted (number->string aie-length))))
        (cons 'rep (list (cons 'raw rep) (cons 'formatted (if (= rep 0) "False" "True"))))
        (cons 'ack (list (cons 'raw ack) (cons 'formatted (if (= ack 0) "False" "True"))))
        (cons 'ce (list (cons 'raw ce) (cons 'formatted (if (= ce 0) "False" "True"))))
        (cons 'hc (list (cons 'raw hc) (cons 'formatted (number->string hc))))
        (cons 'eff (list (cons 'raw eff) (cons 'formatted (fmt-hex eff))))
        (cons 'sa (list (cons 'raw sa) (cons 'formatted (fmt-hex sa))))
        (cons 'oi (list (cons 'raw oi) (cons 'formatted (number->string oi))))
        (cons 'pw (list (cons 'raw pw) (cons 'formatted (number->string pw))))
        (cons 'me (list (cons 'raw me) (cons 'formatted (number->string me))))
        (cons 'ra (list (cons 'raw ra) (cons 'formatted (number->string ra))))
        (cons 'wa (list (cons 'raw wa) (cons 'formatted (number->string wa))))
        (cons 'error (list (cons 'raw error) (cons 'formatted (fmt-hex error))))
        (cons 'da (list (cons 'raw da) (cons 'formatted (fmt-hex da))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'ext-oi (list (cons 'raw ext-oi) (cons 'formatted (number->string ext-oi))))
        (cons 'ext-pid (list (cons 'raw ext-pid) (cons 'formatted (number->string ext-pid))))
        (cons 'memory-address-ext (list (cons 'raw memory-address-ext) (cons 'formatted (fmt-hex memory-address-ext))))
        (cons 'memory-length (list (cons 'raw memory-length) (cons 'formatted (number->string memory-length))))
        (cons 'ext-memory-length (list (cons 'raw ext-memory-length) (cons 'formatted (number->string ext-memory-length))))
        (cons 'ext-memory-address (list (cons 'raw ext-memory-address) (cons 'formatted (fmt-hex ext-memory-address))))
        (cons 'level (list (cons 'raw level) (cons 'formatted (number->string level))))
        (cons 'snp-pid (list (cons 'raw snp-pid) (cons 'formatted (number->string snp-pid))))
        (cons 'snp-reserved (list (cons 'raw snp-reserved) (cons 'formatted (number->string snp-reserved))))
        (cons 'ext-ne (list (cons 'raw ext-ne) (cons 'formatted (number->string ext-ne))))
        (cons 'ext-sx (list (cons 'raw ext-sx) (cons 'formatted (number->string ext-sx))))
        (cons 'ext-dt (list (cons 'raw ext-dt) (cons 'formatted (number->string ext-dt))))
        (cons 'ext-px (list (cons 'raw ext-px) (cons 'formatted (number->string ext-px))))
        (cons 'dpt-major (list (cons 'raw dpt-major) (cons 'formatted (number->string dpt-major))))
        (cons 'dpt-minor (list (cons 'raw dpt-minor) (cons 'formatted (number->string dpt-minor))))
        (cons 'scf-t (list (cons 'raw scf-t) (cons 'formatted (number->string scf-t))))
        (cons 'scf-sbc (list (cons 'raw scf-sbc) (cons 'formatted (number->string scf-sbc))))
        (cons 'ad-memory-length (list (cons 'raw ad-memory-length) (cons 'formatted (fmt-hex ad-memory-length))))
        (cons 'memory-address (list (cons 'raw memory-address) (cons 'formatted (fmt-hex memory-address))))
        (cons 'ad-channel (list (cons 'raw ad-channel) (cons 'formatted (fmt-hex ad-channel))))
        (cons 'adc-count (list (cons 'raw adc-count) (cons 'formatted (number->string adc-count))))
        (cons 'ad-type (list (cons 'raw ad-type) (cons 'formatted (fmt-hex ad-type))))
        (cons 'ad (list (cons 'raw ad) (cons 'formatted (fmt-hex ad))))
        (cons 'hf-bytes (list (cons 'raw hf-bytes) (cons 'formatted (fmt-bytes hf-bytes))))
        (cons 'num (list (cons 'raw num) (cons 'formatted (number->string num))))
        )))

    (catch (e)
      (err (str "CEMI parse error: " e)))))

;; dissect-cemi: parse CEMI from bytevector
;; Returns (ok fields-alist) or (err message)