;; packet-synergy.c
;; Routines for synergy dissection
;; Copyright 2005, Vasanth Manickam <vasanthm@gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/synergy.ss
;; Auto-generated from wireshark/epan/dissectors/packet-synergy.c

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
(def (dissect-synergy buffer)
  "Synergy"
  (try
    (let* (
           (packet-len (unwrap (read-u32be buffer 0)))
           (packet-type (unwrap (slice buffer 0 4)))
           (csec (unwrap (read-u8 buffer 0)))
           (dmdn (unwrap (read-u8 buffer 0)))
           (dmup (unwrap (read-u8 buffer 0)))
           (dmwm (unwrap (read-u16be buffer 0)))
           (dsop (unwrap (read-u32be buffer 0)))
           (handshake-majorversion (unwrap (read-u16be buffer 0)))
           (handshake-minorversion (unwrap (read-u16be buffer 0)))
           (handshake-clientname (unwrap (slice buffer 0 1)))
           (cinn-x (unwrap (read-u16be buffer 0)))
           (cinn-y (unwrap (read-u16be buffer 0)))
           (cinn-sequence (unwrap (read-u32be buffer 0)))
           (cinn-modifiermask (unwrap (read-u16be buffer 0)))
           (cclp-clipboardidentifier (unwrap (read-u8 buffer 0)))
           (cclp-sequencenumber (unwrap (read-u32be buffer 0)))
           (dkdn-keyid (unwrap (read-u16be buffer 0)))
           (dkdn-keymodifiermask (unwrap (read-u16be buffer 0)))
           (dkdn-keybutton (unwrap (read-u16be buffer 0)))
           (dkrp-keyid (unwrap (read-u16be buffer 0)))
           (dkrp-keymodifiermask (unwrap (read-u16be buffer 0)))
           (dkrp-numberofrepeats (unwrap (read-u16be buffer 0)))
           (dkrp-keybutton (unwrap (read-u16be buffer 0)))
           (dkup-keyid (unwrap (read-u16be buffer 0)))
           (dkup-keymodifiermask (unwrap (read-u16be buffer 0)))
           (dkup-keybutton (unwrap (read-u16be buffer 0)))
           (dmmv-x (unwrap (read-u16be buffer 0)))
           (dmmv-y (unwrap (read-u16be buffer 0)))
           (dmrm-x (unwrap (read-u16be buffer 0)))
           (dmrm-y (unwrap (read-u16be buffer 0)))
           (dclp-clipboardidentifier (unwrap (read-u8 buffer 0)))
           (dclp-sequencenumber (unwrap (read-u32be buffer 0)))
           (dclp-clipboarddata (unwrap (slice buffer 0 1)))
           (dinf-clp (unwrap (read-u16be buffer 0)))
           (dinf-ctp (unwrap (read-u16be buffer 0)))
           (dinf-wsp (unwrap (read-u16be buffer 0)))
           (dinf-hsp (unwrap (read-u16be buffer 0)))
           (dinf-swz (unwrap (read-u16be buffer 0)))
           (dinf-x (unwrap (read-u16be buffer 0)))
           (dinf-y (unwrap (read-u16be buffer 0)))
           (eicv-majorversion (unwrap (read-u16be buffer 0)))
           (eicv-minorversion (unwrap (read-u16be buffer 0)))
           )

      (ok (list
        (cons 'packet-len (list (cons 'raw packet-len) (cons 'formatted (number->string packet-len))))
        (cons 'packet-type (list (cons 'raw packet-type) (cons 'formatted (utf8->string packet-type))))
        (cons 'csec (list (cons 'raw csec) (cons 'formatted (number->string csec))))
        (cons 'dmdn (list (cons 'raw dmdn) (cons 'formatted (number->string dmdn))))
        (cons 'dmup (list (cons 'raw dmup) (cons 'formatted (number->string dmup))))
        (cons 'dmwm (list (cons 'raw dmwm) (cons 'formatted (number->string dmwm))))
        (cons 'dsop (list (cons 'raw dsop) (cons 'formatted (number->string dsop))))
        (cons 'handshake-majorversion (list (cons 'raw handshake-majorversion) (cons 'formatted (number->string handshake-majorversion))))
        (cons 'handshake-minorversion (list (cons 'raw handshake-minorversion) (cons 'formatted (number->string handshake-minorversion))))
        (cons 'handshake-clientname (list (cons 'raw handshake-clientname) (cons 'formatted (utf8->string handshake-clientname))))
        (cons 'cinn-x (list (cons 'raw cinn-x) (cons 'formatted (number->string cinn-x))))
        (cons 'cinn-y (list (cons 'raw cinn-y) (cons 'formatted (number->string cinn-y))))
        (cons 'cinn-sequence (list (cons 'raw cinn-sequence) (cons 'formatted (number->string cinn-sequence))))
        (cons 'cinn-modifiermask (list (cons 'raw cinn-modifiermask) (cons 'formatted (number->string cinn-modifiermask))))
        (cons 'cclp-clipboardidentifier (list (cons 'raw cclp-clipboardidentifier) (cons 'formatted (number->string cclp-clipboardidentifier))))
        (cons 'cclp-sequencenumber (list (cons 'raw cclp-sequencenumber) (cons 'formatted (number->string cclp-sequencenumber))))
        (cons 'dkdn-keyid (list (cons 'raw dkdn-keyid) (cons 'formatted (number->string dkdn-keyid))))
        (cons 'dkdn-keymodifiermask (list (cons 'raw dkdn-keymodifiermask) (cons 'formatted (number->string dkdn-keymodifiermask))))
        (cons 'dkdn-keybutton (list (cons 'raw dkdn-keybutton) (cons 'formatted (number->string dkdn-keybutton))))
        (cons 'dkrp-keyid (list (cons 'raw dkrp-keyid) (cons 'formatted (number->string dkrp-keyid))))
        (cons 'dkrp-keymodifiermask (list (cons 'raw dkrp-keymodifiermask) (cons 'formatted (number->string dkrp-keymodifiermask))))
        (cons 'dkrp-numberofrepeats (list (cons 'raw dkrp-numberofrepeats) (cons 'formatted (number->string dkrp-numberofrepeats))))
        (cons 'dkrp-keybutton (list (cons 'raw dkrp-keybutton) (cons 'formatted (number->string dkrp-keybutton))))
        (cons 'dkup-keyid (list (cons 'raw dkup-keyid) (cons 'formatted (number->string dkup-keyid))))
        (cons 'dkup-keymodifiermask (list (cons 'raw dkup-keymodifiermask) (cons 'formatted (number->string dkup-keymodifiermask))))
        (cons 'dkup-keybutton (list (cons 'raw dkup-keybutton) (cons 'formatted (number->string dkup-keybutton))))
        (cons 'dmmv-x (list (cons 'raw dmmv-x) (cons 'formatted (number->string dmmv-x))))
        (cons 'dmmv-y (list (cons 'raw dmmv-y) (cons 'formatted (number->string dmmv-y))))
        (cons 'dmrm-x (list (cons 'raw dmrm-x) (cons 'formatted (number->string dmrm-x))))
        (cons 'dmrm-y (list (cons 'raw dmrm-y) (cons 'formatted (number->string dmrm-y))))
        (cons 'dclp-clipboardidentifier (list (cons 'raw dclp-clipboardidentifier) (cons 'formatted (number->string dclp-clipboardidentifier))))
        (cons 'dclp-sequencenumber (list (cons 'raw dclp-sequencenumber) (cons 'formatted (number->string dclp-sequencenumber))))
        (cons 'dclp-clipboarddata (list (cons 'raw dclp-clipboarddata) (cons 'formatted (utf8->string dclp-clipboarddata))))
        (cons 'dinf-clp (list (cons 'raw dinf-clp) (cons 'formatted (number->string dinf-clp))))
        (cons 'dinf-ctp (list (cons 'raw dinf-ctp) (cons 'formatted (number->string dinf-ctp))))
        (cons 'dinf-wsp (list (cons 'raw dinf-wsp) (cons 'formatted (number->string dinf-wsp))))
        (cons 'dinf-hsp (list (cons 'raw dinf-hsp) (cons 'formatted (number->string dinf-hsp))))
        (cons 'dinf-swz (list (cons 'raw dinf-swz) (cons 'formatted (number->string dinf-swz))))
        (cons 'dinf-x (list (cons 'raw dinf-x) (cons 'formatted (number->string dinf-x))))
        (cons 'dinf-y (list (cons 'raw dinf-y) (cons 'formatted (number->string dinf-y))))
        (cons 'eicv-majorversion (list (cons 'raw eicv-majorversion) (cons 'formatted (number->string eicv-majorversion))))
        (cons 'eicv-minorversion (list (cons 'raw eicv-minorversion) (cons 'formatted (number->string eicv-minorversion))))
        )))

    (catch (e)
      (err (str "SYNERGY parse error: " e)))))

;; dissect-synergy: parse SYNERGY from bytevector
;; Returns (ok fields-alist) or (err message)