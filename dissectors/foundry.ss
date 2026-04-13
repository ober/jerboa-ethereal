;; packet-foundry.c
;; Routines for the disassembly of Foundry LLC messages (currently
;; Foundry Discovery Protocol - FDP only)
;;
;; Copyright 2012 Joerg Mayer (see AUTHORS file)
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/foundry.ss
;; Auto-generated from wireshark/epan/dissectors/packet-foundry.c

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
(def (dissect-foundry buffer)
  "Foundry Discovery Protocol"
  (try
    (let* (
           (version (unwrap (read-u8 buffer 0)))
           (holdtime (unwrap (read-u8 buffer 1)))
           (tlv-length (unwrap (read-u16be buffer 2)))
           (string (unwrap (slice buffer 4 1)))
           (string-data (unwrap (slice buffer 8 1)))
           (string-text (unwrap (slice buffer 8 1)))
           (net (unwrap (slice buffer 8 1)))
           (net-unknown (unwrap (slice buffer 12 7)))
           (net-iplength (unwrap (read-u16be buffer 19)))
           (net-ip (unwrap (read-u32be buffer 21)))
           (vlanmap (unwrap (slice buffer 25 1)))
           (vlanmap-vlan (unwrap (read-u16be buffer 29)))
           (tag (unwrap (slice buffer 29 1)))
           (tag-native (unwrap (read-u16be buffer 33)))
           (tag-type (unwrap (read-u16be buffer 35)))
           (tag-unknown (unwrap (slice buffer 37 1)))
           (unknown (unwrap (slice buffer 37 1)))
           (unknown-data (unwrap (slice buffer 41 1)))
           )

      (ok (list
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'holdtime (list (cons 'raw holdtime) (cons 'formatted (number->string holdtime))))
        (cons 'tlv-length (list (cons 'raw tlv-length) (cons 'formatted (number->string tlv-length))))
        (cons 'string (list (cons 'raw string) (cons 'formatted (fmt-bytes string))))
        (cons 'string-data (list (cons 'raw string-data) (cons 'formatted (fmt-bytes string-data))))
        (cons 'string-text (list (cons 'raw string-text) (cons 'formatted (utf8->string string-text))))
        (cons 'net (list (cons 'raw net) (cons 'formatted (fmt-bytes net))))
        (cons 'net-unknown (list (cons 'raw net-unknown) (cons 'formatted (fmt-bytes net-unknown))))
        (cons 'net-iplength (list (cons 'raw net-iplength) (cons 'formatted (number->string net-iplength))))
        (cons 'net-ip (list (cons 'raw net-ip) (cons 'formatted (fmt-ipv4 net-ip))))
        (cons 'vlanmap (list (cons 'raw vlanmap) (cons 'formatted (fmt-bytes vlanmap))))
        (cons 'vlanmap-vlan (list (cons 'raw vlanmap-vlan) (cons 'formatted (number->string vlanmap-vlan))))
        (cons 'tag (list (cons 'raw tag) (cons 'formatted (fmt-bytes tag))))
        (cons 'tag-native (list (cons 'raw tag-native) (cons 'formatted (number->string tag-native))))
        (cons 'tag-type (list (cons 'raw tag-type) (cons 'formatted (fmt-hex tag-type))))
        (cons 'tag-unknown (list (cons 'raw tag-unknown) (cons 'formatted (fmt-bytes tag-unknown))))
        (cons 'unknown (list (cons 'raw unknown) (cons 'formatted (fmt-bytes unknown))))
        (cons 'unknown-data (list (cons 'raw unknown-data) (cons 'formatted (fmt-bytes unknown-data))))
        )))

    (catch (e)
      (err (str "FOUNDRY parse error: " e)))))

;; dissect-foundry: parse FOUNDRY from bytevector
;; Returns (ok fields-alist) or (err message)