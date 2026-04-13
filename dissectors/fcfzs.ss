;; packet-fcfzs.c
;; Routines for FC Fabric Zone Server
;; Copyright 2001, Dinesh G Dutt <ddutt@andiamo.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/fcfzs.ss
;; Auto-generated from wireshark/epan/dissectors/packet-fcfzs.c

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
(def (dissect-fcfzs buffer)
  "Fibre Channel Fabric Zone Server"
  (try
    (let* (
           (rjtvendor (unwrap (read-u8 buffer 0)))
           (maxres-size (unwrap (read-u16be buffer 0)))
           (mbrid-lun (unwrap (slice buffer 16 8)))
           (zone-state (unwrap (read-u8 buffer 16)))
           (gest-vendor (unwrap (read-u32be buffer 16)))
           (numzonesetattrs (unwrap (read-u32be buffer 16)))
           (zonesetnmlen (unwrap (read-u8 buffer 16)))
           (zonesetname (unwrap (slice buffer 16 1)))
           (zonenmlen (unwrap (read-u8 buffer 16)))
           (zonename (unwrap (slice buffer 16 1)))
           (nummbrentries (unwrap (read-u32be buffer 16)))
           (numzones (unwrap (read-u32be buffer 20)))
           (nummbrs (unwrap (read-u32be buffer 20)))
           (mbrid-uint (unwrap (read-u24be buffer 20)))
           (gzc-flags (unwrap (read-u8 buffer 28)))
           (soft-zone-set-enforced (extract-bits gzc-flags 0x80 7))
           (hard-zone-set-enforced (extract-bits gzc-flags 0x40 6))
           (gzc-vendor (unwrap (read-u32be buffer 28)))
           )

      (ok (list
        (cons 'rjtvendor (list (cons 'raw rjtvendor) (cons 'formatted (fmt-hex rjtvendor))))
        (cons 'maxres-size (list (cons 'raw maxres-size) (cons 'formatted (number->string maxres-size))))
        (cons 'mbrid-lun (list (cons 'raw mbrid-lun) (cons 'formatted (fmt-bytes mbrid-lun))))
        (cons 'zone-state (list (cons 'raw zone-state) (cons 'formatted (fmt-hex zone-state))))
        (cons 'gest-vendor (list (cons 'raw gest-vendor) (cons 'formatted (fmt-hex gest-vendor))))
        (cons 'numzonesetattrs (list (cons 'raw numzonesetattrs) (cons 'formatted (number->string numzonesetattrs))))
        (cons 'zonesetnmlen (list (cons 'raw zonesetnmlen) (cons 'formatted (number->string zonesetnmlen))))
        (cons 'zonesetname (list (cons 'raw zonesetname) (cons 'formatted (utf8->string zonesetname))))
        (cons 'zonenmlen (list (cons 'raw zonenmlen) (cons 'formatted (number->string zonenmlen))))
        (cons 'zonename (list (cons 'raw zonename) (cons 'formatted (utf8->string zonename))))
        (cons 'nummbrentries (list (cons 'raw nummbrentries) (cons 'formatted (number->string nummbrentries))))
        (cons 'numzones (list (cons 'raw numzones) (cons 'formatted (number->string numzones))))
        (cons 'nummbrs (list (cons 'raw nummbrs) (cons 'formatted (number->string nummbrs))))
        (cons 'mbrid-uint (list (cons 'raw mbrid-uint) (cons 'formatted (fmt-hex mbrid-uint))))
        (cons 'gzc-flags (list (cons 'raw gzc-flags) (cons 'formatted (fmt-hex gzc-flags))))
        (cons 'soft-zone-set-enforced (list (cons 'raw soft-zone-set-enforced) (cons 'formatted (if (= soft-zone-set-enforced 0) "Not set" "Set"))))
        (cons 'hard-zone-set-enforced (list (cons 'raw hard-zone-set-enforced) (cons 'formatted (if (= hard-zone-set-enforced 0) "Not set" "Set"))))
        (cons 'gzc-vendor (list (cons 'raw gzc-vendor) (cons 'formatted (fmt-hex gzc-vendor))))
        )))

    (catch (e)
      (err (str "FCFZS parse error: " e)))))

;; dissect-fcfzs: parse FCFZS from bytevector
;; Returns (ok fields-alist) or (err message)