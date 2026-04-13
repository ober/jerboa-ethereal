;; packet-wmio.c
;; Wireshark's WMIO dissector.
;;
;; Copyright 2024, Hiddencodes Sec <hidd3ncod3s[]gmail.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/wmio.ss
;; Auto-generated from wireshark/epan/dissectors/packet-wmio.c

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
(def (dissect-wmio buffer)
  "WMIO"
  (try
    (let* (
           (class-name-length (unwrap (read-u32be buffer 0)))
           (object-flags (unwrap (read-u8 buffer 4)))
           (object-flags-cim-class (extract-bits object-flags 0x0 0))
           (object-flags-cim-instance (extract-bits object-flags 0x0 0))
           (object-flags-has-decoration (extract-bits object-flags 0x0 0))
           (object-flags-prototype-result-object (extract-bits object-flags 0x0 0))
           (object-flags-key-property-missing (extract-bits object-flags 0x0 0))
           (flavor (unwrap (read-u8 buffer 9)))
           (flavor-propagate-to-instance (extract-bits flavor 0x0 0))
           (flavor-propagate-to-derived-class (extract-bits flavor 0x0 0))
           (flavor-not-overridable (extract-bits flavor 0x0 0))
           (flavor-origin-propagated (extract-bits flavor 0x0 0))
           (flavor-origin-system (extract-bits flavor 0x0 0))
           (flavor-amended (extract-bits flavor 0x0 0))
           (qualifiervalue (unwrap (slice buffer 52 1)))
           (qualifierset-length (unwrap (read-u32be buffer 66)))
           (propertyinforef (unwrap (read-u32be buffer 70)))
           (inherited (unwrap (read-u8 buffer 70)))
           (order (unwrap (read-u16be buffer 74)))
           (valuetableoffset (unwrap (read-u32be buffer 76)))
           (classoforigin (unwrap (read-u32be buffer 80)))
           (propertylookuptable-count (unwrap (read-u32be buffer 92)))
           (class-header-partlength (unwrap (read-u32be buffer 96)))
           (class-header-ndtablevaluetablelength (unwrap (read-u32be buffer 105)))
           (class-derivation-length (unwrap (read-u32be buffer 109)))
           (offset (unwrap (read-u32be buffer 113)))
           (methodflags (unwrap (read-u8 buffer 121)))
           (methodorigin (unwrap (read-u32be buffer 125)))
           (methodqualifiers (unwrap (read-u32be buffer 129)))
           (length (unwrap (read-u32be buffer 141)))
           (methodcount (unwrap (read-u16be buffer 145)))
           (heap-length (unwrap (read-u32be buffer 149)))
           (signature (unwrap (read-u32be buffer 149)))
           (objectencodinglength (unwrap (read-u32be buffer 153)))
           )

      (ok (list
        (cons 'class-name-length (list (cons 'raw class-name-length) (cons 'formatted (number->string class-name-length))))
        (cons 'object-flags (list (cons 'raw object-flags) (cons 'formatted (fmt-hex object-flags))))
        (cons 'object-flags-cim-class (list (cons 'raw object-flags-cim-class) (cons 'formatted (if (= object-flags-cim-class 0) "Not set" "Set"))))
        (cons 'object-flags-cim-instance (list (cons 'raw object-flags-cim-instance) (cons 'formatted (if (= object-flags-cim-instance 0) "Not set" "Set"))))
        (cons 'object-flags-has-decoration (list (cons 'raw object-flags-has-decoration) (cons 'formatted (if (= object-flags-has-decoration 0) "Not set" "Set"))))
        (cons 'object-flags-prototype-result-object (list (cons 'raw object-flags-prototype-result-object) (cons 'formatted (if (= object-flags-prototype-result-object 0) "Not set" "Set"))))
        (cons 'object-flags-key-property-missing (list (cons 'raw object-flags-key-property-missing) (cons 'formatted (if (= object-flags-key-property-missing 0) "Not set" "Set"))))
        (cons 'flavor (list (cons 'raw flavor) (cons 'formatted (fmt-hex flavor))))
        (cons 'flavor-propagate-to-instance (list (cons 'raw flavor-propagate-to-instance) (cons 'formatted (if (= flavor-propagate-to-instance 0) "Not set" "Set"))))
        (cons 'flavor-propagate-to-derived-class (list (cons 'raw flavor-propagate-to-derived-class) (cons 'formatted (if (= flavor-propagate-to-derived-class 0) "Not set" "Set"))))
        (cons 'flavor-not-overridable (list (cons 'raw flavor-not-overridable) (cons 'formatted (if (= flavor-not-overridable 0) "Not set" "Set"))))
        (cons 'flavor-origin-propagated (list (cons 'raw flavor-origin-propagated) (cons 'formatted (if (= flavor-origin-propagated 0) "Not set" "Set"))))
        (cons 'flavor-origin-system (list (cons 'raw flavor-origin-system) (cons 'formatted (if (= flavor-origin-system 0) "Not set" "Set"))))
        (cons 'flavor-amended (list (cons 'raw flavor-amended) (cons 'formatted (if (= flavor-amended 0) "Not set" "Set"))))
        (cons 'qualifiervalue (list (cons 'raw qualifiervalue) (cons 'formatted (utf8->string qualifiervalue))))
        (cons 'qualifierset-length (list (cons 'raw qualifierset-length) (cons 'formatted (number->string qualifierset-length))))
        (cons 'propertyinforef (list (cons 'raw propertyinforef) (cons 'formatted (fmt-hex propertyinforef))))
        (cons 'inherited (list (cons 'raw inherited) (cons 'formatted (number->string inherited))))
        (cons 'order (list (cons 'raw order) (cons 'formatted (number->string order))))
        (cons 'valuetableoffset (list (cons 'raw valuetableoffset) (cons 'formatted (fmt-hex valuetableoffset))))
        (cons 'classoforigin (list (cons 'raw classoforigin) (cons 'formatted (number->string classoforigin))))
        (cons 'propertylookuptable-count (list (cons 'raw propertylookuptable-count) (cons 'formatted (number->string propertylookuptable-count))))
        (cons 'class-header-partlength (list (cons 'raw class-header-partlength) (cons 'formatted (number->string class-header-partlength))))
        (cons 'class-header-ndtablevaluetablelength (list (cons 'raw class-header-ndtablevaluetablelength) (cons 'formatted (number->string class-header-ndtablevaluetablelength))))
        (cons 'class-derivation-length (list (cons 'raw class-derivation-length) (cons 'formatted (number->string class-derivation-length))))
        (cons 'offset (list (cons 'raw offset) (cons 'formatted (fmt-hex offset))))
        (cons 'methodflags (list (cons 'raw methodflags) (cons 'formatted (number->string methodflags))))
        (cons 'methodorigin (list (cons 'raw methodorigin) (cons 'formatted (number->string methodorigin))))
        (cons 'methodqualifiers (list (cons 'raw methodqualifiers) (cons 'formatted (number->string methodqualifiers))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'methodcount (list (cons 'raw methodcount) (cons 'formatted (number->string methodcount))))
        (cons 'heap-length (list (cons 'raw heap-length) (cons 'formatted (number->string heap-length))))
        (cons 'signature (list (cons 'raw signature) (cons 'formatted (fmt-hex signature))))
        (cons 'objectencodinglength (list (cons 'raw objectencodinglength) (cons 'formatted (number->string objectencodinglength))))
        )))

    (catch (e)
      (err (str "WMIO parse error: " e)))))

;; dissect-wmio: parse WMIO from bytevector
;; Returns (ok fields-alist) or (err message)