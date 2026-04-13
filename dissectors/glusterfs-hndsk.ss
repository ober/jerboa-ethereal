;; packet-glusterfs_hndsk.c
;; Routines for GlusterFS Handshake dissection
;; Copyright 2012, Niels de Vos <ndevos@redhat.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;;
;; References to source files point in general to the glusterfs sources.
;; There is currently no RFC or other document where the protocol is
;; completely described. The glusterfs sources can be found at:
;; - http://git.gluster.com/?p=glusterfs.git
;; - https://github.com/gluster/glusterfs
;;
;; The coding-style is roughly the same as the one use in the Linux kernel,
;; see http://www.kernel.org/doc/Documentation/CodingStyle.
;;

;; jerboa-ethereal/dissectors/glusterfs-hndsk.ss
;; Auto-generated from wireshark/epan/dissectors/packet-glusterfs_hndsk.c

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
(def (dissect-glusterfs-hndsk buffer)
  "GlusterFS Handshake"
  (try
    (let* (
           (hndsk-flags (unwrap (read-u32be buffer 0)))
           (cbk-ci-flags (unwrap (read-u32be buffer 0)))
           (cbk-upcall-flag-nlink (extract-bits cbk-ci-flags 0x1 0))
           (cbk-upcall-flag-mode (extract-bits cbk-ci-flags 0x2 1))
           (cbk-upcall-flag-own (extract-bits cbk-ci-flags 0x4 2))
           (cbk-upcall-flag-size (extract-bits cbk-ci-flags 0x8 3))
           (cbk-upcall-flag-times (extract-bits cbk-ci-flags 0x10 4))
           (cbk-upcall-flag-atime (extract-bits cbk-ci-flags 0x20 5))
           (cbk-upcall-flag-perm (extract-bits cbk-ci-flags 0x40 6))
           (cbk-upcall-flag-rename (extract-bits cbk-ci-flags 0x80 7))
           (cbk-upcall-flag-forget (extract-bits cbk-ci-flags 0x100 8))
           (cbk-upcall-flag-parent-times (extract-bits cbk-ci-flags 0x200 9))
           (cbk-upcall-flag-xattr (extract-bits cbk-ci-flags 0x400 10))
           (cbk-upcall-flag-xattr-rm (extract-bits cbk-ci-flags 0x800 11))
           )

      (ok (list
        (cons 'hndsk-flags (list (cons 'raw hndsk-flags) (cons 'formatted (fmt-oct hndsk-flags))))
        (cons 'cbk-ci-flags (list (cons 'raw cbk-ci-flags) (cons 'formatted (number->string cbk-ci-flags))))
        (cons 'cbk-upcall-flag-nlink (list (cons 'raw cbk-upcall-flag-nlink) (cons 'formatted (if (= cbk-upcall-flag-nlink 0) "Not set" "Set"))))
        (cons 'cbk-upcall-flag-mode (list (cons 'raw cbk-upcall-flag-mode) (cons 'formatted (if (= cbk-upcall-flag-mode 0) "Not set" "Set"))))
        (cons 'cbk-upcall-flag-own (list (cons 'raw cbk-upcall-flag-own) (cons 'formatted (if (= cbk-upcall-flag-own 0) "Not set" "Set"))))
        (cons 'cbk-upcall-flag-size (list (cons 'raw cbk-upcall-flag-size) (cons 'formatted (if (= cbk-upcall-flag-size 0) "Not set" "Set"))))
        (cons 'cbk-upcall-flag-times (list (cons 'raw cbk-upcall-flag-times) (cons 'formatted (if (= cbk-upcall-flag-times 0) "Not set" "Set"))))
        (cons 'cbk-upcall-flag-atime (list (cons 'raw cbk-upcall-flag-atime) (cons 'formatted (if (= cbk-upcall-flag-atime 0) "Not set" "Set"))))
        (cons 'cbk-upcall-flag-perm (list (cons 'raw cbk-upcall-flag-perm) (cons 'formatted (if (= cbk-upcall-flag-perm 0) "Not set" "Set"))))
        (cons 'cbk-upcall-flag-rename (list (cons 'raw cbk-upcall-flag-rename) (cons 'formatted (if (= cbk-upcall-flag-rename 0) "Not set" "Set"))))
        (cons 'cbk-upcall-flag-forget (list (cons 'raw cbk-upcall-flag-forget) (cons 'formatted (if (= cbk-upcall-flag-forget 0) "Not set" "Set"))))
        (cons 'cbk-upcall-flag-parent-times (list (cons 'raw cbk-upcall-flag-parent-times) (cons 'formatted (if (= cbk-upcall-flag-parent-times 0) "Not set" "Set"))))
        (cons 'cbk-upcall-flag-xattr (list (cons 'raw cbk-upcall-flag-xattr) (cons 'formatted (if (= cbk-upcall-flag-xattr 0) "Not set" "Set"))))
        (cons 'cbk-upcall-flag-xattr-rm (list (cons 'raw cbk-upcall-flag-xattr-rm) (cons 'formatted (if (= cbk-upcall-flag-xattr-rm 0) "Not set" "Set"))))
        )))

    (catch (e)
      (err (str "GLUSTERFS-HNDSK parse error: " e)))))

;; dissect-glusterfs-hndsk: parse GLUSTERFS-HNDSK from bytevector
;; Returns (ok fields-alist) or (err message)