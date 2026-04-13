;; packet-mount.c
;; Routines for mount dissection
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-smb.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/mount.ss
;; Auto-generated from wireshark/epan/dissectors/packet-mount.c
;; RFC 1813

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
(def (dissect-mount buffer)
  "Mount Service"
  (try
    (let* (
           (pathconf-max-input (unwrap (read-u16be buffer 8)))
           (pathconf-name-max (unwrap (read-u16be buffer 12)))
           (pathconf-path-max (unwrap (read-u16be buffer 16)))
           (pathconf-pipe-buf (unwrap (read-u16be buffer 20)))
           (pathconf-vdisable (unwrap (read-u8 buffer 28)))
           (pathconf-mask (unwrap (read-u16be buffer 32)))
           (statvfs-flag-rdonly (extract-bits pathconf-mask 0x0 0))
           (statvfs-flag-nosuid (extract-bits pathconf-mask 0x0 0))
           (statvfs-flag-notrunc (extract-bits pathconf-mask 0x0 0))
           (statvfs-flag-nodev (extract-bits pathconf-mask 0x0 0))
           (statvfs-flag-grpid (extract-bits pathconf-mask 0x0 0))
           (statvfs-flag-local (extract-bits pathconf-mask 0x0 0))
           (pathconf-max-canon (unwrap (read-u16be buffer 34)))
           )

      (ok (list
        (cons 'pathconf-max-input (list (cons 'raw pathconf-max-input) (cons 'formatted (number->string pathconf-max-input))))
        (cons 'pathconf-name-max (list (cons 'raw pathconf-name-max) (cons 'formatted (number->string pathconf-name-max))))
        (cons 'pathconf-path-max (list (cons 'raw pathconf-path-max) (cons 'formatted (number->string pathconf-path-max))))
        (cons 'pathconf-pipe-buf (list (cons 'raw pathconf-pipe-buf) (cons 'formatted (number->string pathconf-pipe-buf))))
        (cons 'pathconf-vdisable (list (cons 'raw pathconf-vdisable) (cons 'formatted (fmt-hex pathconf-vdisable))))
        (cons 'pathconf-mask (list (cons 'raw pathconf-mask) (cons 'formatted (fmt-hex pathconf-mask))))
        (cons 'statvfs-flag-rdonly (list (cons 'raw statvfs-flag-rdonly) (cons 'formatted (if (= statvfs-flag-rdonly 0) "Read/Write file system" "Read-only file system"))))
        (cons 'statvfs-flag-nosuid (list (cons 'raw statvfs-flag-nosuid) (cons 'formatted (if (= statvfs-flag-nosuid 0) "Supports setuid/setgid semantics" "Does not support setuid/setgid semantics"))))
        (cons 'statvfs-flag-notrunc (list (cons 'raw statvfs-flag-notrunc) (cons 'formatted (if (= statvfs-flag-notrunc 0) "Truncates filenames longer than NAME_MAX" "Does not truncate filenames longer than NAME_MAX"))))
        (cons 'statvfs-flag-nodev (list (cons 'raw statvfs-flag-nodev) (cons 'formatted (if (= statvfs-flag-nodev 0) "Allows opening of device files" "Disallows opening of device files"))))
        (cons 'statvfs-flag-grpid (list (cons 'raw statvfs-flag-grpid) (cons 'formatted (if (= statvfs-flag-grpid 0) "Group ID not assigned from directory" "Group ID assigned from directory"))))
        (cons 'statvfs-flag-local (list (cons 'raw statvfs-flag-local) (cons 'formatted (if (= statvfs-flag-local 0) "File system is not local" "File system is local"))))
        (cons 'pathconf-max-canon (list (cons 'raw pathconf-max-canon) (cons 'formatted (number->string pathconf-max-canon))))
        )))

    (catch (e)
      (err (str "MOUNT parse error: " e)))))

;; dissect-mount: parse MOUNT from bytevector
;; Returns (ok fields-alist) or (err message)