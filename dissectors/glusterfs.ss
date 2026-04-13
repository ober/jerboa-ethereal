;; packet-glusterfs.c
;; Routines for GlusterFS dissection
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
;; - https://github.com/gluster/glusterfs
;;
;; The coding-style is roughly the same as the one use in the Linux kernel,
;; see http://www.kernel.org/doc/Documentation/CodingStyle.
;;

;; jerboa-ethereal/dissectors/glusterfs.ss
;; Auto-generated from wireshark/epan/dissectors/packet-glusterfs.c

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
(def (dissect-glusterfs buffer)
  "GlusterFS"
  (try
    (let* (
           (setattr-valid (unwrap (read-u32be buffer 0)))
           (xflags (unwrap (read-u32be buffer 0)))
           (fsync-flags (unwrap (read-u32be buffer 0)))
           (flock-owner (unwrap (slice buffer 56 1)))
           (flags (unwrap (read-u32be buffer 56)))
           (flags-rdonly (unwrap (read-u8 buffer 56)))
           (mnt-flags (unwrap (read-u64be buffer 60)))
           (fsync-flag-datasync (extract-bits mnt-flags 0x1 0))
           (dict-size (unwrap (read-u32be buffer 68)))
           (num-dict-items (unwrap (read-u32be buffer 72)))
           (rpc-roundup-bytes (unwrap (slice buffer 84 1)))
           (gfid (unwrap (slice buffer 104 16)))
           (trusted-afr-key (unwrap (slice buffer 104 12)))
           (dict-value (unwrap (slice buffer 104 1)))
           (op-errno (unwrap (read-u32be buffer 108)))
           )

      (ok (list
        (cons 'setattr-valid (list (cons 'raw setattr-valid) (cons 'formatted (fmt-hex setattr-valid))))
        (cons 'xflags (list (cons 'raw xflags) (cons 'formatted (fmt-oct xflags))))
        (cons 'fsync-flags (list (cons 'raw fsync-flags) (cons 'formatted (fmt-hex fsync-flags))))
        (cons 'flock-owner (list (cons 'raw flock-owner) (cons 'formatted (fmt-bytes flock-owner))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-oct flags))))
        (cons 'flags-rdonly (list (cons 'raw flags-rdonly) (cons 'formatted (if (= flags-rdonly 0) "Set" "Not set"))))
        (cons 'mnt-flags (list (cons 'raw mnt-flags) (cons 'formatted (fmt-hex mnt-flags))))
        (cons 'fsync-flag-datasync (list (cons 'raw fsync-flag-datasync) (cons 'formatted (if (= fsync-flag-datasync 0) "Not set" "Set"))))
        (cons 'dict-size (list (cons 'raw dict-size) (cons 'formatted (number->string dict-size))))
        (cons 'num-dict-items (list (cons 'raw num-dict-items) (cons 'formatted (number->string num-dict-items))))
        (cons 'rpc-roundup-bytes (list (cons 'raw rpc-roundup-bytes) (cons 'formatted (fmt-bytes rpc-roundup-bytes))))
        (cons 'gfid (list (cons 'raw gfid) (cons 'formatted (fmt-bytes gfid))))
        (cons 'trusted-afr-key (list (cons 'raw trusted-afr-key) (cons 'formatted (fmt-bytes trusted-afr-key))))
        (cons 'dict-value (list (cons 'raw dict-value) (cons 'formatted (utf8->string dict-value))))
        (cons 'op-errno (list (cons 'raw op-errno) (cons 'formatted (number->string op-errno))))
        )))

    (catch (e)
      (err (str "GLUSTERFS parse error: " e)))))

;; dissect-glusterfs: parse GLUSTERFS from bytevector
;; Returns (ok fields-alist) or (err message)