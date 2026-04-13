;; packet-ar_drone.c
;; Routines for AR ar_drone protocol packet disassembly
;; By Paul Hoisington <hoisingtonp@bit-sys.com>,
;; Tom Hildesheim <hildesheimt@bit-sys.com>,
;; and Claire Brantley <brantleyc@bit-sys.com>
;; Copyright 2012 BIT Systems
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ar-drone.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ar_drone.c

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
(def (dissect-ar-drone buffer)
  "AR Drone Packet"
  (try
    (let* (
           (drone-PCMD-flag (unwrap (slice buffer 0 1)))
           (drone-PCMD-roll (unwrap (slice buffer 0 1)))
           (drone-PCMD-pitch (unwrap (slice buffer 0 1)))
           (drone-PCMD-gaz (unwrap (slice buffer 0 1)))
           (drone-PCMD-yaw (unwrap (slice buffer 0 1)))
           (drone-REF-id (unwrap (slice buffer 0 1)))
           (drone-REF-ctrl (unwrap (slice buffer 0 1)))
           (drone-CONFIG-ID-seq (unwrap (slice buffer 0 1)))
           (drone-CONFIG-ID-session (unwrap (slice buffer 0 1)))
           (drone-CONFIG-ID-user (unwrap (slice buffer 0 1)))
           (drone-CONFIG-ID-app (unwrap (slice buffer 0 1)))
           (drone-ANIM-seq (unwrap (slice buffer 0 1)))
           (drone-ANIM-anim (unwrap (slice buffer 0 1)))
           (drone-ANIM-sec (unwrap (slice buffer 0 1)))
           (drone-FTRIM-seq (unwrap (slice buffer 0 1)))
           (drone-CONFIG-seq (unwrap (slice buffer 0 1)))
           (drone-CONFIG-name (unwrap (slice buffer 0 1)))
           (drone-CONFIG-val (unwrap (slice buffer 0 1)))
           (drone-LED-seq (unwrap (slice buffer 0 1)))
           (drone-LED-anim (unwrap (slice buffer 0 1)))
           (drone-LED-freq (unwrap (slice buffer 0 1)))
           (drone-LED-sec (unwrap (slice buffer 0 1)))
           (drone-COMWDG (unwrap (slice buffer 0 1)))
           (drone-CTRL-seq (unwrap (slice buffer 0 1)))
           (drone-CTRL-mode (unwrap (slice buffer 0 1)))
           (drone-CTRL-fsize (unwrap (slice buffer 0 1)))
           (drone-PCMD-id (unwrap (slice buffer 1 1)))
           )

      (ok (list
        (cons 'drone-PCMD-flag (list (cons 'raw drone-PCMD-flag) (cons 'formatted (utf8->string drone-PCMD-flag))))
        (cons 'drone-PCMD-roll (list (cons 'raw drone-PCMD-roll) (cons 'formatted (utf8->string drone-PCMD-roll))))
        (cons 'drone-PCMD-pitch (list (cons 'raw drone-PCMD-pitch) (cons 'formatted (utf8->string drone-PCMD-pitch))))
        (cons 'drone-PCMD-gaz (list (cons 'raw drone-PCMD-gaz) (cons 'formatted (utf8->string drone-PCMD-gaz))))
        (cons 'drone-PCMD-yaw (list (cons 'raw drone-PCMD-yaw) (cons 'formatted (utf8->string drone-PCMD-yaw))))
        (cons 'drone-REF-id (list (cons 'raw drone-REF-id) (cons 'formatted (utf8->string drone-REF-id))))
        (cons 'drone-REF-ctrl (list (cons 'raw drone-REF-ctrl) (cons 'formatted (utf8->string drone-REF-ctrl))))
        (cons 'drone-CONFIG-ID-seq (list (cons 'raw drone-CONFIG-ID-seq) (cons 'formatted (utf8->string drone-CONFIG-ID-seq))))
        (cons 'drone-CONFIG-ID-session (list (cons 'raw drone-CONFIG-ID-session) (cons 'formatted (utf8->string drone-CONFIG-ID-session))))
        (cons 'drone-CONFIG-ID-user (list (cons 'raw drone-CONFIG-ID-user) (cons 'formatted (utf8->string drone-CONFIG-ID-user))))
        (cons 'drone-CONFIG-ID-app (list (cons 'raw drone-CONFIG-ID-app) (cons 'formatted (utf8->string drone-CONFIG-ID-app))))
        (cons 'drone-ANIM-seq (list (cons 'raw drone-ANIM-seq) (cons 'formatted (utf8->string drone-ANIM-seq))))
        (cons 'drone-ANIM-anim (list (cons 'raw drone-ANIM-anim) (cons 'formatted (utf8->string drone-ANIM-anim))))
        (cons 'drone-ANIM-sec (list (cons 'raw drone-ANIM-sec) (cons 'formatted (utf8->string drone-ANIM-sec))))
        (cons 'drone-FTRIM-seq (list (cons 'raw drone-FTRIM-seq) (cons 'formatted (utf8->string drone-FTRIM-seq))))
        (cons 'drone-CONFIG-seq (list (cons 'raw drone-CONFIG-seq) (cons 'formatted (utf8->string drone-CONFIG-seq))))
        (cons 'drone-CONFIG-name (list (cons 'raw drone-CONFIG-name) (cons 'formatted (utf8->string drone-CONFIG-name))))
        (cons 'drone-CONFIG-val (list (cons 'raw drone-CONFIG-val) (cons 'formatted (utf8->string drone-CONFIG-val))))
        (cons 'drone-LED-seq (list (cons 'raw drone-LED-seq) (cons 'formatted (utf8->string drone-LED-seq))))
        (cons 'drone-LED-anim (list (cons 'raw drone-LED-anim) (cons 'formatted (utf8->string drone-LED-anim))))
        (cons 'drone-LED-freq (list (cons 'raw drone-LED-freq) (cons 'formatted (utf8->string drone-LED-freq))))
        (cons 'drone-LED-sec (list (cons 'raw drone-LED-sec) (cons 'formatted (utf8->string drone-LED-sec))))
        (cons 'drone-COMWDG (list (cons 'raw drone-COMWDG) (cons 'formatted (utf8->string drone-COMWDG))))
        (cons 'drone-CTRL-seq (list (cons 'raw drone-CTRL-seq) (cons 'formatted (utf8->string drone-CTRL-seq))))
        (cons 'drone-CTRL-mode (list (cons 'raw drone-CTRL-mode) (cons 'formatted (utf8->string drone-CTRL-mode))))
        (cons 'drone-CTRL-fsize (list (cons 'raw drone-CTRL-fsize) (cons 'formatted (utf8->string drone-CTRL-fsize))))
        (cons 'drone-PCMD-id (list (cons 'raw drone-PCMD-id) (cons 'formatted (utf8->string drone-PCMD-id))))
        )))

    (catch (e)
      (err (str "AR-DRONE parse error: " e)))))

;; dissect-ar-drone: parse AR-DRONE from bytevector
;; Returns (ok fields-alist) or (err message)