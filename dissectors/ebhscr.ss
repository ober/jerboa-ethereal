;; packet-ebhscr.c
;; Routines for EBHSCR dissection
;; Copyright 2019, Ana Pantar <ana.pantar@gmail.com> for Elektrobit
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; For more information on this protocol see:
;; https://www.elektrobit.com/ebhscr
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ebhscr.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ebhscr.c

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
(def (dissect-ebhscr buffer)
  "EBHSCR Protocol"
  (try
    (let* (
           (major-number (unwrap (read-u8 buffer 0)))
           (packet-header (unwrap (slice buffer 0 32)))
           (channel (unwrap (read-u8 buffer 1)))
           (slot (unwrap (read-u8 buffer 1)))
           (version (unwrap (read-u16be buffer 2)))
           (status (unwrap (read-u16be buffer 2)))
           (status-unused (unwrap (read-u32be buffer 2)))
           (length (unwrap (read-u32be buffer 4)))
           (start-timestamp (unwrap (read-u64be buffer 8)))
           (stop-timestamp (unwrap (read-u64be buffer 16)))
           (slot-information (unwrap (read-u16be buffer 24)))
           (mjr-hdr-unused (unwrap (read-u64be buffer 24)))
           (mjr-hdr (unwrap (read-u64be buffer 24)))
           (following-cycle-counter (unwrap (read-u8 buffer 25)))
           (frame-status (unwrap (read-u16be buffer 26)))
           (csi2-mjr-hdr-frame-counter (unwrap (read-u16be buffer 28)))
           (symbol-length-and-status (unwrap (read-u8 buffer 28)))
           (supercycle-counter (unwrap (read-u32be buffer 28)))
           (csi2-mjr-hdr-line-counter (unwrap (read-u16be buffer 30)))
           (frame-header (unwrap (slice buffer 32 128)))
           (csi2-payload-pkt-hdr-dt (unwrap (read-u8 buffer 32)))
           (csi2-payload-pkt-hdr (unwrap (read-u64be buffer 32)))
           (payload-pid (unwrap (read-u8 buffer 32)))
           (time-offset-ns (unwrap (read-u64be buffer 32)))
           (csi2-payload-pkt-hdr-vc (unwrap (read-u8 buffer 33)))
           (csi2-payload-pkt-hdr-ecc (unwrap (read-u8 buffer 35)))
           (csi2-payload-pkt-hdr-crc (unwrap (read-u16be buffer 36)))
           (csi2-payload-pkt-hdr-wc-msb (unwrap (read-u16be buffer 38)))
           (csi2-payload-pkt-hdr-wc-lsb (unwrap (read-u16be buffer 38)))
           (last-offset-ns (unwrap (read-u64be buffer 40)))
           (last-jump-ns (unwrap (read-u64be buffer 48)))
           (utc-leap-sec (unwrap (read-u16be buffer 56)))
           )

      (ok (list
        (cons 'major-number (list (cons 'raw major-number) (cons 'formatted (fmt-hex major-number))))
        (cons 'packet-header (list (cons 'raw packet-header) (cons 'formatted (fmt-bytes packet-header))))
        (cons 'channel (list (cons 'raw channel) (cons 'formatted (fmt-hex channel))))
        (cons 'slot (list (cons 'raw slot) (cons 'formatted (fmt-hex slot))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (fmt-hex version))))
        (cons 'status (list (cons 'raw status) (cons 'formatted (fmt-hex status))))
        (cons 'status-unused (list (cons 'raw status-unused) (cons 'formatted (fmt-hex status-unused))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'start-timestamp (list (cons 'raw start-timestamp) (cons 'formatted (fmt-hex start-timestamp))))
        (cons 'stop-timestamp (list (cons 'raw stop-timestamp) (cons 'formatted (fmt-hex stop-timestamp))))
        (cons 'slot-information (list (cons 'raw slot-information) (cons 'formatted (fmt-hex slot-information))))
        (cons 'mjr-hdr-unused (list (cons 'raw mjr-hdr-unused) (cons 'formatted (fmt-hex mjr-hdr-unused))))
        (cons 'mjr-hdr (list (cons 'raw mjr-hdr) (cons 'formatted (fmt-hex mjr-hdr))))
        (cons 'following-cycle-counter (list (cons 'raw following-cycle-counter) (cons 'formatted (number->string following-cycle-counter))))
        (cons 'frame-status (list (cons 'raw frame-status) (cons 'formatted (fmt-hex frame-status))))
        (cons 'csi2-mjr-hdr-frame-counter (list (cons 'raw csi2-mjr-hdr-frame-counter) (cons 'formatted (number->string csi2-mjr-hdr-frame-counter))))
        (cons 'symbol-length-and-status (list (cons 'raw symbol-length-and-status) (cons 'formatted (fmt-hex symbol-length-and-status))))
        (cons 'supercycle-counter (list (cons 'raw supercycle-counter) (cons 'formatted (number->string supercycle-counter))))
        (cons 'csi2-mjr-hdr-line-counter (list (cons 'raw csi2-mjr-hdr-line-counter) (cons 'formatted (number->string csi2-mjr-hdr-line-counter))))
        (cons 'frame-header (list (cons 'raw frame-header) (cons 'formatted (fmt-bytes frame-header))))
        (cons 'csi2-payload-pkt-hdr-dt (list (cons 'raw csi2-payload-pkt-hdr-dt) (cons 'formatted (fmt-hex csi2-payload-pkt-hdr-dt))))
        (cons 'csi2-payload-pkt-hdr (list (cons 'raw csi2-payload-pkt-hdr) (cons 'formatted (fmt-hex csi2-payload-pkt-hdr))))
        (cons 'payload-pid (list (cons 'raw payload-pid) (cons 'formatted (fmt-hex payload-pid))))
        (cons 'time-offset-ns (list (cons 'raw time-offset-ns) (cons 'formatted (fmt-hex time-offset-ns))))
        (cons 'csi2-payload-pkt-hdr-vc (list (cons 'raw csi2-payload-pkt-hdr-vc) (cons 'formatted (fmt-hex csi2-payload-pkt-hdr-vc))))
        (cons 'csi2-payload-pkt-hdr-ecc (list (cons 'raw csi2-payload-pkt-hdr-ecc) (cons 'formatted (fmt-hex csi2-payload-pkt-hdr-ecc))))
        (cons 'csi2-payload-pkt-hdr-crc (list (cons 'raw csi2-payload-pkt-hdr-crc) (cons 'formatted (fmt-hex csi2-payload-pkt-hdr-crc))))
        (cons 'csi2-payload-pkt-hdr-wc-msb (list (cons 'raw csi2-payload-pkt-hdr-wc-msb) (cons 'formatted (fmt-hex csi2-payload-pkt-hdr-wc-msb))))
        (cons 'csi2-payload-pkt-hdr-wc-lsb (list (cons 'raw csi2-payload-pkt-hdr-wc-lsb) (cons 'formatted (fmt-hex csi2-payload-pkt-hdr-wc-lsb))))
        (cons 'last-offset-ns (list (cons 'raw last-offset-ns) (cons 'formatted (fmt-hex last-offset-ns))))
        (cons 'last-jump-ns (list (cons 'raw last-jump-ns) (cons 'formatted (fmt-hex last-jump-ns))))
        (cons 'utc-leap-sec (list (cons 'raw utc-leap-sec) (cons 'formatted (fmt-hex utc-leap-sec))))
        )))

    (catch (e)
      (err (str "EBHSCR parse error: " e)))))

;; dissect-ebhscr: parse EBHSCR from bytevector
;; Returns (ok fields-alist) or (err message)