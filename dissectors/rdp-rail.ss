;; packet-rdp_rail.c
;; Routines for the RAIL RDP channel
;; Copyright 2023, David Fort <contact@hardening-consulting.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rdp-rail.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rdp_rail.c

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
(def (dissect-rdp-rail buffer)
  "RDP Program virtual channel Protocol"
  (try
    (let* (
           (pduLength (unwrap (read-u32be buffer 2)))
           (activate-enabled (unwrap (read-u8 buffer 8)))
           (notify-iconId (unwrap (read-u32be buffer 8)))
           (windowmove-left (unwrap (read-u16be buffer 12)))
           (windowmove-top (unwrap (read-u16be buffer 14)))
           (windowmove-right (unwrap (read-u16be buffer 16)))
           (windowmove-bottom (unwrap (read-u16be buffer 18)))
           (localmovesize-isMoveSizeStart (unwrap (read-u16be buffer 18)))
           (localmovesize-posX (unwrap (read-u16be buffer 22)))
           (localmovesize-posY (unwrap (read-u16be buffer 24)))
           (minmaxinfo-maxwidth (unwrap (read-u16be buffer 24)))
           (minmaxinfo-maxheight (unwrap (read-u16be buffer 26)))
           (minmaxinfo-maxPosX (unwrap (read-u16be buffer 28)))
           (minmaxinfo-maxPosY (unwrap (read-u16be buffer 30)))
           (minmaxinfo-minTrackWidth (unwrap (read-u16be buffer 32)))
           (minmaxinfo-minTrackHeight (unwrap (read-u16be buffer 34)))
           (minmaxinfo-maxTrackWidth (unwrap (read-u16be buffer 36)))
           (minmaxinfo-maxTrackHeight (unwrap (read-u16be buffer 38)))
           (cstatus-flags (unwrap (read-u32le buffer 38)))
           (caps-handshake-buildNumber (unwrap (read-u32be buffer 38)))
           (handshake-flags (unwrap (read-u32le buffer 42)))
           (cloak-cloaked (unwrap (read-u8 buffer 42)))
           (windowId (unwrap (read-u32be buffer 46)))
           )

      (ok (list
        (cons 'pduLength (list (cons 'raw pduLength) (cons 'formatted (number->string pduLength))))
        (cons 'activate-enabled (list (cons 'raw activate-enabled) (cons 'formatted (number->string activate-enabled))))
        (cons 'notify-iconId (list (cons 'raw notify-iconId) (cons 'formatted (fmt-hex notify-iconId))))
        (cons 'windowmove-left (list (cons 'raw windowmove-left) (cons 'formatted (number->string windowmove-left))))
        (cons 'windowmove-top (list (cons 'raw windowmove-top) (cons 'formatted (number->string windowmove-top))))
        (cons 'windowmove-right (list (cons 'raw windowmove-right) (cons 'formatted (number->string windowmove-right))))
        (cons 'windowmove-bottom (list (cons 'raw windowmove-bottom) (cons 'formatted (number->string windowmove-bottom))))
        (cons 'localmovesize-isMoveSizeStart (list (cons 'raw localmovesize-isMoveSizeStart) (cons 'formatted (number->string localmovesize-isMoveSizeStart))))
        (cons 'localmovesize-posX (list (cons 'raw localmovesize-posX) (cons 'formatted (number->string localmovesize-posX))))
        (cons 'localmovesize-posY (list (cons 'raw localmovesize-posY) (cons 'formatted (number->string localmovesize-posY))))
        (cons 'minmaxinfo-maxwidth (list (cons 'raw minmaxinfo-maxwidth) (cons 'formatted (number->string minmaxinfo-maxwidth))))
        (cons 'minmaxinfo-maxheight (list (cons 'raw minmaxinfo-maxheight) (cons 'formatted (number->string minmaxinfo-maxheight))))
        (cons 'minmaxinfo-maxPosX (list (cons 'raw minmaxinfo-maxPosX) (cons 'formatted (number->string minmaxinfo-maxPosX))))
        (cons 'minmaxinfo-maxPosY (list (cons 'raw minmaxinfo-maxPosY) (cons 'formatted (number->string minmaxinfo-maxPosY))))
        (cons 'minmaxinfo-minTrackWidth (list (cons 'raw minmaxinfo-minTrackWidth) (cons 'formatted (number->string minmaxinfo-minTrackWidth))))
        (cons 'minmaxinfo-minTrackHeight (list (cons 'raw minmaxinfo-minTrackHeight) (cons 'formatted (number->string minmaxinfo-minTrackHeight))))
        (cons 'minmaxinfo-maxTrackWidth (list (cons 'raw minmaxinfo-maxTrackWidth) (cons 'formatted (number->string minmaxinfo-maxTrackWidth))))
        (cons 'minmaxinfo-maxTrackHeight (list (cons 'raw minmaxinfo-maxTrackHeight) (cons 'formatted (number->string minmaxinfo-maxTrackHeight))))
        (cons 'cstatus-flags (list (cons 'raw cstatus-flags) (cons 'formatted (fmt-hex cstatus-flags))))
        (cons 'caps-handshake-buildNumber (list (cons 'raw caps-handshake-buildNumber) (cons 'formatted (fmt-hex caps-handshake-buildNumber))))
        (cons 'handshake-flags (list (cons 'raw handshake-flags) (cons 'formatted (fmt-hex handshake-flags))))
        (cons 'cloak-cloaked (list (cons 'raw cloak-cloaked) (cons 'formatted (number->string cloak-cloaked))))
        (cons 'windowId (list (cons 'raw windowId) (cons 'formatted (fmt-hex windowId))))
        )))

    (catch (e)
      (err (str "RDP-RAIL parse error: " e)))))

;; dissect-rdp-rail: parse RDP-RAIL from bytevector
;; Returns (ok fields-alist) or (err message)