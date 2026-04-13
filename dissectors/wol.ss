;; packet-wol.c
;; Routines for WOL dissection
;; Copyright 2007, Christopher Maynard <Chris.Maynard[AT]gtech.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; This dissector for "Wake On LAN" was not copied from any other existing
;; dissector.  It uses the template from SVN23520 docs/README.devloper, which
;; was the latest one available at the time of this writing.  This dissector is
;; a heuristic one though, so appropriate changes have made to the template
;; as needed.
;;
;; The "Wake On LAN" dissector was written based primarily on the AMD white
;; paper, available from:
;;
;; https://web.archive.org/web/20100601154907/http://www.amd.com/us-en/assets/content_type/white_papers_and_tech_docs/20213.pdf
;;
;; In addition, testing of the dissector was conducted using 2 utilities
;; downloaded from http://www.moldaner.de/wakeonlan/wakeonlan.html and
;; http://www.depicus.com/wake-on-lan/, as well as with the ether-wake utility
;; on a Linux Fedora Core 4 system.
;;
;; From what I can tell from the tools available, even though the white paper
;; indicates that the so-called, "MagicPacket" can be located anywhere within
;; the Ethernet frame, in practice, there seem to be only 2 variations of the
;; implementation of the MagicPacket.  Ether-wake implements it as an Ethernet
;; frame with ether type 0x0842 (ETHERTYPE_WOL), and the other tools all seem
;; to implement it as a UDP packet, both with the payload as nothing but the
;; MagicPacket.
;;
;; To keep things simple, this dissector will only indicate a frame as
;; Wake-On-Lan if the MagicPacket is found for a frame marked as etherytpe
;; 0x0842 or if it's a UDP packet.  To fully support Wake-On-Lan dissection
;; though, we would need a way to have this dissector called only if the frame
;; hasn't already been classified as some other type of dissector ... but I
;; don't know how to do that?  The only alternative I am aware of would be to
;; register as a heuristic dissector for pretty much every possible protocol
;; there is, which seems unreasonable to do to me.
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/wol.ss
;; Auto-generated from wireshark/epan/dissectors/packet-wol.c

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
(def (dissect-wol buffer)
  "Wake On LAN"
  (try
    (let* (
           (sync (unwrap (slice buffer 0 6)))
           (mac (unwrap (slice buffer 12 6)))
           (passwd (unwrap (slice buffer 12 4)))
           )

      (ok (list
        (cons 'sync (list (cons 'raw sync) (cons 'formatted (fmt-bytes sync))))
        (cons 'mac (list (cons 'raw mac) (cons 'formatted (fmt-mac mac))))
        (cons 'passwd (list (cons 'raw passwd) (cons 'formatted (fmt-bytes passwd))))
        )))

    (catch (e)
      (err (str "WOL parse error: " e)))))

;; dissect-wol: parse WOL from bytevector
;; Returns (ok fields-alist) or (err message)