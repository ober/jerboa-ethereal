;; packet-rdp_drdynvc.c
;; Routines for Dynamic Virtual channel RDP packet dissection
;; Copyright 2021, David Fort
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/rdp-drdynvc.ss
;; Auto-generated from wireshark/epan/dissectors/packet-rdp_drdynvc.c

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
(def (dissect-rdp-drdynvc buffer)
  "RDP Dynamic Channel Protocol"
  (try
    (let* (
           (drdynvc-sp (unwrap (read-u8 buffer 0)))
           (drdynvc-creationStatus (unwrap (read-u32be buffer 0)))
           (drdynvc-capa-version (unwrap (read-u16be buffer 0)))
           (drdynvc-capa-prio0 (unwrap (read-u16be buffer 2)))
           (drdynvc-capa-prio1 (unwrap (read-u16be buffer 4)))
           (drdynvc-capa-prio2 (unwrap (read-u16be buffer 6)))
           (drdynvc-capa-prio3 (unwrap (read-u16be buffer 8)))
           (drdynvc-createresp-channelname (unwrap (slice buffer 10 1)))
           (drdynvc-data-progress (unwrap (slice buffer 10 1)))
           (drdynvc-data (unwrap (slice buffer 10 1)))
           (drdynvc-softsync-req-length (unwrap (read-u32be buffer 10)))
           (drdynvc-softsync-req-flags (unwrap (read-u16be buffer 14)))
           (drdynvc-softsync-req-ntunnels (unwrap (read-u16be buffer 16)))
           (drdynvc-softsync-req-channel-ndvc (unwrap (read-u16be buffer 22)))
           (drdynvc-softsync-req-channel-dvcid (unwrap (read-u32be buffer 28)))
           (drdynvc-pad (unwrap (read-u8 buffer 28)))
           (drdynvc-softsync-resp-ntunnels (unwrap (read-u32be buffer 28)))
           (drdynvc-channelName (unwrap (slice buffer 36 1)))
           )

      (ok (list
        (cons 'drdynvc-sp (list (cons 'raw drdynvc-sp) (cons 'formatted (fmt-hex drdynvc-sp))))
        (cons 'drdynvc-creationStatus (list (cons 'raw drdynvc-creationStatus) (cons 'formatted (number->string drdynvc-creationStatus))))
        (cons 'drdynvc-capa-version (list (cons 'raw drdynvc-capa-version) (cons 'formatted (number->string drdynvc-capa-version))))
        (cons 'drdynvc-capa-prio0 (list (cons 'raw drdynvc-capa-prio0) (cons 'formatted (number->string drdynvc-capa-prio0))))
        (cons 'drdynvc-capa-prio1 (list (cons 'raw drdynvc-capa-prio1) (cons 'formatted (number->string drdynvc-capa-prio1))))
        (cons 'drdynvc-capa-prio2 (list (cons 'raw drdynvc-capa-prio2) (cons 'formatted (number->string drdynvc-capa-prio2))))
        (cons 'drdynvc-capa-prio3 (list (cons 'raw drdynvc-capa-prio3) (cons 'formatted (number->string drdynvc-capa-prio3))))
        (cons 'drdynvc-createresp-channelname (list (cons 'raw drdynvc-createresp-channelname) (cons 'formatted (utf8->string drdynvc-createresp-channelname))))
        (cons 'drdynvc-data-progress (list (cons 'raw drdynvc-data-progress) (cons 'formatted (utf8->string drdynvc-data-progress))))
        (cons 'drdynvc-data (list (cons 'raw drdynvc-data) (cons 'formatted (fmt-bytes drdynvc-data))))
        (cons 'drdynvc-softsync-req-length (list (cons 'raw drdynvc-softsync-req-length) (cons 'formatted (number->string drdynvc-softsync-req-length))))
        (cons 'drdynvc-softsync-req-flags (list (cons 'raw drdynvc-softsync-req-flags) (cons 'formatted (number->string drdynvc-softsync-req-flags))))
        (cons 'drdynvc-softsync-req-ntunnels (list (cons 'raw drdynvc-softsync-req-ntunnels) (cons 'formatted (number->string drdynvc-softsync-req-ntunnels))))
        (cons 'drdynvc-softsync-req-channel-ndvc (list (cons 'raw drdynvc-softsync-req-channel-ndvc) (cons 'formatted (number->string drdynvc-softsync-req-channel-ndvc))))
        (cons 'drdynvc-softsync-req-channel-dvcid (list (cons 'raw drdynvc-softsync-req-channel-dvcid) (cons 'formatted (fmt-hex drdynvc-softsync-req-channel-dvcid))))
        (cons 'drdynvc-pad (list (cons 'raw drdynvc-pad) (cons 'formatted (fmt-hex drdynvc-pad))))
        (cons 'drdynvc-softsync-resp-ntunnels (list (cons 'raw drdynvc-softsync-resp-ntunnels) (cons 'formatted (number->string drdynvc-softsync-resp-ntunnels))))
        (cons 'drdynvc-channelName (list (cons 'raw drdynvc-channelName) (cons 'formatted (utf8->string drdynvc-channelName))))
        )))

    (catch (e)
      (err (str "RDP-DRDYNVC parse error: " e)))))

;; dissect-rdp-drdynvc: parse RDP-DRDYNVC from bytevector
;; Returns (ok fields-alist) or (err message)