;; packet-slsk.c
;; Routines for SoulSeek Protocol dissection
;; Copyright 2003, Christian Wagner <Christian.Wagner@stud.uni-karlsruhe.de>
;; Institute of Telematics - University of Karlsruhe
;; part of this work supported by
;; Deutsche Forschungsgemeinschaft (DFG) Grant Number FU448/1
;;
;; The SoulSeek Protocol is proprietary, with official site:
;; https://www.slsknet.org/news/
;; This dissector is based on protocol descriptions from various open source
;; reverse engineering projects (some no longer active), including SoleSeek Project:
;; https://web.archive.org/web/20060223004530/http://cvs.sourceforge.net/viewcvs.py/soleseek/SoleSeek/doc/protocol.html?rev=HEAD
;; Museek+
;; https://web.archive.org/web/20220327151706/https://www.museek-plus.org/wiki/SoulseekProtocol
;; https://github.com/eLvErDe/museek-plus
;; and Nicotine+
;; https://nicotine-plus.org/doc/SLSKPROTOCOL.html
;; Updated for SoulSeek client version 151
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/slsk.ss
;; Auto-generated from wireshark/epan/dissectors/packet-slsk.c

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
(def (dissect-slsk buffer)
  "SoulSeek Protocol"
  (try
    (let* (
           (message-length (unwrap (read-u32be buffer 0)))
           (version (unwrap (read-u32be buffer 8)))
           (client-ip (unwrap (read-u32be buffer 17)))
           (total-uploads (unwrap (read-u32be buffer 246)))
           (queued-uploads (unwrap (read-u32be buffer 250)))
           (timestamp (unwrap (read-u32be buffer 303)))
           (chat-message-id (unwrap (read-u32be buffer 311)))
           (folder-count (unwrap (read-u32be buffer 347)))
           (file-count (unwrap (read-u32be buffer 351)))
           (uncompressed-packet-length (unwrap (read-u32be buffer 395)))
           (compressed-packet-length (unwrap (read-u32be buffer 428)))
           (size (unwrap (read-u32be buffer 465)))
           (num-strings (unwrap (read-u32be buffer 569)))
           (place-in-queue (unwrap (read-u32be buffer 581)))
           (number-of-rooms (unwrap (read-u32be buffer 601)))
           (bytes (unwrap (slice buffer 641 13)))
           (users-in-room (unwrap (read-u32be buffer 678)))
           (average-speed (unwrap (read-u32be buffer 682)))
           (download-number (unwrap (read-u32be buffer 686)))
           (files (unwrap (read-u32be buffer 694)))
           (directories (unwrap (read-u32be buffer 698)))
           (num-slotsfull-records (unwrap (read-u32be buffer 702)))
           (slotsfull (unwrap (read-u32be buffer 706)))
           (code (unwrap (read-u32be buffer 714)))
           (number-of-priv-users (unwrap (read-u32be buffer 738)))
           (parent-min-speed (unwrap (read-u32be buffer 759)))
           (parent-speed-connection-ratio (unwrap (read-u32be buffer 767)))
           (seconds-parent-inactivity-before-disconnect (unwrap (read-u32be buffer 775)))
           (seconds-server-inactivity-before-disconnect (unwrap (read-u32be buffer 783)))
           (nodes-in-cache-before-disconnect (unwrap (read-u32be buffer 791)))
           (seconds-before-ping-children (unwrap (read-u32be buffer 799)))
           (number-of-days (unwrap (read-u32be buffer 815)))
           (embedded-message-type (unwrap (read-u32be buffer 823)))
           (byte (unwrap (read-u8 buffer 836)))
           (num-parent-address (unwrap (read-u32be buffer 841)))
           (ip (unwrap (read-u32be buffer 845)))
           (port (unwrap (read-u32be buffer 849)))
           (number-of-users (unwrap (read-u32be buffer 877)))
           (same-recommendation (unwrap (read-u32be buffer 881)))
           (ranking (unwrap (read-u32be buffer 897)))
           (num-recommendations (unwrap (read-u32be buffer 909)))
           (integer (unwrap (read-u32be buffer 930)))
           (connection-type (unwrap (slice buffer 939 4)))
           (token (unwrap (read-u32be buffer 948)))
           (message-code (unwrap (read-u32be buffer 952)))
           )

      (ok (list
        (cons 'message-length (list (cons 'raw message-length) (cons 'formatted (number->string message-length))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'client-ip (list (cons 'raw client-ip) (cons 'formatted (fmt-ipv4 client-ip))))
        (cons 'total-uploads (list (cons 'raw total-uploads) (cons 'formatted (number->string total-uploads))))
        (cons 'queued-uploads (list (cons 'raw queued-uploads) (cons 'formatted (number->string queued-uploads))))
        (cons 'timestamp (list (cons 'raw timestamp) (cons 'formatted (number->string timestamp))))
        (cons 'chat-message-id (list (cons 'raw chat-message-id) (cons 'formatted (number->string chat-message-id))))
        (cons 'folder-count (list (cons 'raw folder-count) (cons 'formatted (number->string folder-count))))
        (cons 'file-count (list (cons 'raw file-count) (cons 'formatted (number->string file-count))))
        (cons 'uncompressed-packet-length (list (cons 'raw uncompressed-packet-length) (cons 'formatted (number->string uncompressed-packet-length))))
        (cons 'compressed-packet-length (list (cons 'raw compressed-packet-length) (cons 'formatted (number->string compressed-packet-length))))
        (cons 'size (list (cons 'raw size) (cons 'formatted (number->string size))))
        (cons 'num-strings (list (cons 'raw num-strings) (cons 'formatted (number->string num-strings))))
        (cons 'place-in-queue (list (cons 'raw place-in-queue) (cons 'formatted (number->string place-in-queue))))
        (cons 'number-of-rooms (list (cons 'raw number-of-rooms) (cons 'formatted (number->string number-of-rooms))))
        (cons 'bytes (list (cons 'raw bytes) (cons 'formatted (fmt-bytes bytes))))
        (cons 'users-in-room (list (cons 'raw users-in-room) (cons 'formatted (number->string users-in-room))))
        (cons 'average-speed (list (cons 'raw average-speed) (cons 'formatted (number->string average-speed))))
        (cons 'download-number (list (cons 'raw download-number) (cons 'formatted (number->string download-number))))
        (cons 'files (list (cons 'raw files) (cons 'formatted (number->string files))))
        (cons 'directories (list (cons 'raw directories) (cons 'formatted (number->string directories))))
        (cons 'num-slotsfull-records (list (cons 'raw num-slotsfull-records) (cons 'formatted (number->string num-slotsfull-records))))
        (cons 'slotsfull (list (cons 'raw slotsfull) (cons 'formatted (number->string slotsfull))))
        (cons 'code (list (cons 'raw code) (cons 'formatted (number->string code))))
        (cons 'number-of-priv-users (list (cons 'raw number-of-priv-users) (cons 'formatted (number->string number-of-priv-users))))
        (cons 'parent-min-speed (list (cons 'raw parent-min-speed) (cons 'formatted (number->string parent-min-speed))))
        (cons 'parent-speed-connection-ratio (list (cons 'raw parent-speed-connection-ratio) (cons 'formatted (number->string parent-speed-connection-ratio))))
        (cons 'seconds-parent-inactivity-before-disconnect (list (cons 'raw seconds-parent-inactivity-before-disconnect) (cons 'formatted (number->string seconds-parent-inactivity-before-disconnect))))
        (cons 'seconds-server-inactivity-before-disconnect (list (cons 'raw seconds-server-inactivity-before-disconnect) (cons 'formatted (number->string seconds-server-inactivity-before-disconnect))))
        (cons 'nodes-in-cache-before-disconnect (list (cons 'raw nodes-in-cache-before-disconnect) (cons 'formatted (number->string nodes-in-cache-before-disconnect))))
        (cons 'seconds-before-ping-children (list (cons 'raw seconds-before-ping-children) (cons 'formatted (number->string seconds-before-ping-children))))
        (cons 'number-of-days (list (cons 'raw number-of-days) (cons 'formatted (number->string number-of-days))))
        (cons 'embedded-message-type (list (cons 'raw embedded-message-type) (cons 'formatted (number->string embedded-message-type))))
        (cons 'byte (list (cons 'raw byte) (cons 'formatted (number->string byte))))
        (cons 'num-parent-address (list (cons 'raw num-parent-address) (cons 'formatted (number->string num-parent-address))))
        (cons 'ip (list (cons 'raw ip) (cons 'formatted (fmt-ipv4 ip))))
        (cons 'port (list (cons 'raw port) (cons 'formatted (number->string port))))
        (cons 'number-of-users (list (cons 'raw number-of-users) (cons 'formatted (number->string number-of-users))))
        (cons 'same-recommendation (list (cons 'raw same-recommendation) (cons 'formatted (number->string same-recommendation))))
        (cons 'ranking (list (cons 'raw ranking) (cons 'formatted (number->string ranking))))
        (cons 'num-recommendations (list (cons 'raw num-recommendations) (cons 'formatted (number->string num-recommendations))))
        (cons 'integer (list (cons 'raw integer) (cons 'formatted (number->string integer))))
        (cons 'connection-type (list (cons 'raw connection-type) (cons 'formatted (utf8->string connection-type))))
        (cons 'token (list (cons 'raw token) (cons 'formatted (number->string token))))
        (cons 'message-code (list (cons 'raw message-code) (cons 'formatted (number->string message-code))))
        )))

    (catch (e)
      (err (str "SLSK parse error: " e)))))

;; dissect-slsk: parse SLSK from bytevector
;; Returns (ok fields-alist) or (err message)