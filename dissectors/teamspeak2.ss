;; packet-teamspeak2.c
;; Routines for TeamSpeak2 protocol packet disassembly
;; By brooss <brooss.teambb@gmail.com>
;; Copyright 2008 brooss
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/teamspeak2.ss
;; Auto-generated from wireshark/epan/dissectors/packet-teamspeak2.c

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
(def (dissect-teamspeak2 buffer)
  "Teamspeak2 Protocol"
  (try
    (let* (
           (number-of-channels (unwrap (read-u32be buffer 0)))
           (number-of-players (unwrap (read-u32be buffer 0)))
           (sessionkey (unwrap (read-u32be buffer 4)))
           (player-id (unwrap (read-u32be buffer 4)))
           (clientid (unwrap (read-u32be buffer 8)))
           (channel-id (unwrap (read-u32be buffer 8)))
           (channel-flags (unwrap (read-u8 buffer 8)))
           (channel-unregistered (unwrap (read-u8 buffer 8)))
           (channel-moderated (unwrap (read-u8 buffer 8)))
           (channel-password (unwrap (read-u8 buffer 8)))
           (channel-subchannels (unwrap (read-u8 buffer 8)))
           (channel-default (unwrap (read-u8 buffer 8)))
           (unknown (unwrap (slice buffer 9 1)))
           (seqnum (unwrap (read-u32be buffer 12)))
           (parent-channel-id (unwrap (read-u32be buffer 12)))
           (resend-count (unwrap (read-u16be buffer 16)))
           (channel-order (unwrap (read-u16be buffer 16)))
           (player-status-flags (unwrap (read-u16be buffer 16)))
           (fragmentnumber (unwrap (read-u16be buffer 18)))
           (max-users (unwrap (read-u16be buffer 18)))
           (ackto (unwrap (read-u32be buffer 20)))
           (channel-name (unwrap (slice buffer 20 1)))
           (channel-topic (unwrap (slice buffer 20 1)))
           (channel-description (unwrap (slice buffer 20 1)))
           (status-channelcommander (unwrap (read-u8 buffer 20)))
           (status-blockwhispers (unwrap (read-u8 buffer 20)))
           (status-away (unwrap (read-u8 buffer 20)))
           (status-mutemicrophone (unwrap (read-u8 buffer 20)))
           (status-mute (unwrap (read-u8 buffer 20)))
           (badlogin (unwrap (read-u8 buffer 89)))
           (registeredlogin (unwrap (read-u8 buffer 90)))
           )

      (ok (list
        (cons 'number-of-channels (list (cons 'raw number-of-channels) (cons 'formatted (number->string number-of-channels))))
        (cons 'number-of-players (list (cons 'raw number-of-players) (cons 'formatted (number->string number-of-players))))
        (cons 'sessionkey (list (cons 'raw sessionkey) (cons 'formatted (fmt-hex sessionkey))))
        (cons 'player-id (list (cons 'raw player-id) (cons 'formatted (number->string player-id))))
        (cons 'clientid (list (cons 'raw clientid) (cons 'formatted (number->string clientid))))
        (cons 'channel-id (list (cons 'raw channel-id) (cons 'formatted (number->string channel-id))))
        (cons 'channel-flags (list (cons 'raw channel-flags) (cons 'formatted (fmt-hex channel-flags))))
        (cons 'channel-unregistered (list (cons 'raw channel-unregistered) (cons 'formatted (number->string channel-unregistered))))
        (cons 'channel-moderated (list (cons 'raw channel-moderated) (cons 'formatted (number->string channel-moderated))))
        (cons 'channel-password (list (cons 'raw channel-password) (cons 'formatted (number->string channel-password))))
        (cons 'channel-subchannels (list (cons 'raw channel-subchannels) (cons 'formatted (number->string channel-subchannels))))
        (cons 'channel-default (list (cons 'raw channel-default) (cons 'formatted (number->string channel-default))))
        (cons 'unknown (list (cons 'raw unknown) (cons 'formatted (fmt-bytes unknown))))
        (cons 'seqnum (list (cons 'raw seqnum) (cons 'formatted (number->string seqnum))))
        (cons 'parent-channel-id (list (cons 'raw parent-channel-id) (cons 'formatted (fmt-hex parent-channel-id))))
        (cons 'resend-count (list (cons 'raw resend-count) (cons 'formatted (number->string resend-count))))
        (cons 'channel-order (list (cons 'raw channel-order) (cons 'formatted (number->string channel-order))))
        (cons 'player-status-flags (list (cons 'raw player-status-flags) (cons 'formatted (number->string player-status-flags))))
        (cons 'fragmentnumber (list (cons 'raw fragmentnumber) (cons 'formatted (number->string fragmentnumber))))
        (cons 'max-users (list (cons 'raw max-users) (cons 'formatted (number->string max-users))))
        (cons 'ackto (list (cons 'raw ackto) (cons 'formatted (number->string ackto))))
        (cons 'channel-name (list (cons 'raw channel-name) (cons 'formatted (utf8->string channel-name))))
        (cons 'channel-topic (list (cons 'raw channel-topic) (cons 'formatted (utf8->string channel-topic))))
        (cons 'channel-description (list (cons 'raw channel-description) (cons 'formatted (utf8->string channel-description))))
        (cons 'status-channelcommander (list (cons 'raw status-channelcommander) (cons 'formatted (number->string status-channelcommander))))
        (cons 'status-blockwhispers (list (cons 'raw status-blockwhispers) (cons 'formatted (number->string status-blockwhispers))))
        (cons 'status-away (list (cons 'raw status-away) (cons 'formatted (number->string status-away))))
        (cons 'status-mutemicrophone (list (cons 'raw status-mutemicrophone) (cons 'formatted (number->string status-mutemicrophone))))
        (cons 'status-mute (list (cons 'raw status-mute) (cons 'formatted (number->string status-mute))))
        (cons 'badlogin (list (cons 'raw badlogin) (cons 'formatted (number->string badlogin))))
        (cons 'registeredlogin (list (cons 'raw registeredlogin) (cons 'formatted (number->string registeredlogin))))
        )))

    (catch (e)
      (err (str "TEAMSPEAK2 parse error: " e)))))

;; dissect-teamspeak2: parse TEAMSPEAK2 from bytevector
;; Returns (ok fields-alist) or (err message)