;; packet-hsrp.c
;; Routines for the Cisco Hot Standby Router Protocol (HSRP)
;;
;; Heikki Vatiainen <hessu@cs.tut.fi>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-vrrp.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/hsrp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-hsrp.c
;; RFC 2281

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
(def (dissect-hsrp buffer)
  "Cisco Hot Standby Router Protocol"
  (try
    (let* (
           (reserved (unwrap (read-u8 buffer 0)))
           (group-state-tlv (unwrap (read-u8 buffer 0)))
           (version (unwrap (read-u8 buffer 2)))
           (group (unwrap (read-u16be buffer 2)))
           (identifier (unwrap (slice buffer 4 6)))
           (priority (unwrap (read-u32be buffer 10)))
           (adv-length (unwrap (read-u16be buffer 14)))
           (hellotime (unwrap (read-u32be buffer 14)))
           (adv-reserved1 (unwrap (read-u8 buffer 17)))
           (adv-activegrp (unwrap (read-u16be buffer 18)))
           (holdtime (unwrap (read-u32be buffer 18)))
           (adv-passivegrp (unwrap (read-u16be buffer 20)))
           (adv-reserved2 (unwrap (read-u32be buffer 22)))
           (virt-ip-addr (unwrap (read-u32be buffer 22)))
           (virt-ip-addr-v6 (unwrap (slice buffer 22 16)))
           (interface-state-tlv (unwrap (read-u8 buffer 38)))
           (active-group (unwrap (read-u16be buffer 40)))
           (passive-group (unwrap (read-u16be buffer 42)))
           (text-auth-tlv (unwrap (read-u8 buffer 44)))
           (auth-data (unwrap (slice buffer 46 8)))
           )

      (ok (list
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (number->string reserved))))
        (cons 'group-state-tlv (list (cons 'raw group-state-tlv) (cons 'formatted (number->string group-state-tlv))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'group (list (cons 'raw group) (cons 'formatted (number->string group))))
        (cons 'identifier (list (cons 'raw identifier) (cons 'formatted (fmt-mac identifier))))
        (cons 'priority (list (cons 'raw priority) (cons 'formatted (number->string priority))))
        (cons 'adv-length (list (cons 'raw adv-length) (cons 'formatted (number->string adv-length))))
        (cons 'hellotime (list (cons 'raw hellotime) (cons 'formatted (number->string hellotime))))
        (cons 'adv-reserved1 (list (cons 'raw adv-reserved1) (cons 'formatted (number->string adv-reserved1))))
        (cons 'adv-activegrp (list (cons 'raw adv-activegrp) (cons 'formatted (number->string adv-activegrp))))
        (cons 'holdtime (list (cons 'raw holdtime) (cons 'formatted (number->string holdtime))))
        (cons 'adv-passivegrp (list (cons 'raw adv-passivegrp) (cons 'formatted (number->string adv-passivegrp))))
        (cons 'adv-reserved2 (list (cons 'raw adv-reserved2) (cons 'formatted (number->string adv-reserved2))))
        (cons 'virt-ip-addr (list (cons 'raw virt-ip-addr) (cons 'formatted (fmt-ipv4 virt-ip-addr))))
        (cons 'virt-ip-addr-v6 (list (cons 'raw virt-ip-addr-v6) (cons 'formatted (fmt-ipv6-address virt-ip-addr-v6))))
        (cons 'interface-state-tlv (list (cons 'raw interface-state-tlv) (cons 'formatted (number->string interface-state-tlv))))
        (cons 'active-group (list (cons 'raw active-group) (cons 'formatted (number->string active-group))))
        (cons 'passive-group (list (cons 'raw passive-group) (cons 'formatted (number->string passive-group))))
        (cons 'text-auth-tlv (list (cons 'raw text-auth-tlv) (cons 'formatted (number->string text-auth-tlv))))
        (cons 'auth-data (list (cons 'raw auth-data) (cons 'formatted (utf8->string auth-data))))
        )))

    (catch (e)
      (err (str "HSRP parse error: " e)))))

;; dissect-hsrp: parse HSRP from bytevector
;; Returns (ok fields-alist) or (err message)