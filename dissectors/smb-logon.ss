;; packet-smb-logon.c
;; Routines for SMB net logon packet dissection
;; Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Copied from packet-pop.c
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/smb-logon.ss
;; Auto-generated from wireshark/epan/dissectors/packet-smb_logon.c

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
(def (dissect-smb-logon buffer)
  "Microsoft Windows Logon Protocol (Old)"
  (try
    (let* (
           (control (unwrap (read-u32le buffer 0)))
           (autolock (extract-bits control 0x0 0))
           (expire (extract-bits control 0x0 0))
           (server-trust (extract-bits control 0x0 0))
           (workstation-trust (extract-bits control 0x0 0))
           (interdomain-trust (extract-bits control 0x0 0))
           (mns-user (extract-bits control 0x0 0))
           (normal-user (extract-bits control 0x0 0))
           (temp-dup-user (extract-bits control 0x0 0))
           (password-required (extract-bits control 0x0 0))
           (homedir-required (extract-bits control 0x0 0))
           (enabled (extract-bits control 0x0 0))
           (token (unwrap (read-u16be buffer 6)))
           (hf-pulse (unwrap (read-u32be buffer 33)))
           (hf-random (unwrap (read-u32be buffer 37)))
           (index (unwrap (read-u32be buffer 45)))
           (serial (unwrap (read-u64be buffer 49)))
           (count (unwrap (read-u16be buffer 73)))
           (sid-size (unwrap (read-u32be buffer 75)))
           (hf-signature (unwrap (read-u64be buffer 90)))
           (time (unwrap (read-u32be buffer 98)))
           (type (unwrap (read-u16be buffer 102)))
           (guid (unwrap (slice buffer 123 16)))
           (hf-unknown8 (unwrap (read-u8 buffer 139)))
           (ip (unwrap (read-u32be buffer 144)))
           (hf-unknown32 (unwrap (read-u32be buffer 148)))
           (version (unwrap (read-u32be buffer 156)))
           (hf-data (unwrap (slice buffer 160 1)))
           )

      (ok (list
        (cons 'control (list (cons 'raw control) (cons 'formatted (fmt-hex control))))
        (cons 'autolock (list (cons 'raw autolock) (cons 'formatted (if (= autolock 0) "User account NOT auto-locked" "User account auto-locked"))))
        (cons 'expire (list (cons 'raw expire) (cons 'formatted (if (= expire 0) "User password will expire" "User password will NOT expire"))))
        (cons 'server-trust (list (cons 'raw server-trust) (cons 'formatted (if (= server-trust 0) "NOT a Server Trust user account" "Server Trust user account"))))
        (cons 'workstation-trust (list (cons 'raw workstation-trust) (cons 'formatted (if (= workstation-trust 0) "NOT a Workstation Trust user account" "Workstation Trust user account"))))
        (cons 'interdomain-trust (list (cons 'raw interdomain-trust) (cons 'formatted (if (= interdomain-trust 0) "NOT a Inter-domain Trust user account" "Inter-domain Trust user account"))))
        (cons 'mns-user (list (cons 'raw mns-user) (cons 'formatted (if (= mns-user 0) "NOT a MNS Logon user account" "MNS Logon user account"))))
        (cons 'normal-user (list (cons 'raw normal-user) (cons 'formatted (if (= normal-user 0) "NOT a normal user account" "Normal user account"))))
        (cons 'temp-dup-user (list (cons 'raw temp-dup-user) (cons 'formatted (if (= temp-dup-user 0) "NOT a temp duplicate user account" "Temp duplicate user account"))))
        (cons 'password-required (list (cons 'raw password-required) (cons 'formatted (if (= password-required 0) "Password required" "NO password required"))))
        (cons 'homedir-required (list (cons 'raw homedir-required) (cons 'formatted (if (= homedir-required 0) "Homedir required" "NO homedir required"))))
        (cons 'enabled (list (cons 'raw enabled) (cons 'formatted (if (= enabled 0) "User account disabled" "User account enabled"))))
        (cons 'token (list (cons 'raw token) (cons 'formatted (fmt-hex token))))
        (cons 'hf-pulse (list (cons 'raw hf-pulse) (cons 'formatted (number->string hf-pulse))))
        (cons 'hf-random (list (cons 'raw hf-random) (cons 'formatted (number->string hf-random))))
        (cons 'index (list (cons 'raw index) (cons 'formatted (number->string index))))
        (cons 'serial (list (cons 'raw serial) (cons 'formatted (number->string serial))))
        (cons 'count (list (cons 'raw count) (cons 'formatted (number->string count))))
        (cons 'sid-size (list (cons 'raw sid-size) (cons 'formatted (number->string sid-size))))
        (cons 'hf-signature (list (cons 'raw hf-signature) (cons 'formatted (fmt-hex hf-signature))))
        (cons 'time (list (cons 'raw time) (cons 'formatted (number->string time))))
        (cons 'type (list (cons 'raw type) (cons 'formatted (number->string type))))
        (cons 'guid (list (cons 'raw guid) (cons 'formatted (fmt-bytes guid))))
        (cons 'hf-unknown8 (list (cons 'raw hf-unknown8) (cons 'formatted (fmt-hex hf-unknown8))))
        (cons 'ip (list (cons 'raw ip) (cons 'formatted (fmt-ipv4 ip))))
        (cons 'hf-unknown32 (list (cons 'raw hf-unknown32) (cons 'formatted (fmt-hex hf-unknown32))))
        (cons 'version (list (cons 'raw version) (cons 'formatted (number->string version))))
        (cons 'hf-data (list (cons 'raw hf-data) (cons 'formatted (fmt-bytes hf-data))))
        )))

    (catch (e)
      (err (str "SMB-LOGON parse error: " e)))))

;; dissect-smb-logon: parse SMB-LOGON from bytevector
;; Returns (ok fields-alist) or (err message)