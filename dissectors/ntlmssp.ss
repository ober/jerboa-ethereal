;; packet-ntlmssp.c
;; Add-on for better NTLM v1/v2 handling
;; Copyright 2009, 2012 Matthieu Patou <mat@matws.net>
;; Routines for NTLM Secure Service Provider
;; Devin Heitmueller <dheitmueller@netilla.com>
;; Copyright 2003, Tim Potter <tpot@samba.org>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/ntlmssp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-ntlmssp.c

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
(def (dissect-ntlmssp buffer)
  "NTLM Secure Service Provider"
  (try
    (let* (
           (string-len (unwrap (read-u16be buffer 0)))
           (verf-vers (unwrap (read-u32be buffer 0)))
           (auth (unwrap (slice buffer 0 8)))
           (string-maxlen (unwrap (read-u16be buffer 2)))
           (string-offset (unwrap (read-u32be buffer 4)))
           (verf-body (unwrap (slice buffer 4 1)))
           (blob-len (unwrap (read-u16be buffer 8)))
           (blob-maxlen (unwrap (read-u16be buffer 10)))
           (blob-offset (unwrap (read-u32be buffer 12)))
           (version-major (unwrap (read-u8 buffer 16)))
           (version-minor (unwrap (read-u8 buffer 16)))
           (version-build-number (unwrap (read-u16be buffer 16)))
           (version-ntlm-current-revision (unwrap (read-u8 buffer 16)))
           (ntlmv2-response (unwrap (slice buffer 16 1)))
           (ntlmv2-response-ntproofstr (unwrap (slice buffer 16 16)))
           (NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-Flags (unwrap (read-u32le buffer 20)))
           (NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-LM-PRESENT (extract-bits NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-Flags 0x0 0))
           (NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-NT-PRESENT (extract-bits NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-Flags 0x0 0))
           (NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-REMOVED (extract-bits NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-Flags 0x0 0))
           (NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-CREDKEY-PRESENT (extract-bits NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-Flags 0x0 0))
           (NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-SHA-PRESENT (extract-bits NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-Flags 0x0 0))
           (NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-CredentialKey (unwrap (slice buffer 24 1)))
           (NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-EncryptedCredsSize (unwrap (read-u32be buffer 28)))
           (ntlmv2-response-rversion (unwrap (read-u8 buffer 32)))
           (NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-EncryptedCreds (unwrap (slice buffer 32 1)))
           (ntlmv2-response-hirversion (unwrap (read-u8 buffer 33)))
           (ntlmv2-response-chal (unwrap (slice buffer 48 8)))
           (ntlmv2-response-pad (unwrap (slice buffer 60 1)))
           (challenge-target-info-len (unwrap (read-u16be buffer 64)))
           (challenge-target-info-maxlen (unwrap (read-u16be buffer 66)))
           (challenge-target-info-offset (unwrap (read-u32be buffer 68)))
           (ntlm-server-challenge (unwrap (slice buffer 76 8)))
           (reserved (unwrap (slice buffer 84 8)))
           (negotiate-flags (unwrap (read-u32le buffer 92)))
           (ntlmv2-response-z (unwrap (slice buffer 96 8)))
           (message-integrity-code (unwrap (slice buffer 104 16)))
           )

      (ok (list
        (cons 'string-len (list (cons 'raw string-len) (cons 'formatted (number->string string-len))))
        (cons 'verf-vers (list (cons 'raw verf-vers) (cons 'formatted (number->string verf-vers))))
        (cons 'auth (list (cons 'raw auth) (cons 'formatted (utf8->string auth))))
        (cons 'string-maxlen (list (cons 'raw string-maxlen) (cons 'formatted (number->string string-maxlen))))
        (cons 'string-offset (list (cons 'raw string-offset) (cons 'formatted (number->string string-offset))))
        (cons 'verf-body (list (cons 'raw verf-body) (cons 'formatted (fmt-bytes verf-body))))
        (cons 'blob-len (list (cons 'raw blob-len) (cons 'formatted (number->string blob-len))))
        (cons 'blob-maxlen (list (cons 'raw blob-maxlen) (cons 'formatted (number->string blob-maxlen))))
        (cons 'blob-offset (list (cons 'raw blob-offset) (cons 'formatted (number->string blob-offset))))
        (cons 'version-major (list (cons 'raw version-major) (cons 'formatted (number->string version-major))))
        (cons 'version-minor (list (cons 'raw version-minor) (cons 'formatted (number->string version-minor))))
        (cons 'version-build-number (list (cons 'raw version-build-number) (cons 'formatted (number->string version-build-number))))
        (cons 'version-ntlm-current-revision (list (cons 'raw version-ntlm-current-revision) (cons 'formatted (number->string version-ntlm-current-revision))))
        (cons 'ntlmv2-response (list (cons 'raw ntlmv2-response) (cons 'formatted (fmt-bytes ntlmv2-response))))
        (cons 'ntlmv2-response-ntproofstr (list (cons 'raw ntlmv2-response-ntproofstr) (cons 'formatted (fmt-bytes ntlmv2-response-ntproofstr))))
        (cons 'NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-Flags (list (cons 'raw NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-Flags) (cons 'formatted (fmt-hex NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-Flags))))
        (cons 'NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-LM-PRESENT (list (cons 'raw NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-LM-PRESENT) (cons 'formatted (if (= NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-LM-PRESENT 0) "Not set" "Set"))))
        (cons 'NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-NT-PRESENT (list (cons 'raw NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-NT-PRESENT) (cons 'formatted (if (= NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-NT-PRESENT 0) "Not set" "Set"))))
        (cons 'NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-REMOVED (list (cons 'raw NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-REMOVED) (cons 'formatted (if (= NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-REMOVED 0) "Not set" "Set"))))
        (cons 'NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-CREDKEY-PRESENT (list (cons 'raw NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-CREDKEY-PRESENT) (cons 'formatted (if (= NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-CREDKEY-PRESENT 0) "Not set" "Set"))))
        (cons 'NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-SHA-PRESENT (list (cons 'raw NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-SHA-PRESENT) (cons 'formatted (if (= NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-FLAG-SHA-PRESENT 0) "Not set" "Set"))))
        (cons 'NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-CredentialKey (list (cons 'raw NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-CredentialKey) (cons 'formatted (fmt-bytes NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-CredentialKey))))
        (cons 'NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-EncryptedCredsSize (list (cons 'raw NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-EncryptedCredsSize) (cons 'formatted (number->string NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-EncryptedCredsSize))))
        (cons 'ntlmv2-response-rversion (list (cons 'raw ntlmv2-response-rversion) (cons 'formatted (number->string ntlmv2-response-rversion))))
        (cons 'NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-EncryptedCreds (list (cons 'raw NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-EncryptedCreds) (cons 'formatted (fmt-bytes NTLM-REMOTE-SUPPLEMENTAL-CREDENTIAL-EncryptedCreds))))
        (cons 'ntlmv2-response-hirversion (list (cons 'raw ntlmv2-response-hirversion) (cons 'formatted (number->string ntlmv2-response-hirversion))))
        (cons 'ntlmv2-response-chal (list (cons 'raw ntlmv2-response-chal) (cons 'formatted (fmt-bytes ntlmv2-response-chal))))
        (cons 'ntlmv2-response-pad (list (cons 'raw ntlmv2-response-pad) (cons 'formatted (fmt-bytes ntlmv2-response-pad))))
        (cons 'challenge-target-info-len (list (cons 'raw challenge-target-info-len) (cons 'formatted (number->string challenge-target-info-len))))
        (cons 'challenge-target-info-maxlen (list (cons 'raw challenge-target-info-maxlen) (cons 'formatted (number->string challenge-target-info-maxlen))))
        (cons 'challenge-target-info-offset (list (cons 'raw challenge-target-info-offset) (cons 'formatted (number->string challenge-target-info-offset))))
        (cons 'ntlm-server-challenge (list (cons 'raw ntlm-server-challenge) (cons 'formatted (fmt-bytes ntlm-server-challenge))))
        (cons 'reserved (list (cons 'raw reserved) (cons 'formatted (fmt-bytes reserved))))
        (cons 'negotiate-flags (list (cons 'raw negotiate-flags) (cons 'formatted (fmt-hex negotiate-flags))))
        (cons 'ntlmv2-response-z (list (cons 'raw ntlmv2-response-z) (cons 'formatted (fmt-bytes ntlmv2-response-z))))
        (cons 'message-integrity-code (list (cons 'raw message-integrity-code) (cons 'formatted (fmt-bytes message-integrity-code))))
        )))

    (catch (e)
      (err (str "NTLMSSP parse error: " e)))))

;; dissect-ntlmssp: parse NTLMSSP from bytevector
;; Returns (ok fields-alist) or (err message)