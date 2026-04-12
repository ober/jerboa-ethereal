;; jerboa-ethereal/dissectors/ssh.ss
;; RFC 4251: The Secure Shell (SSH) Protocol Architecture
;;
;; Basic SSH protocol parsing - unencrypted protocol header analysis
;; Full message decryption is crypto-intensive and handled separately

(import (jerboa prelude)
        (lib dissector protocol))

;; ── SSH Protocol Message Type Formatter ────────────────────────────────────

(def (format-ssh-message-type msg-type)
  "Format SSH message type code"
  (case msg-type
    ((1) "SSH_MSG_DISCONNECT")
    ((2) "SSH_MSG_IGNORE")
    ((3) "SSH_MSG_UNIMPLEMENTED")
    ((4) "SSH_MSG_DEBUG")
    ((5) "SSH_MSG_SERVICE_REQUEST")
    ((6) "SSH_MSG_SERVICE_ACCEPT")
    ((20) "SSH_MSG_KEXINIT")
    ((21) "SSH_MSG_NEWKEYS")
    ((30) "SSH_MSG_KEXDH_INIT")
    ((31) "SSH_MSG_KEXDH_REPLY")
    ((50) "SSH_MSG_USERAUTH_REQUEST")
    ((51) "SSH_MSG_USERAUTH_FAILURE")
    ((52) "SSH_MSG_USERAUTH_SUCCESS")
    ((53) "SSH_MSG_USERAUTH_BANNER")
    ((60) "SSH_MSG_USERAUTH_PASSWD_CHANGEREQ")
    ((80) "SSH_MSG_GLOBAL_REQUEST")
    ((81) "SSH_MSG_REQUEST_SUCCESS")
    ((82) "SSH_MSG_REQUEST_FAILURE")
    ((90) "SSH_MSG_CHANNEL_OPEN")
    ((91) "SSH_MSG_CHANNEL_OPEN_CONFIRMATION")
    ((92) "SSH_MSG_CHANNEL_OPEN_FAILURE")
    ((93) "SSH_MSG_CHANNEL_WINDOW_ADJUST")
    ((94) "SSH_MSG_CHANNEL_DATA")
    ((95) "SSH_MSG_CHANNEL_EXTENDED_DATA")
    ((96) "SSH_MSG_CHANNEL_EOF")
    ((97) "SSH_MSG_CHANNEL_CLOSE")
    ((98) "SSH_MSG_CHANNEL_REQUEST")
    ((99) "SSH_MSG_CHANNEL_SUCCESS")
    ((100) "SSH_MSG_CHANNEL_FAILURE")
    (else (str "Type " msg-type))))

(def (format-ssh-version version-string)
  "Format SSH protocol version string
   Format: SSH-protocolversion-softwareversion"
  (if (string? version-string)
      version-string
      "Unknown"))

;; ── Core SSH Dissector ────────────────────────────────────────────────────

(def (dissect-ssh buffer)
  "Parse SSH protocol from bytevector
   Returns (ok fields) or (err message)

   SSH has two phases:
   1. Unencrypted protocol exchange (version strings, algorithms)
   2. Encrypted packet exchange

   This dissector handles:
   - SSH version identification string (first line)
   - Packet header (for encrypted packets)
   - Basic protocol structure

   Structure:
   - Identification string: 'SSH-<protocolversion>-<softwareversion>\\r\\n'
   - Then encrypted packets with structure:
     [0:4)   packet length
     [4]     padding length
     [5:)    payload"

  (try
    ;; Minimum 11 bytes for SSH identification
    (_ (unwrap (validate (>= (bytevector-length buffer) 5)
                         "SSH packet too short")))

    ;; Check if this is an identification string or encrypted packet
    (let ((first-bytes (bytevector->list (bytevector-copy buffer 0 (min 4 (bytevector-length buffer))))))
      (cond
        ;; Unencrypted identification string: starts with 'SSH-'
        ((and (>= (bytevector-length buffer) 4)
              (= (bytevector-u8-ref buffer 0) 83)  ; 'S'
              (= (bytevector-u8-ref buffer 1) 83)  ; 'S'
              (= (bytevector-u8-ref buffer 2) 72)  ; 'H'
              (= (bytevector-u8-ref buffer 3) 45)) ; '-'

         ;; Extract version string (up to CRLF or buffer end)
         (let ((version-end (let loop ((i 0))
                             (cond
                               ((>= i (bytevector-length buffer)) i)
                               ((and (= (bytevector-u8-ref buffer i) 13)  ; CR
                                     (< (+ i 1) (bytevector-length buffer))
                                     (= (bytevector-u8-ref buffer (+ i 1)) 10))  ; LF
                                i)
                               (else (loop (+ i 1)))))))

           (let ((version-bytes (unwrap (slice buffer 0 version-end)))
                 (version-str (try
                               (bytevector->string version-bytes (make-transcoder (utf-8-codec)))
                               (catch (e) "Unable to decode version string"))))

             (ok `((protocol . "SSH")
                   (type . "Identification String")
                   (version . ((raw . ,version-bytes)
                              (formatted . ,version-str)))
                   (size . ,(bytevector-length buffer)))))))

        ;; Encrypted packet: parse header
        ((>= (bytevector-length buffer) 5)

         (let* ((pkt-len-res (read-u32be buffer 0))
                (pkt-len (unwrap pkt-len-res))

                (pad-len-res (read-u8 buffer 4))
                (pad-len (unwrap pad-len-res)))

           (ok `((protocol . "SSH")
                 (type . "Encrypted Packet")
                 (packet-length . ,pkt-len)
                 (padding-length . ,pad-len)
                 (payload-length . ,(max 0 (- pkt-len pad-len 1)))
                 (encrypted . #t)
                 (size . ,(bytevector-length buffer))))))

        ;; Unknown format
        (else
         (err "Invalid SSH packet format"))))

    ;; Error handling
    (catch (e)
      (err (str "SSH parse error: " e)))))

;; ── Exported API ───────────────────────────────────────────────────────────

;; dissect-ssh: main entry point
;; format-ssh-message-type: message type formatter
;; format-ssh-version: version string formatter
;;
;; Note: This is BASIC SSH parsing for identification and packet structure.
;; Full SSH message parsing requires decryption and is protocol-dependent.
