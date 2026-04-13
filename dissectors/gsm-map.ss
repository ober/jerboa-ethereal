;; Do not modify this file. Changes will be overwritten.

;; jerboa-ethereal/dissectors/gsm-map.ss
;; Auto-generated from wireshark/epan/dissectors/packet-gsm_map.c

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
(def (dissect-gsm-map buffer)
  "GSM Mobile Application"
  (try
    (let* (
           (map-notification-to-calling-party (unwrap (read-u8 buffer 0)))
           (map-redirecting-presentation (unwrap (read-u8 buffer 0)))
           (map-notification-to-forwarding-party (unwrap (read-u8 buffer 0)))
           (map-extension (unwrap (read-u8 buffer 0)))
           (map-ext-qos-subscribed-pri (unwrap (read-u8 buffer 0)))
           (map-qos-max-sdu (unwrap (read-u32be buffer 0)))
           (map-max-brate-ulink (unwrap (read-u32be buffer 0)))
           (map-max-brate-dlink (unwrap (read-u32be buffer 0)))
           (map-qos-transfer-delay (unwrap (read-u8 buffer 0)))
           (map-guaranteed-max-brate-ulink (unwrap (read-u32be buffer 0)))
           (map-guaranteed-max-brate-dlink (unwrap (read-u32be buffer 0)))
           (map-qos-signalling-ind (unwrap (read-u8 buffer 0)))
           (map-qos-source-stat-desc (unwrap (read-u8 buffer 0)))
           (map-qos-max-bitrate-upl-ext (unwrap (read-u8 buffer 0)))
           (map-earp-pvi (unwrap (read-u8 buffer 0)))
           (map-earp-pl (unwrap (read-u8 buffer 0)))
           (map-earp-pci (unwrap (read-u8 buffer 0)))
           (map-cbs-coding-grp4-7-comp (unwrap (read-u8 buffer 0)))
           (map-cbs-coding-grp4-7-class-ind (unwrap (read-u8 buffer 0)))
           (map-address-digits (unwrap (slice buffer 1 1)))
           (map-qos-max-bitrate-downl-ext (unwrap (read-u8 buffer 1)))
           (map-qos-guar-bitrate-upl-ext (unwrap (read-u8 buffer 1)))
           (map-qos-guar-bitrate-downl-ext (unwrap (read-u8 buffer 2)))
           )

      (ok (list
        (cons 'map-notification-to-calling-party (list (cons 'raw map-notification-to-calling-party) (cons 'formatted (if (= map-notification-to-calling-party 0) "No notification" "Notification"))))
        (cons 'map-redirecting-presentation (list (cons 'raw map-redirecting-presentation) (cons 'formatted (if (= map-redirecting-presentation 0) "No presentation" "Presentation"))))
        (cons 'map-notification-to-forwarding-party (list (cons 'raw map-notification-to-forwarding-party) (cons 'formatted (if (= map-notification-to-forwarding-party 0) "No notification" "Notification"))))
        (cons 'map-extension (list (cons 'raw map-extension) (cons 'formatted (if (= map-extension 0) "False" "True"))))
        (cons 'map-ext-qos-subscribed-pri (list (cons 'raw map-ext-qos-subscribed-pri) (cons 'formatted (number->string map-ext-qos-subscribed-pri))))
        (cons 'map-qos-max-sdu (list (cons 'raw map-qos-max-sdu) (cons 'formatted (number->string map-qos-max-sdu))))
        (cons 'map-max-brate-ulink (list (cons 'raw map-max-brate-ulink) (cons 'formatted (number->string map-max-brate-ulink))))
        (cons 'map-max-brate-dlink (list (cons 'raw map-max-brate-dlink) (cons 'formatted (number->string map-max-brate-dlink))))
        (cons 'map-qos-transfer-delay (list (cons 'raw map-qos-transfer-delay) (cons 'formatted (number->string map-qos-transfer-delay))))
        (cons 'map-guaranteed-max-brate-ulink (list (cons 'raw map-guaranteed-max-brate-ulink) (cons 'formatted (number->string map-guaranteed-max-brate-ulink))))
        (cons 'map-guaranteed-max-brate-dlink (list (cons 'raw map-guaranteed-max-brate-dlink) (cons 'formatted (number->string map-guaranteed-max-brate-dlink))))
        (cons 'map-qos-signalling-ind (list (cons 'raw map-qos-signalling-ind) (cons 'formatted (if (= map-qos-signalling-ind 0) "Not optimised for signalling traffic" "Optimised for signalling traffic"))))
        (cons 'map-qos-source-stat-desc (list (cons 'raw map-qos-source-stat-desc) (cons 'formatted (number->string map-qos-source-stat-desc))))
        (cons 'map-qos-max-bitrate-upl-ext (list (cons 'raw map-qos-max-bitrate-upl-ext) (cons 'formatted (number->string map-qos-max-bitrate-upl-ext))))
        (cons 'map-earp-pvi (list (cons 'raw map-earp-pvi) (cons 'formatted (if (= map-earp-pvi 0) "False" "True"))))
        (cons 'map-earp-pl (list (cons 'raw map-earp-pl) (cons 'formatted (number->string map-earp-pl))))
        (cons 'map-earp-pci (list (cons 'raw map-earp-pci) (cons 'formatted (if (= map-earp-pci 0) "False" "True"))))
        (cons 'map-cbs-coding-grp4-7-comp (list (cons 'raw map-cbs-coding-grp4-7-comp) (cons 'formatted (if (= map-cbs-coding-grp4-7-comp 0) "The text is uncompressed" "The text is compressed using the compression algorithm defined in 3GPP TS 23.042"))))
        (cons 'map-cbs-coding-grp4-7-class-ind (list (cons 'raw map-cbs-coding-grp4-7-class-ind) (cons 'formatted (if (= map-cbs-coding-grp4-7-class-ind 0) "Bits 1 to 0 are reserved and have no message class meaning" "Bits 1 to 0 have a message class meaning"))))
        (cons 'map-address-digits (list (cons 'raw map-address-digits) (cons 'formatted (utf8->string map-address-digits))))
        (cons 'map-qos-max-bitrate-downl-ext (list (cons 'raw map-qos-max-bitrate-downl-ext) (cons 'formatted (number->string map-qos-max-bitrate-downl-ext))))
        (cons 'map-qos-guar-bitrate-upl-ext (list (cons 'raw map-qos-guar-bitrate-upl-ext) (cons 'formatted (number->string map-qos-guar-bitrate-upl-ext))))
        (cons 'map-qos-guar-bitrate-downl-ext (list (cons 'raw map-qos-guar-bitrate-downl-ext) (cons 'formatted (number->string map-qos-guar-bitrate-downl-ext))))
        )))

    (catch (e)
      (err (str "GSM-MAP parse error: " e)))))

;; dissect-gsm-map: parse GSM-MAP from bytevector
;; Returns (ok fields-alist) or (err message)