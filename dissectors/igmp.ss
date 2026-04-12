;; jerboa-ethereal/dissectors/igmp.ss
;; RFC 3376: Internet Group Management Protocol, Version 3
;;
;; Handles IGMP membership reports and queries
;; Versions supported: IGMPv1, IGMPv2, IGMPv3

(import (jerboa prelude)
        (lib dissector protocol))

;; ── IGMP Message Type Formatters ───────────────────────────────────────

(def (format-igmp-type type-val)
  "Format IGMP message type as readable string"
  (case type-val
    ((0x11) "Membership Query")
    ((0x12) "Version 1 Membership Report")
    ((0x16) "Version 2 Membership Report")
    ((0x17) "Version 2 Leave Group")
    ((0x22) "Version 3 Membership Report")
    (else (str "Type 0x" (string-pad (number->string type-val 16) 2 #\0)))))

(def (format-igmp-mode mode-val)
  "Format IGMPv3 filter mode"
  (case mode-val
    ((1) "Include")
    ((2) "Exclude")
    (else (str "Mode " mode-val))))

;; ── Core IGMP Dissector ────────────────────────────────────────────────

(def (dissect-igmp buffer)
  "Parse IGMP message from bytevector
   Returns (ok fields) or (err message)

   Structure (8-byte minimum):
   [0]     type (message type: Query, Report, Leave)
   [1]     max response time (for queries, or reserved for reports)
   [2:4)   checksum
   [4:8)   group address (multicast group IP)
   [8:)    IGMPv3-specific fields (membership records)"

  (try
    ;; Validate minimum size
    (_ (unwrap (validate (>= (bytevector-length buffer) 8)
                         "IGMP message too short (< 8 bytes)")))

    (let* ((type-res (read-u8 buffer 0))
           (type-val (unwrap type-res))

           (max-resp-time-res (read-u8 buffer 1))
           (max-resp-time (unwrap max-resp-time-res))

           (checksum-res (read-u16be buffer 2))
           (checksum (unwrap checksum-res))

           (group-addr-res (read-u32be buffer 4))
           (group-addr (unwrap group-addr-res)))

      ;; Parse version-specific fields
      (let ((version-fields (parse-igmp-version type-val buffer)))
        (ok `((type . ((raw . ,type-val)
                      (formatted . ,(format-igmp-type type-val))))
              (max-response-time . ,max-resp-time)
              (checksum . ((raw . ,checksum)
                          (formatted . ,(fmt-hex checksum))))
              (group-address . ((raw . ,group-addr)
                               (formatted . ,(fmt-ipv4 group-addr))))
              ,@version-fields))))

    ;; Error handling
    (catch (e)
      (err (str "IGMP parse error: " e)))))

;; ── Version-Specific Parsing ──────────────────────────────────────────

(def (parse-igmp-version type-val buffer)
  "Parse IGMPv1, v2, or v3 specific fields
   Returns alist of additional fields"

  (case type-val
    ;; Membership Query (0x11)
    ((0x11)
     (if (>= (bytevector-length buffer) 12)
         (try
           ;; IGMPv3 Query has additional fields starting at offset 8
           (let* ((resv-s-qrv-res (read-u8 buffer 8))
                  (resv-s-qrv (unwrap resv-s-qrv-res))
                  (s-flag (extract-bits resv-s-qrv #x08 3))
                  (qrv (extract-bits resv-s-qrv #x07 0))
                  (qqic-res (read-u8 buffer 9))
                  (qqic (unwrap qqic-res))
                  (num-sources-res (read-u16be buffer 10))
                  (num-sources (unwrap num-sources-res)))
             `((suppress-router-processing . ,s-flag)
               (querier-robustness-variable . ,qrv)
               (querier-query-interval . ,qqic)
               (number-of-sources . ,num-sources)))
           (catch (e)
             ;; Fallback for v1/v2 (no additional fields)
             '()))
         '()))

    ;; Membership Reports (v1, v2, v3)
    ((0x12) ; v1 Report
     '()) ; No extra fields

    ((0x16) ; v2 Report
     '()) ; No extra fields

    ((0x22) ; v3 Report
     (if (>= (bytevector-length buffer) 12)
         (try
           (let* ((reserved-res (read-u16be buffer 8))
                  (reserved (unwrap reserved-res))
                  (num-records-res (read-u16be buffer 10))
                  (num-records (unwrap num-records-res)))
             `((reserved . ,reserved)
               (number-of-group-records . ,num-records)))
           (catch (e) '()))
         '()))

    ;; Leave Group (0x17)
    ((0x17)
     '()) ; Same as v2 Report, no extra fields

    ;; Default
    (else '())))

;; ── Exported API ───────────────────────────────────────────────────────

;; dissect-igmp: main entry point
;; format-igmp-type: type formatter
;; format-igmp-mode: mode formatter for v3 records
