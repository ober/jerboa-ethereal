;; jerboa-ethereal/dissectors/dns.ss
;; RFC 1035: DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
;;
;; DNS header parsing and basic query/response handling
;; Supports UDP and TCP transport
;; Note: Full domain name decompression is complex; basic version extracts header only

(import (jerboa prelude)
        (lib dissector protocol))

;; ── DNS Opcode Formatter ──────────────────────────────────────────────

(def (format-dns-opcode opcode-val)
  "Format DNS operation code"
  (case opcode-val
    ((0) "Standard Query")
    ((1) "Inverse Query (IQUERY) - obsolete")
    ((2) "Server Status Request (STATUS)")
    ((3) "Reserved")
    ((4) "Notify")
    ((5) "Update (DNSSEC)")
    (else (str "Opcode " opcode-val))))

(def (format-dns-rcode rcode-val)
  "Format DNS response code"
  (case rcode-val
    ((0) "No Error")
    ((1) "Format Error")
    ((2) "Server Failure")
    ((3) "Name Error (NXDOMAIN)")
    ((4) "Not Implemented")
    ((5) "Query Refused")
    ((6) "Name Exists When It Should Not")
    ((7) "RR Set Exists When It Should Not")
    ((8) "RR Set That Should Exist Does Not")
    ((9) "Server Not Authoritative")
    ((10) "Name Not in Zone")
    ((16) "DNSSEC Bad Old Signature (BADSIG)")
    ((17) "DNSSEC Bad Signature (BADKEY)")
    ((18) "DNSSEC Bad Time (BADTIME)")
    ((19) "Bad TKEY Mode")
    ((20) "Duplicate Key Name")
    ((21) "Bad Algorithm Name")
    (else (str "RCode " rcode-val))))

(def (format-dns-type type-val)
  "Format DNS resource record type"
  (case type-val
    ((1) "A (IPv4 Address)")
    ((2) "NS (Name Server)")
    ((3) "MD (Mail Destination)")
    ((4) "MF (Mail Forwarder)")
    ((5) "CNAME (Canonical Name)")
    ((6) "SOA (Start of Authority)")
    ((7) "MB (Mailbox)")
    ((8) "MG (Mail Group)")
    ((9) "MR (Mail Rename)")
    ((10) "NULL")
    ((11) "WKS (Well Known Service)")
    ((12) "PTR (Pointer)")
    ((13) "HINFO (Host Info)")
    ((14) "MINFO (Mailbox Info)")
    ((15) "MX (Mail Exchange)")
    ((16) "TXT (Text)")
    ((28) "AAAA (IPv6 Address)")
    ((33) "SRV (Service)")
    ((35) "NAPTR (Naming Authority Pointer)")
    ((37) "CERT (Certificate)")
    ((39) "DNAME (Delegation Name)")
    ((41) "OPT (Option)")
    ((42) "APL (Address Prefix List)")
    ((43) "DS (Delegation Signer)")
    ((46) "RRSIG (RRSIG)")
    ((47) "NSEC")
    ((48) "DNSKEY (DNS Key)")
    ((50) "NSEC3")
    ((51) "NSEC3PARAM")
    ((255) "ANY (All types)")
    ((32769) "TKEY (Transaction Key)")
    ((32770) "TSIG (Transaction Signature)")
    ((32771) "IXFR (Incremental Zone Transfer)")
    ((32772) "AXFR (Zone Transfer)")
    ((32773) "MAILB (Mail Box)")
    ((32774) "MAILA (Mail Agent)")
    (else (str "Type " type-val))))

(def (format-dns-class class-val)
  "Format DNS resource record class"
  (case class-val
    ((1) "IN (Internet)")
    ((2) "CS (CSNET)")
    ((3) "CH (CHAOS)")
    ((4) "HS (Hesiod)")
    ((255) "ANY (Any class)")
    (else (str "Class " class-val))))

;; ── Core DNS Dissector ────────────────────────────────────────────────

(def (dissect-dns buffer)
  "Parse DNS message from bytevector
   Returns (ok fields) or (err message)

   Structure (12-byte header minimum):
   [0:2)   transaction ID
   [2:4)   flags (QR, Opcode, AA, TC, RD, RA, Z, AD, CD, RCode)
   [4:6)   question count
   [6:8)   answer count
   [8:10)  authority count
   [10:12) additional count
   [12:)   questions, answers, authority, additional sections"

  (try
    ;; Validate minimum size
    (_ (unwrap (validate (>= (bytevector-length buffer) 12)
                         "DNS message too short (< 12 bytes)")))

    (let* ((transaction-id-res (read-u16be buffer 0))
           (transaction-id (unwrap transaction-id-res))

           (flags-res (read-u16be buffer 2))
           (flags (unwrap flags-res))

           ;; Parse flag bits
           (qr-flag (extract-bits flags #x8000 15))
           (opcode (extract-bits flags #x7800 11))
           (aa-flag (extract-bits flags #x0400 10))
           (tc-flag (extract-bits flags #x0200 9))
           (rd-flag (extract-bits flags #x0100 8))
           (ra-flag (extract-bits flags #x0080 7))
           (z-flag (extract-bits flags #x0040 6))
           (ad-flag (extract-bits flags #x0020 5))
           (cd-flag (extract-bits flags #x0010 4))
           (rcode (extract-bits flags #x000F 0))

           (question-count-res (read-u16be buffer 4))
           (question-count (unwrap question-count-res))

           (answer-count-res (read-u16be buffer 6))
           (answer-count (unwrap answer-count-res))

           (authority-count-res (read-u16be buffer 8))
           (authority-count (unwrap authority-count-res))

           (additional-count-res (read-u16be buffer 10))
           (additional-count (unwrap additional-count-res)))

      (ok `((transaction-id . ((raw . ,transaction-id)
                              (formatted . ,(fmt-hex transaction-id))))
            (is-response . ,qr-flag)
            (opcode . ((raw . ,opcode)
                      (formatted . ,(format-dns-opcode opcode))))
            (authoritative-answer . ,aa-flag)
            (truncated . ,tc-flag)
            (recursion-desired . ,rd-flag)
            (recursion-available . ,ra-flag)
            (authentic-data . ,ad-flag)
            (checking-disabled . ,cd-flag)
            (response-code . ((raw . ,rcode)
                             (formatted . ,(format-dns-rcode rcode))))
            (question-count . ,question-count)
            (answer-count . ,answer-count)
            (authority-count . ,authority-count)
            (additional-count . ,additional-count)
            (payload . ,(if (> (bytevector-length buffer) 12)
                           (unwrap (slice buffer 12 (- (bytevector-length buffer) 12)))
                           #f)))))

    ;; Error handling
    (catch (e)
      (err (str "DNS parse error: " e)))))

;; ── Export Helpers ────────────────────────────────────────────────────

(def (extract-dns-question buffer offset)
  "Extract single DNS question from buffer
   Returns (question-name question-type question-class new-offset) or error"
  ;; Note: Full implementation requires domain name decompression
  ;; This is a stub for the header-only version
  (values #f 0 1 offset))

(def (extract-dns-answer buffer offset)
  "Extract single DNS answer RR from buffer
   Returns (name type class ttl rdlength rdata new-offset) or error"
  ;; Note: Full implementation requires domain name decompression
  ;; This is a stub for the header-only version
  (values #f 0 1 0 0 #f offset))

;; ── Exported API ───────────────────────────────────────────────────────

;; dissect-dns: main entry point
;; format-dns-opcode: opcode formatter
;; format-dns-rcode: response code formatter
;; format-dns-type: record type formatter
;; format-dns-class: record class formatter
;;
;; Note: Full DNS dissection (including domain name decompression,
;;       question/answer/authority/additional sections) is complex
;;       and will be implemented in Phase 6.
;;       This version handles the 12-byte header and flags only.
