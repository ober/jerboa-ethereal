;; jerboa-ethereal/dissectors/dns.ss
;; RFC 1035: DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
;;
;; DNS header parsing and basic query/response handling
;; Supports UDP and TCP transport
;; Note: Full domain name decompression is complex; basic version extracts header only

(import (jerboa prelude))
;; ── Protocol Helpers (from lib/dissector/protocol.ss) ────────────────────

(def (read-u8 buf offset)
  (if (>= offset (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u8-ref buf offset))))

(def (read-u16be buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u16-ref buf offset (endianness big)))))

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

(def (slice buf offset len)
  (if (> (+ offset len) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (let ((result (make-bytevector len)))
            (bytevector-copy! buf offset result 0 len)
            result))))

(def (extract-bits val mask shift)
  (bitwise-arithmetic-shift-right (bitwise-and val mask) shift))

(def (validate pred msg)
  (if pred (ok #t) (err msg)))

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

(def (fmt-port port)
  (number->string port))

(def (ip-protocol->protocol num)
  (case num
    ((1) 'icmp) ((6) 'tcp) ((17) 'udp)
    ((41) 'ipv6) ((58) 'icmpv6) (else #f)))



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
    (unwrap (validate (>= (bytevector-length buffer) 12)
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

;; ── Domain Name Decompression ────────────────────────────────────

(def (decompress-domain-name buffer offset)
  "Decompress DNS domain name from buffer starting at offset
   Returns (name new-offset) or (err message)
   Handles both literal names and message compression pointers (RFC 1035)"

  (let loop ((offset offset)
             (labels '())
             (max-iterations 255))

    (if (<= max-iterations 0)
        (err "Domain name decompression: maximum iterations exceeded")
        (if (>= offset (bytevector-length buffer))
            (err "Domain name: offset beyond buffer end")
            (let ((len-byte-res (read-u8 buffer offset)))
              (if (err? len-byte-res)
                  len-byte-res
                  (let ((len-byte (unwrap len-byte-res)))
                    (cond
                      ;; End of name (length 0)
                      ((= len-byte 0)
                       (ok (cons (string-join (reverse labels) ".") (+ offset 1))))

                      ;; Pointer (high 2 bits are 11)
                      ((>= len-byte #xC0)
                       (if (>= (+ offset 1) (bytevector-length buffer))
                           (err "Domain name: incomplete pointer")
                           (let ((ptr-res (read-u16be buffer offset)))
                             (if (err? ptr-res)
                                 ptr-res
                                 (let* ((ptr-word (unwrap ptr-res))
                                        (ptr-offset (bitwise-and ptr-word #x3FFF)))
                                   ;; Recursively decompress at pointer offset, then continue
                                   (match (decompress-domain-name buffer ptr-offset)
                                     ((ok (cons ptr-name _))
                                      (ok (cons (if (null? labels)
                                                   ptr-name
                                                   (str (string-join (reverse labels) ".") "." ptr-name))
                                               (+ offset 2))))
                                     ((err e) (err e))))))))

                      ;; Normal label (length < 64)
                      ((< len-byte 64)
                       (if (> (+ offset 1 len-byte) (bytevector-length buffer))
                           (err "Domain name: label extends beyond buffer")
                           (let ((label-bytes (unwrap (slice buffer (+ offset 1) len-byte))))
                             (try
                               (let ((label-str (bytevector->string label-bytes
                                                                    (make-transcoder (utf-8-codec)))))
                                 (loop (+ offset 1 len-byte)
                                      (cons label-str labels)
                                      (- max-iterations 1)))
                               (catch (e) (err "Domain name: invalid label encoding"))))))

                      ;; Invalid (reserved bits)
                      (else
                       (err (str "Domain name: invalid length byte " len-byte))))))))))

;; ── Record Extraction ──────────────────────────────────────────────

(def (extract-dns-question buffer offset)
  "Extract single DNS question from buffer
   Returns (name type class new-offset) or error"

  (match (decompress-domain-name buffer offset)
    ((ok (cons qname new-offset))
     (if (> (+ new-offset 4) (bytevector-length buffer))
         (err "Question: incomplete type/class fields")
         (let ((type-res (read-u16be buffer new-offset))
               (class-res (read-u16be buffer (+ new-offset 2))))
           (match (list type-res class-res)
             ((list (ok qtype) (ok qclass))
              (ok (list qname qtype qclass (+ new-offset 4))))
             (err "Question: invalid type or class"))))))
    ((err e) (err (str "Question: " e)))))

(def (extract-dns-answer buffer offset)
  "Extract single DNS answer RR from buffer
   Returns (name type class ttl rdlength rdata new-offset) or error"

  (match (decompress-domain-name buffer offset)
    ((ok (cons rname new-offset))
     (if (> (+ new-offset 10) (bytevector-length buffer))
         (err "Answer: incomplete type/class/ttl/rdlen fields")
         (let ((type-res (read-u16be buffer new-offset))
               (class-res (read-u16be buffer (+ new-offset 2)))
               (ttl-res (read-u32be buffer (+ new-offset 4)))
               (rdlen-res (read-u16be buffer (+ new-offset 8))))
           (match (list type-res class-res ttl-res rdlen-res)
             ((list (ok rtype) (ok rclass) (ok rttl) (ok rdlen))
              (if (> (+ new-offset 10 rdlen) (bytevector-length buffer))
                  (err "Answer: rdata extends beyond buffer")
                  (let ((rdata (unwrap (slice buffer (+ new-offset 10) rdlen))))
                    (ok (list rname rtype rclass rttl rdlen rdata
                             (+ new-offset 10 rdlen))))))
             (err "Answer: invalid fields"))))))
    ((err e) (err (str "Answer: " e)))))

;; ── Exported API ───────────────────────────────────────────────────────

;; dissect-dns: main entry point - parses 12-byte header and flags
;; decompress-domain-name: RFC 1035 compression pointer handling
;; extract-dns-question: parse DNS question (name, type, class)
;; extract-dns-answer: parse DNS answer RR (name, type, class, TTL, rdata)
;; format-dns-opcode: opcode formatter
;; format-dns-rcode: response code formatter
;; format-dns-type: record type formatter
;; format-dns-class: record class formatter
;;
;; Phase 6 Complete: Full DNS dissection with domain name decompression,
;;                   RFC 1035 compression pointers, and record extraction
