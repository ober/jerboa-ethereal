#!chezscheme
;; qt/dissect.ss — Self-contained PCAP dissection engine
;; Produces parsed-packet records with a layer tree for the Qt GUI.

(import (except (chezscheme)
                make-hash-table hash-table? sort sort!
                printf fprintf iota 1+ 1-
                partition make-date make-time
                path-extension path-absolute?
                with-input-from-string with-output-to-string)
        (jerboa prelude))

;; ── Data Structures ───────────────────────────────────────────────────────

(defrecord layer
  (name         ;; string: "Ethernet II", "IPv4", etc.
   fields        ;; list of (label . value-string) pairs
   start         ;; byte offset where this layer starts
   end))         ;; byte offset where this layer ends (exclusive)

(defrecord parsed-packet
  (index         ;; 0-based integer
   timestamp     ;; float seconds since epoch
   caplen        ;; captured length
   origlen       ;; original length
   data          ;; bytevector
   layers        ;; list of layer records (Ethernet first)
   src           ;; string: source address (IP or MAC)
   dst           ;; string: destination address
   protocol      ;; string: "TCP", "UDP", "DNS", etc.
   info))        ;; string: one-line summary

;; ── Safe Byte Reading ────────────────────────────────────────────────────

(define (u8-at buf off)
  (if (< off (bytevector-length buf))
      (bytevector-u8-ref buf off) 0))

(define (u16be-at buf off)
  (if (>= (+ off 2) (bytevector-length buf))
      0
      (bytevector-u16-ref buf off (endianness big))))

(define (u32be-at buf off)
  (if (>= (+ off 4) (bytevector-length buf))
      0
      (bytevector-u32-ref buf off (endianness big))))

(define (u16le-at buf off)
  (if (>= (+ off 2) (bytevector-length buf))
      0
      (bytevector-u16-ref buf off (endianness little))))

(define (u32le-at buf off)
  (if (>= (+ off 4) (bytevector-length buf))
      0
      (bytevector-u32-ref buf off (endianness little))))

;; ── Subvector Helper ─────────────────────────────────────────────────────
;; Chez Scheme's bytevector-copy takes only 1 arg; use bytevector-copy! for slicing.

(define (bv-slice bv start end)
  "Copy bv[start..end) into a fresh bytevector."
  (let* ([blen (bytevector-length bv)]
         [s    (max 0 start)]
         [e    (min blen end)]
         [len  (max 0 (- e s))]
         [r    (make-bytevector len)])
    (bytevector-copy! bv s r 0 len)
    r))

;; ── Format Helpers ────────────────────────────────────────────────────────

(define (fmt-mac buf off)
  (if (>= (+ off 6) (bytevector-length buf))
      "??:??:??:??:??:??"
      (format "~2,'0x:~2,'0x:~2,'0x:~2,'0x:~2,'0x:~2,'0x"
              (u8-at buf off)       (u8-at buf (+ off 1))
              (u8-at buf (+ off 2)) (u8-at buf (+ off 3))
              (u8-at buf (+ off 4)) (u8-at buf (+ off 5)))))

(define (fmt-ipv4 buf off)
  (format "~a.~a.~a.~a"
          (u8-at buf off)       (u8-at buf (+ off 1))
          (u8-at buf (+ off 2)) (u8-at buf (+ off 3))))

(define (fmt-ipv6 buf off)
  (if (> (+ off 16) (bytevector-length buf))
      "??"
      (apply string-append
        (let loop ([i 0] [acc '()])
          (if (= i 8)
              (reverse acc)
              (loop (+ i 1)
                    (cons (if (= i 0) "" ":")
                          (cons (format "~4,'0x" (u16be-at buf (+ off (* i 2))))
                                acc))))))))

(define (fmt-hex n digits)
  (let ([s (format (string-append "~" (number->string digits) ",'0x") n)])
    (string-append "0x" s)))

(define (fmt-flags-tcp flags)
  (string-join
    (filter (lambda (s) (not (string=? s "")))
      (list (if (not (zero? (bitwise-and flags #x01))) "FIN" "")
            (if (not (zero? (bitwise-and flags #x02))) "SYN" "")
            (if (not (zero? (bitwise-and flags #x04))) "RST" "")
            (if (not (zero? (bitwise-and flags #x08))) "PSH" "")
            (if (not (zero? (bitwise-and flags #x10))) "ACK" "")
            (if (not (zero? (bitwise-and flags #x20))) "URG" "")))
    ","))

(define (fmt-ipv4-n n)
  (format "~a.~a.~a.~a"
          (bitwise-and (bitwise-arithmetic-shift-right n 24) #xff)
          (bitwise-and (bitwise-arithmetic-shift-right n 16) #xff)
          (bitwise-and (bitwise-arithmetic-shift-right n  8) #xff)
          (bitwise-and n #xff)))

;; ── DNS Name Decoder ──────────────────────────────────────────────────────

(define (decode-dns-name buf off limit)
  "Decode a DNS name starting at off in buf; returns (name . bytes-consumed)"
  (let loop ([pos off] [parts '()] [jumped #f] [consumed 0])
    (if (>= pos limit)
        (cons (string-join (reverse parts) ".") consumed)
        (let ([len (u8-at buf pos)])
          (cond
            [(= len 0)
             ;; End of name
             (cons (string-join (reverse parts) ".")
                   (if jumped consumed (- (+ pos 1) off)))]
            [(= (bitwise-and len #xc0) #xc0)
             ;; Pointer compression
             (if (>= (+ pos 2) limit)
                 (cons (string-join (reverse parts) ".") consumed)
                 (let ([ptr (bitwise-ior
                               (bitwise-arithmetic-shift-left
                                 (bitwise-and len #x3f) 8)
                               (u8-at buf (+ pos 1)))])
                   (let ([result (decode-dns-name buf ptr limit)])
                     (cons (let ([existing (string-join (reverse parts) ".")])
                             (if (string=? existing "")
                                 (car result)
                                 (string-append existing "." (car result))))
                           (if jumped consumed (- (+ pos 2) off))))))]
            [else
             ;; Regular label
             (let ([label (if (> (+ pos 1 len) limit)
                              "?"
                              (utf8->string
                                (bv-slice buf (+ pos 1) (+ pos 1 len))))])
               (loop (+ pos 1 len)
                     (cons label parts)
                     jumped
                     (if jumped consumed (+ (- pos off) 1 len))))])))))

;; ── Ethernet Dissector ────────────────────────────────────────────────────

(define (dissect-ethernet buf start)
  "Returns (layer . next-info) where next-info = (ethertype . payload-start)"
  (if (< (bytevector-length buf) (+ start 14))
      (cons (make-layer "Ethernet" '(("(truncated)" . "")) start (bytevector-length buf)) #f)
      (let* ([dst-mac  (fmt-mac buf start)]
             [src-mac  (fmt-mac buf (+ start 6))]
             [ethertype (u16be-at buf (+ start 12))]
             [etype-str (cond [(= ethertype #x0800) "IPv4 (0x0800)"]
                              [(= ethertype #x0806) "ARP (0x0806)"]
                              [(= ethertype #x86DD) "IPv6 (0x86DD)"]
                              [(= ethertype #x8100) "802.1Q VLAN (0x8100)"]
                              [else (format "0x~4,'0x" ethertype)])]
             [fields (list (cons "Destination" dst-mac)
                           (cons "Source"      src-mac)
                           (cons "Type"        etype-str))]
             [l (make-layer "Ethernet II" fields start (+ start 14))])
        (cons l (cons ethertype (+ start 14))))))

;; ── ARP Dissector ─────────────────────────────────────────────────────────

(define (dissect-arp buf start)
  (if (< (bytevector-length buf) (+ start 28))
      (make-layer "ARP" '(("(truncated)" . "")) start (bytevector-length buf))
      (let* ([op     (u16be-at buf (+ start 6))]
             [op-str (if (= op 1) "Request (1)" "Reply (2)")]
             [sha    (fmt-mac buf (+ start 8))]
             [spa    (fmt-ipv4 buf (+ start 14))]
             [tha    (fmt-mac buf (+ start 18))]
             [tpa    (fmt-ipv4 buf (+ start 24))]
             [fields (list (cons "Hardware Type"      "Ethernet (1)")
                           (cons "Protocol Type"      "IPv4 (0x0800)")
                           (cons "Operation"          op-str)
                           (cons "Sender MAC"         sha)
                           (cons "Sender IP"          spa)
                           (cons "Target MAC"         tha)
                           (cons "Target IP"          tpa))])
        (make-layer "Address Resolution Protocol" fields start (+ start 28)))))

;; ── IPv4 Dissector ────────────────────────────────────────────────────────

(define (dissect-ipv4 buf start)
  "Returns (layer . (proto . payload-start))"
  (let* ([len (bytevector-length buf)])
    (if (< len (+ start 20))
        (cons (make-layer "IPv4" '(("(truncated)" . "")) start len) #f)
        (let* ([ver-ihl  (u8-at buf start)]
               [ihl      (* (bitwise-and ver-ihl #x0f) 4)]
               [dscp     (bitwise-arithmetic-shift-right (u8-at buf (+ start 1)) 2)]
               [total-len (u16be-at buf (+ start 2))]
               [id       (u16be-at buf (+ start 4))]
               [frag     (u16be-at buf (+ start 6))]
               [ttl      (u8-at buf (+ start 8))]
               [proto    (u8-at buf (+ start 9))]
               [proto-str (cond [(= proto 1)  "ICMP (1)"]
                                [(= proto 2)  "IGMP (2)"]
                                [(= proto 6)  "TCP (6)"]
                                [(= proto 17) "UDP (17)"]
                                [(= proto 41) "IPv6 (41)"]
                                [(= proto 58) "ICMPv6 (58)"]
                                [else (format "~a" proto)])]
               [src-ip   (fmt-ipv4 buf (+ start 12))]
               [dst-ip   (fmt-ipv4 buf (+ start 16))]
               [flags    (bitwise-arithmetic-shift-right frag 13)]
               [frag-off (bitwise-and frag #x1fff)]
               [fields   (list (cons "Version"         "4")
                               (cons "Header Length"   (format "~a bytes" ihl))
                               (cons "DSCP"            (format "~a" dscp))
                               (cons "Total Length"    (format "~a" total-len))
                               (cons "Identification"  (fmt-hex id 4))
                               (cons "Flags"           (format "0x~x" flags))
                               (cons "Fragment Offset" (format "~a" frag-off))
                               (cons "TTL"             (format "~a" ttl))
                               (cons "Protocol"        proto-str)
                               (cons "Source"          src-ip)
                               (cons "Destination"     dst-ip))]
               [payload-start (+ start ihl)]
               [l (make-layer "Internet Protocol Version 4" fields start payload-start)])
          (cons l (cons proto payload-start))))))

;; ── IPv6 Dissector ────────────────────────────────────────────────────────

(define (dissect-ipv6 buf start)
  "Returns (layer . (next-hdr . payload-start))"
  (if (< (bytevector-length buf) (+ start 40))
      (cons (make-layer "IPv6" '(("(truncated)" . "")) start (bytevector-length buf)) #f)
      (let* ([vtc      (u32be-at buf start)]
             [flow     (bitwise-and vtc #xfffff)]
             [pay-len  (u16be-at buf (+ start 4))]
             [next-hdr (u8-at buf (+ start 6))]
             [hop-lim  (u8-at buf (+ start 7))]
             [src-ip   (fmt-ipv6 buf (+ start 8))]
             [dst-ip   (fmt-ipv6 buf (+ start 24))]
             [nh-str   (cond [(= next-hdr 6)  "TCP (6)"]
                             [(= next-hdr 17) "UDP (17)"]
                             [(= next-hdr 58) "ICMPv6 (58)"]
                             [(= next-hdr 43) "Routing (43)"]
                             [(= next-hdr 44) "Fragment (44)"]
                             [else (format "~a" next-hdr)])]
             [fields   (list (cons "Version"          "6")
                             (cons "Traffic Class"    (format "~a" (bitwise-and (bitwise-arithmetic-shift-right vtc 20) #xff)))
                             (cons "Flow Label"       (fmt-hex flow 5))
                             (cons "Payload Length"   (format "~a" pay-len))
                             (cons "Next Header"      nh-str)
                             (cons "Hop Limit"        (format "~a" hop-lim))
                             (cons "Source"           src-ip)
                             (cons "Destination"      dst-ip))]
             [l (make-layer "Internet Protocol Version 6" fields start (+ start 40))])
        (cons l (cons next-hdr (+ start 40))))))

;; ── ICMP Dissector ────────────────────────────────────────────────────────

(define (dissect-icmp buf start)
  (if (< (bytevector-length buf) (+ start 8))
      (make-layer "ICMP" '(("(truncated)" . "")) start (bytevector-length buf))
      (let* ([type    (u8-at buf start)]
             [code    (u8-at buf (+ start 1))]
             [chksum  (u16be-at buf (+ start 2))]
             [type-str (cond [(= type 0)  "Echo Reply (0)"]
                             [(= type 3)  "Destination Unreachable (3)"]
                             [(= type 8)  "Echo Request (8)"]
                             [(= type 11) "Time Exceeded (11)"]
                             [else (format "~a" type)])]
             [fields  (list (cons "Type"     type-str)
                            (cons "Code"     (format "~a" code))
                            (cons "Checksum" (fmt-hex chksum 4)))]
             [fields  (if (or (= type 0) (= type 8))
                          (append fields
                                  (list (cons "Identifier" (fmt-hex (u16be-at buf (+ start 4)) 4))
                                        (cons "Sequence"   (format "~a" (u16be-at buf (+ start 6))))))
                          fields)])
        (make-layer "Internet Control Message Protocol" fields start (bytevector-length buf)))))

;; ── TCP Dissector ─────────────────────────────────────────────────────────

(define (dissect-tcp buf start)
  "Returns (layer sport dport payload-start)"
  (if (< (bytevector-length buf) (+ start 20))
      (list (make-layer "TCP" '(("(truncated)" . "")) start (bytevector-length buf)) 0 0 (bytevector-length buf))
      (let* ([sport    (u16be-at buf start)]
             [dport    (u16be-at buf (+ start 2))]
             [seq      (u32be-at buf (+ start 4))]
             [ack      (u32be-at buf (+ start 8))]
             [off-res  (u8-at buf (+ start 12))]
             [data-off (* (bitwise-arithmetic-shift-right off-res 4) 4)]
             [flags    (u8-at buf (+ start 13))]
             [win      (u16be-at buf (+ start 14))]
             [chksum   (u16be-at buf (+ start 16))]
             [fields   (list (cons "Source Port"      (format "~a" sport))
                             (cons "Destination Port" (format "~a" dport))
                             (cons "Sequence Number"  (format "~a" seq))
                             (cons "Acknowledgment"   (format "~a" ack))
                             (cons "Header Length"    (format "~a bytes" data-off))
                             (cons "Flags"            (fmt-flags-tcp flags))
                             (cons "Window Size"      (format "~a" win))
                             (cons "Checksum"         (fmt-hex chksum 4)))]
             [payload-start (+ start data-off)]
             [l (make-layer "Transmission Control Protocol" fields start payload-start)])
        (list l sport dport payload-start))))

;; ── UDP Dissector ─────────────────────────────────────────────────────────

(define (dissect-udp buf start)
  "Returns (layer sport dport payload-start)"
  (if (< (bytevector-length buf) (+ start 8))
      (list (make-layer "UDP" '(("(truncated)" . "")) start (bytevector-length buf)) 0 0 (bytevector-length buf))
      (let* ([sport   (u16be-at buf start)]
             [dport   (u16be-at buf (+ start 2))]
             [length  (u16be-at buf (+ start 4))]
             [chksum  (u16be-at buf (+ start 6))]
             [fields  (list (cons "Source Port"      (format "~a" sport))
                            (cons "Destination Port" (format "~a" dport))
                            (cons "Length"           (format "~a" length))
                            (cons "Checksum"         (fmt-hex chksum 4)))]
             [l (make-layer "User Datagram Protocol" fields start (+ start 8))])
        (list l sport dport (+ start 8)))))

;; ── DNS Dissector ─────────────────────────────────────────────────────────

(define (dissect-dns buf start)
  (let* ([blen  (bytevector-length buf)]
         [limit blen])
    (if (< blen (+ start 12))
        (make-layer "DNS" '(("(truncated)" . "")) start blen)
        (let* ([txid  (u16be-at buf start)]
               [flags (u16be-at buf (+ start 2))]
               [qr    (bitwise-arithmetic-shift-right flags 15)]
               [qdcnt (u16be-at buf (+ start 4))]
               [ancnt (u16be-at buf (+ start 6))]
               [type-str (if (zero? qr) "Query" "Response")]
               [opcode (bitwise-and (bitwise-arithmetic-shift-right flags 11) #xf)]
               [rcode  (bitwise-and flags #xf)]
               [fields (list (cons "Transaction ID" (fmt-hex txid 4))
                             (cons "Type"           type-str)
                             (cons "Opcode"         (format "~a" opcode))
                             (cons "Questions"      (format "~a" qdcnt))
                             (cons "Answers"        (format "~a" ancnt))
                             (cons "Response Code"  (format "~a" rcode)))]
               ;; Try to decode the first question name
               [fields (if (and (> qdcnt 0) (< (+ start 12) limit))
                           (let ([result (decode-dns-name buf (+ start 12) limit)])
                             (append fields
                                     (list (cons "Query Name" (car result)))))
                           fields)])
          (make-layer "Domain Name System" fields start blen)))))

;; ── DHCP Dissector ────────────────────────────────────────────────────────

(define (dissect-dhcp buf start)
  (if (< (bytevector-length buf) (+ start 240))
      (make-layer "DHCP" '(("(truncated)" . "")) start (bytevector-length buf))
      (let* ([op     (u8-at buf start)]
             [op-str (if (= op 1) "Boot Request (1)" "Boot Reply (2)")]
             [ciaddr (fmt-ipv4 buf (+ start 12))]
             [yiaddr (fmt-ipv4 buf (+ start 16))]
             [siaddr (fmt-ipv4 buf (+ start 20))]
             [chaddr (fmt-mac buf (+ start 28))]
             [fields (list (cons "Message Type"  op-str)
                           (cons "Client IP"     ciaddr)
                           (cons "Your IP"       yiaddr)
                           (cons "Server IP"     siaddr)
                           (cons "Client MAC"    chaddr))])
        (make-layer "Dynamic Host Configuration Protocol" fields start (bytevector-length buf)))))

;; ── NTP Dissector ─────────────────────────────────────────────────────────

(define (dissect-ntp buf start)
  (if (< (bytevector-length buf) (+ start 48))
      (make-layer "NTP" '(("(truncated)" . "")) start (bytevector-length buf))
      (let* ([b0     (u8-at buf start)]
             [li     (bitwise-arithmetic-shift-right b0 6)]
             [ver    (bitwise-and (bitwise-arithmetic-shift-right b0 3) #x7)]
             [mode   (bitwise-and b0 #x7)]
             [mode-str (case mode
                         [(1) "Symmetric Active"] [(2) "Symmetric Passive"]
                         [(3) "Client"] [(4) "Server"] [(5) "Broadcast"]
                         [else "Unknown"])]
             [stratum (u8-at buf (+ start 1))]
             [fields (list (cons "Leap Indicator" (format "~a" li))
                           (cons "Version"        (format "~a" ver))
                           (cons "Mode"           mode-str)
                           (cons "Stratum"        (format "~a" stratum)))])
        (make-layer "Network Time Protocol" fields start (bytevector-length buf)))))

;; ── SSH Dissector ─────────────────────────────────────────────────────────

(define (dissect-ssh-banner buf start)
  "Detect SSH banner if present"
  (let ([blen (bytevector-length buf)])
    (if (< (+ start 4) blen)
        (let ([prefix (utf8->string (bv-slice buf start (min (+ start 4) blen)))])
          (if (string=? prefix "SSH-")
              (let* ([end   (let lp ([i start])
                              (if (or (>= i blen) (= (bytevector-u8-ref buf i) 10))
                                  i (lp (+ i 1))))]
                     [banner (utf8->string (bv-slice buf start end))])
                (make-layer "SSH" (list (cons "Banner" banner)) start end))
              #f))
        #f)))

;; ── Application Layer Dissection ─────────────────────────────────────────

(define (dissect-app-layer buf payload-start sport dport proto-str)
  "Try to identify and dissect application layer protocol"
  (let ([port (min sport dport)]
        [blen (bytevector-length buf)])
    (cond
      ;; DNS (port 53)
      [(or (= sport 53) (= dport 53))
       (dissect-dns buf payload-start)]
      ;; DHCP (ports 67/68)
      [(or (= sport 67) (= dport 67)
           (= sport 68) (= dport 68))
       (dissect-dhcp buf payload-start)]
      ;; NTP (port 123)
      [(or (= sport 123) (= dport 123))
       (dissect-ntp buf payload-start)]
      ;; SSH (port 22) — detect banner
      [(or (= sport 22) (= dport 22))
       (dissect-ssh-banner buf payload-start)]
      ;; HTTP (port 80) — show first line
      [(or (= sport 80) (= dport 80))
       (if (< payload-start blen)
           (let* ([end (let lp ([i payload-start])
                         (if (or (>= i blen) (= (u8-at buf i) 13) (= (u8-at buf i) 10))
                             i (lp (+ i 1))))]
                  [line (if (> end payload-start)
                            (utf8->string (bv-slice buf payload-start end))
                            "(empty)")])
             (make-layer "HyperText Transfer Protocol" (list (cons "Request" line)) payload-start blen))
           #f)]
      [else #f])))

;; ── Packet Summary ────────────────────────────────────────────────────────

(define (classify-packet layers)
  "Derive src, dst, protocol, and info string from layers"
  (let* ([eth-layer (and (pair? layers) (car layers))]
         [ip-layer  (and (pair? layers) (pair? (cdr layers)) (cadr layers))]
         [xport-layer (and ip-layer (pair? (cddr layers)) (caddr layers))]
         [app-layer (and xport-layer (pair? (cdddr layers)) (cadddr layers))]
         ;; Extract src/dst from IP layer if present
         [src (or (and ip-layer
                       (let ([f (assoc "Source" (layer-fields ip-layer))])
                         (and f (cdr f))))
                  (and eth-layer
                       (let ([f (assoc "Source" (layer-fields eth-layer))])
                         (and f (cdr f))))
                  "?")]
         [dst (or (and ip-layer
                       (let ([f (assoc "Destination" (layer-fields ip-layer))])
                         (and f (cdr f))))
                  (and eth-layer
                       (let ([f (assoc "Destination" (layer-fields eth-layer))])
                         (and f (cdr f))))
                  "?")]
         ;; Protocol: prefer app layer name, else transport, else network
         [proto (cond
                  [app-layer   (layer-name app-layer)]
                  [xport-layer (cond
                                 [(string-prefix? "Transmission" (layer-name xport-layer)) "TCP"]
                                 [(string-prefix? "User Datagram" (layer-name xport-layer)) "UDP"]
                                 [(string-prefix? "Internet Control" (layer-name xport-layer)) "ICMP"]
                                 [else (layer-name xport-layer)])]
                  [ip-layer    (layer-name ip-layer)]
                  [eth-layer   "Ethernet"]
                  [else "?"])]
         ;; Build one-line info
         [info (cond
                 [app-layer
                  (let ([fields (layer-fields app-layer)])
                    (cond
                      ;; DNS
                      [(and (assoc "Type" fields) (assoc "Query Name" fields))
                       (format "~a ~a"
                               (cdr (assoc "Type" fields))
                               (cdr (assoc "Query Name" fields)))]
                      ;; HTTP
                      [(assoc "Request" fields)
                       (let ([req (cdr (assoc "Request" fields))])
                         (if (> (string-length req) 60)
                             (string-append (substring req 0 60) "...")
                             req))]
                      ;; SSH banner
                      [(assoc "Banner" fields)
                       (cdr (assoc "Banner" fields))]
                      ;; NTP
                      [(assoc "Mode" fields)
                       (format "NTP ~a" (cdr (assoc "Mode" fields)))]
                      [else (layer-name app-layer)]))]
                 [xport-layer
                  (let ([fields (layer-fields xport-layer)])
                    (cond
                      ;; TCP with flags
                      [(assoc "Flags" fields)
                       (let ([sport-f (assoc "Source Port" fields)]
                             [dport-f (assoc "Destination Port" fields)]
                             [flags-f (assoc "Flags" fields)])
                         (format "~a → ~a [~a]"
                                 (if sport-f (cdr sport-f) "?")
                                 (if dport-f (cdr dport-f) "?")
                                 (if flags-f (cdr flags-f) "")))]
                      ;; UDP
                      [(assoc "Source Port" fields)
                       (let ([sport-f (assoc "Source Port" fields)]
                             [dport-f (assoc "Destination Port" fields)])
                         (format "~a → ~a"
                                 (if sport-f (cdr sport-f) "?")
                                 (if dport-f (cdr dport-f) "?")))]
                      [else (layer-name xport-layer)]))]
                 ;; ARP
                 [(and eth-layer (string-prefix? "Address Resolution" (layer-name eth-layer)))
                  (let ([fields (layer-fields eth-layer)])
                    (or (and (assoc "Operation" fields)
                             (format "ARP ~a" (cdr (assoc "Operation" fields))))
                        "ARP"))]
                 [ip-layer
                  (let ([proto-f (assoc "Protocol" (layer-fields ip-layer))])
                    (or (and proto-f (cdr proto-f)) ""))]
                 [else ""])])
    (values src dst proto info)))

;; ── Full Packet Dissector ─────────────────────────────────────────────────

(def (dissect-one buf)
  "Dissect one raw packet bytevector; returns list of layers"
  (let ([blen (bytevector-length buf)])
    (if (< blen 14)
        (list (make-layer "Raw" (list (cons "Length" (format "~a" blen))) 0 blen))
        (let* ([eth-result (dissect-ethernet buf 0)]
               [eth-layer  (car eth-result)]
               [next-info  (cdr eth-result)]
               [ethertype  (and next-info (car next-info))]
               [payload    (and next-info (cdr next-info))])
          (cond
            ;; ARP
            [(and ethertype (= ethertype #x0806))
             (list eth-layer (dissect-arp buf payload))]
            ;; IPv4
            [(and ethertype (= ethertype #x0800))
             (let ([ipv4-result (dissect-ipv4 buf payload)])
               (if (not ipv4-result)
                   (list eth-layer)
                   (let* ([ipv4-layer   (car ipv4-result)]
                          [proto-info   (cdr ipv4-result)]
                          [ip-proto     (car proto-info)]
                          [ip-payload   (cdr proto-info)])
                     (cond
                       ;; ICMP
                       [(= ip-proto 1)
                        (list eth-layer ipv4-layer (dissect-icmp buf ip-payload))]
                       ;; TCP
                       [(= ip-proto 6)
                        (let ([tcp-result (dissect-tcp buf ip-payload)])
                          (let* ([tcp-layer    (car tcp-result)]
                                 [sport        (cadr tcp-result)]
                                 [dport        (caddr tcp-result)]
                                 [tcp-payload  (cadddr tcp-result)]
                                 [app-layer    (dissect-app-layer buf tcp-payload sport dport "TCP")])
                            (filter (lambda (x) x)
                                    (list eth-layer ipv4-layer tcp-layer app-layer))))]
                       ;; UDP
                       [(= ip-proto 17)
                        (let ([udp-result (dissect-udp buf ip-payload)])
                          (let* ([udp-layer   (car udp-result)]
                                 [sport       (cadr udp-result)]
                                 [dport       (caddr udp-result)]
                                 [udp-payload (cadddr udp-result)]
                                 [app-layer   (dissect-app-layer buf udp-payload sport dport "UDP")])
                            (filter (lambda (x) x)
                                    (list eth-layer ipv4-layer udp-layer app-layer))))]
                       ;; IGMP or other
                       [else (list eth-layer ipv4-layer)]))))]
            ;; IPv6
            [(and ethertype (= ethertype #x86DD))
             (let ([ipv6-result (dissect-ipv6 buf payload)])
               (if (not ipv6-result)
                   (list eth-layer)
                   (let* ([ipv6-layer  (car ipv6-result)]
                          [proto-info  (cdr ipv6-result)]
                          [next-hdr    (car proto-info)]
                          [ipv6-payload (cdr proto-info)])
                     (cond
                       [(= next-hdr 6)
                        (let ([tcp-result (dissect-tcp buf ipv6-payload)])
                          (let* ([tcp-layer   (car tcp-result)]
                                 [sport       (cadr tcp-result)]
                                 [dport       (caddr tcp-result)]
                                 [tcp-payload (cadddr tcp-result)]
                                 [app-layer   (dissect-app-layer buf tcp-payload sport dport "TCP")])
                            (filter (lambda (x) x)
                                    (list eth-layer ipv6-layer tcp-layer app-layer))))]
                       [(= next-hdr 17)
                        (let ([udp-result (dissect-udp buf ipv6-payload)])
                          (let* ([udp-layer   (car udp-result)]
                                 [sport       (cadr udp-result)]
                                 [dport       (caddr udp-result)]
                                 [udp-payload (cadddr udp-result)]
                                 [app-layer   (dissect-app-layer buf udp-payload sport dport "UDP")])
                            (filter (lambda (x) x)
                                    (list eth-layer ipv6-layer udp-layer app-layer))))]
                       [else (list eth-layer ipv6-layer)]))))]
            ;; Unknown ethertype
            [else (list eth-layer)])))))

;; ── PCAP File Reader ──────────────────────────────────────────────────────

(def (read-pcap-file path)
  "Read a PCAP file and return list of parsed-packet records.
   Returns (ok packets) or (err message)."
  (try
    (let* ([port     (open-file-input-port path)]
           [packets  (unwind-protect
                       (read-pcap-packets port)
                       (close-port port))])
      (ok packets))
    (catch (e)
      (err (str "Failed to read PCAP: "
                (if (condition? e)
                    (with-output-to-string (lambda () (display-condition e)))
                    e))))))

(define (read-pcap-packets port)
  "Read all packets from an open PCAP port."
  (let* ([hdr     (get-bytevector-n port 24)]
         [_       (when (eof-object? hdr) (error 'read-pcap "Empty file"))]
         ;; Check magic: little-endian (d4 c3 b2 a1) or big-endian (a1 b2 c3 d4)
         [magic   (bytevector-u32-ref hdr 0 (endianness little))]
         [le?     (= magic #xa1b2c3d4)]
         [_       (unless (or le? (= magic #xd4c3b2a1))
                    (error 'read-pcap "Not a PCAP file"))])
    (let loop ([idx 0] [acc '()])
      (let ([pkt-hdr (get-bytevector-n port 16)])
        (if (or (eof-object? pkt-hdr)
                (< (bytevector-length pkt-hdr) 16))
            (reverse acc)
            (let* ([ts-sec    (bytevector-u32-ref pkt-hdr 0 (endianness little))]
                   [ts-usec   (bytevector-u32-ref pkt-hdr 4 (endianness little))]
                   [caplen    (bytevector-u32-ref pkt-hdr 8 (endianness little))]
                   [origlen   (bytevector-u32-ref pkt-hdr 12 (endianness little))]
                   [data      (get-bytevector-n port caplen)])
              (if (or (eof-object? data)
                      (< (bytevector-length data) caplen))
                  (reverse acc)
                  (let* ([timestamp (+ ts-sec (/ ts-usec 1000000.0))]
                         [layers    (dissect-one data)]
                         [summary   (call-with-values
                                      (lambda () (classify-packet layers))
                                      list)]
                         [src       (list-ref summary 0)]
                         [dst       (list-ref summary 1)]
                         [proto     (list-ref summary 2)]
                         [info      (list-ref summary 3)]
                         [pkt       (make-parsed-packet
                                      idx timestamp caplen origlen
                                      data layers src dst proto info)])
                    (loop (+ idx 1) (cons pkt acc))))))))))

;; ── Hex Dump Formatter ────────────────────────────────────────────────────

(def (format-hex-dump buf)
  "Format bytevector as Wireshark-style hex+ASCII dump string."
  (let* ([blen  (bytevector-length buf)]
         [lines (let loop ([off 0] [acc '()])
                  (if (>= off blen)
                      (reverse acc)
                      (let* ([row-end (min (+ off 16) blen)]
                             [row-len (- row-end off)]
                             ;; Hex part: two columns of 8 bytes each
                             [hex-str (let hloop ([i off] [h '()])
                                        (if (>= i row-end)
                                            (apply string-append (reverse h))
                                            (hloop (+ i 1)
                                                   (cons (if (= (- i off) 8) "  " " ")
                                                         (cons (format "~2,'0x" (bytevector-u8-ref buf i))
                                                               h)))))]
                             ;; Pad hex to fixed width (3*16 + 1 = 49 chars)
                             [hex-padded (let ([l (string-length hex-str)])
                                          (string-append hex-str
                                                         (make-string (max 0 (- 49 l)) #\space)))]
                             ;; ASCII part
                             [asc-str (let aloop ([i off] [a '()])
                                        (if (>= i row-end)
                                            (list->string (reverse a))
                                            (let ([b (bytevector-u8-ref buf i)])
                                              (aloop (+ i 1)
                                                     (cons (if (and (>= b 32) (< b 127))
                                                               (integer->char b)
                                                               #\.)
                                                           a)))))]
                             [line (format "~4,'0x ~a  ~a" off hex-padded asc-str)])
                        (loop row-end (cons line acc)))))])
    (string-join lines "\n")))
