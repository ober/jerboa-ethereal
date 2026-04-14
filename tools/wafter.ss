#!chezscheme
;; wafter - PCAP analyzer tool
;; Phase 7: Static binary, full protocol dissection

(import (except (chezscheme)
                make-hash-table hash-table?
                sort sort!
                printf fprintf
                path-extension path-absolute?
                with-input-from-string with-output-to-string
                iota 1+ 1-
                partition
                make-date make-time
                meta atom?)
        (jerboa prelude)
        (std pcap))

(def wafter-version "0.7.0")

(def (show-version)
  (displayln (str "wafter " wafter-version))
  (displayln "PCAP packet analyzer — jerboa-ethereal")
  (displayln "Protocols: Ethernet, IPv4, IPv6, ARP, TCP, UDP, ICMP, ICMPv6, IGMP, DNS, DHCP, NTP, SSH"))

;; ── Dissection Helpers ─────────────────────────────────────────────────────

(def (read-u8 buf offset)
  (if (>= offset (bytevector-length buf))
      (err "EOF")
      (ok (bytevector-u8-ref buf offset))))

(def (read-u16be buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err "EOF")
      (ok (bytevector-u16-ref buf offset (endianness big)))))

(def (read-u32be buf offset)
  (if (> (+ offset 4) (bytevector-length buf))
      (err "EOF")
      (ok (bytevector-u32-ref buf offset (endianness big)))))

;; ── PCAP Reader ───────────────────────────────────────────────────────────

(def (read-pcap-packets file-path)
  (let ((port (open-file-input-port file-path)))
    (unwind-protect
      (begin
        ;; Skip PCAP global header (24 bytes)
        (get-bytevector-n port 24)
        (let loop ((packets '()))
          (let ((pkt-header (get-bytevector-n port 16)))
            (if (eof-object? pkt-header)
                (reverse packets)
                (let* ((ts-sec (bytevector-u32-ref pkt-header 0 (endianness little)))
                       (capt-len (bytevector-u32-ref pkt-header 8 (endianness little)))
                       (pkt-data (get-bytevector-n port capt-len)))
                  (if (eof-object? pkt-data)
                      (reverse packets)
                      (loop (cons (cons ts-sec pkt-data) packets))))))))
      (close-port port))))

;; ── Display ────────────────────────────────────────────────────────────────

(def (show-help)
  (displayln "")
  (displayln "wafter - PCAP packet analyzer")
  (displayln "════════════════════════════════════════════════════════════")
  (displayln "")
  (displayln "Usage:")
  (displayln "  ./wafter-musl <pcap-file> <command>")
  (displayln "  ./wafter-musl capture <iface> [N]    (live capture)")
  (displayln "  ./wafter-musl interfaces              (list interfaces)")
  (displayln "  scheme wafter.ss <pcap-file> <command>")
  (displayln "")
  (displayln "Commands (pcap file):")
  (displayln "  stats       - Show packet statistics")
  (displayln "  list N      - List first N packets with protocol info")
  (displayln "  protocols   - Count packets by EtherType")
  (displayln "  --version   - Show version")
  (displayln "")
  (displayln "Commands (live capture — requires root/CAP_NET_RAW):")
  (displayln "  capture <iface> [N]  - Capture N live packets (default: 20)")
  (displayln "  interfaces           - List available network interfaces")
  (displayln "")
  (displayln "Example:")
  (displayln "  ./wafter-musl capture.pcap stats")
  (displayln "  ./wafter-musl capture.pcap list 20")
  (displayln "  sudo ./wafter-musl capture eth0 50")
  (displayln "  ./wafter-musl interfaces")
  (displayln "")
  (displayln "Supported protocols:")
  (displayln "  Layer 2: Ethernet, ARP")
  (displayln "  Layer 3: IPv4, IPv6, ICMP, ICMPv6")
  (displayln "  Layer 4: TCP, UDP")
  (displayln "  Application: DNS, HTTP, HTTPS, SSH, DHCP, NTP")
  (displayln "")
  (displayln ""))

;; ── Main ────────────────────────────────────────────────────────────────

;; ── Inline packet description (multi-layer) ─────────────────────────────────

(def (fmt-ipv4 addr)
  (let ((b0 (bitwise-arithmetic-shift-right addr 24))
        (b1 (bitwise-and (bitwise-arithmetic-shift-right addr 16) 255))
        (b2 (bitwise-and (bitwise-arithmetic-shift-right addr 8) 255))
        (b3 (bitwise-and addr 255)))
    (str b0 "." b1 "." b2 "." b3)))

(def (port->app port)
  "Map well-known port to application name, or #f."
  (case port
    ((20 21)       "FTP")
    ((22)          "SSH")
    ((23)          "Telnet")
    ((25 587 465)  "SMTP")
    ((53)          "DNS")
    ((67 68)       "DHCP")
    ((80 8080)     "HTTP")
    ((110)         "POP3")
    ((123)         "NTP")
    ((143)         "IMAP")
    ((161 162)     "SNMP")
    ((179)         "BGP")
    ((443 8443)    "HTTPS")
    ((514)         "Syslog")
    ((587)         "SMTP")
    ((993)         "IMAPS")
    ((995)         "POP3S")
    ((1194)        "OpenVPN")
    ((1433)        "MSSQL")
    ((3306)        "MySQL")
    ((3389)        "RDP")
    ((5432)        "PostgreSQL")
    ((5900)        "VNC")
    ((6379)        "Redis")
    ((8883)        "MQTT")
    ((9200 9300)   "Elasticsearch")
    (else #f)))

(def (app-label sport dport)
  "Return \" [AppName]\" if either port is well-known, else \"\"."
  (let ((app (or (port->app dport) (port->app sport))))
    (if app (str " [" app "]") "")))

(def (describe-transport data l4-off proto src-str dst-str)
  "Format L4 layer: TCP/UDP with ports, ICMP, or proto number."
  (case proto
    ((6)                                       ; TCP
     (if (< (bytevector-length data) (+ l4-off 4))
         (str "IPv4/TCP " src-str " → " dst-str)
         (let ((sport (unwrap (read-u16be data l4-off)))
               (dport (unwrap (read-u16be data (+ l4-off 2)))))
           (str "IPv4/TCP " src-str ":" sport " → " dst-str ":" dport
                (app-label sport dport)))))
    ((17)                                      ; UDP
     (if (< (bytevector-length data) (+ l4-off 4))
         (str "IPv4/UDP " src-str " → " dst-str)
         (let ((sport (unwrap (read-u16be data l4-off)))
               (dport (unwrap (read-u16be data (+ l4-off 2)))))
           (str "IPv4/UDP " src-str ":" sport " → " dst-str ":" dport
                (app-label sport dport)))))
    ((1) (str "IPv4/ICMP " src-str " → " dst-str))
    ((2) (str "IPv4/IGMP " src-str " → " dst-str))
    ((58) (str "IPv6/ICMPv6 " src-str " → " dst-str))
    (else (str "IPv4/proto" proto " " src-str " → " dst-str))))

(def (describe-ipv4 data ip-off)
  "Parse IPv4 header starting at ip-off; return description string."
  (if (< (bytevector-length data) (+ ip-off 20))
      "IPv4 (truncated)"
      (let* ((ihl     (* (bitwise-and (bytevector-u8-ref data ip-off) #x0F) 4))
             (proto   (bytevector-u8-ref data (+ ip-off 9)))
             (src-ip  (unwrap (read-u32be data (+ ip-off 12))))
             (dst-ip  (unwrap (read-u32be data (+ ip-off 16))))
             (l4-off  (+ ip-off ihl)))
        (describe-transport data l4-off proto (fmt-ipv4 src-ip) (fmt-ipv4 dst-ip)))))

(def (describe-packet data)
  "Return a one-line human-readable description of an Ethernet frame."
  (let ((len (bytevector-length data)))
    (if (< len 14)
        (str "short (" len " bytes)")
        (let ((etype (if (ok? (read-u16be data 12)) (unwrap (read-u16be data 12)) 0)))
          (case etype
            ((#x0800) (describe-ipv4 data 14))
            ((#x0806) "ARP")
            ((#x86DD) "IPv6")
            (else (str "0x" (format "~4,'0x" etype))))))))

;; ── Live capture ────────────────────────────────────────────────────────────

(def (wafter-list-interfaces)
  (if (pcap-available?)
      (let ((ifaces (pcap-interfaces)))
        (displayln "Network interfaces:")
        (for ((iface ifaces))
          (displayln (str "  " iface))))
      (displayln "Live capture not available (libjerboa_native not loaded)")))

(def (wafter-live-capture args)
  ;; args = ("capture" iface [count])
  (if (not (pcap-available?))
      (displayln "Live capture not available (libjerboa_native not loaded)")
      (let* ((iface (cadr args))
             (count (if (>= (length args) 3)
                        (or (string->number (caddr args)) 20)
                        20)))
        (displayln (str "Capturing " count " packets on " iface
                        " (requires root/CAP_NET_RAW)..."))
        (displayln "")
        (try
          (let ((cap (pcap-open iface))
                (n 0))
            (unwind-protect
              (let loop ()
                (when (< n count)
                  (let ((pkt (pcap-next cap)))
                    (when pkt
                      (let* ((data    (vector-ref pkt 0))
                             (ts-sec  (vector-ref pkt 1))
                             (ts-usec (vector-ref pkt 2))
                             (len     (bytevector-length data))
                             (desc    (describe-packet data)))
                        (printf "  ~a.~6,'0d  ~5d bytes  ~a\n"
                                ts-sec ts-usec len desc)
                        (set! n (+ n 1))
                        (loop))))))
              (pcap-close cap))
            (displayln (str "\nCaptured " n " packet(s).")))
          (catch (e)
            (let ((msg (cond
                         ((and (condition? e) (message-condition? e))
                          (condition-message e))
                         (else (str e)))))
              (displayln (str "Capture error: " msg))
              (when (or (string-contains msg "ermission")
                        (string-contains msg "peration not"))
                (displayln "  Hint: live capture requires root — try: sudo ./wafter-macos capture ..."))))))))

;; wafter-main is called by the C entry point in the static binary
(def (wafter-main)
  (let ((args (command-line-arguments)))
    (cond
      ((and (= (length args) 1) (string=? (car args) "--version"))
       (show-version))
      ((and (= (length args) 1) (string=? (car args) "interfaces"))
       (wafter-list-interfaces))
      ((and (>= (length args) 2) (string=? (car args) "capture"))
       (wafter-live-capture args))
      ((< (length args) 2)
       (show-help))
      (else
       (wafter-run (car args) (cadr args) args)))))

(def (wafter-run pcap-file command args)
  (try
    (displayln (str "Reading PCAP: " pcap-file))
    (let ((packets (read-pcap-packets pcap-file)))
      (displayln (str "Loaded " (length packets) " packets\n"))
      (wafter-dispatch command args packets))
    (catch (e)
      (displayln (str "Error: " e))
      (show-help))))

(def (wafter-dispatch command args packets)
  (case (string->symbol command)
    ((stats)
     (displayln "PCAP Statistics")
     (displayln "════════════════════════════════════════════════════════════")
     (displayln (str "Total packets: " (length packets)))
     (let ((total-size (apply + (map (lambda (p) (bytevector-length (cdr p)))
                                     packets))))
       (displayln (str "Total bytes: " total-size))
       (if (> (length packets) 0)
           (displayln (str "Avg packet: " (quotient total-size (length packets)))))
       (displayln "")))

    ((protocols)
     (displayln "Protocol Distribution")
     (displayln "════════════════════════════════════════════════════════════")
     (let ((proto-count (make-hash-table)))
       (for ((pkt packets))
         (let ((data (cdr pkt)))
           (if (>= (bytevector-length data) 14)
               (let ((etype-result (read-u16be data 12)))
                 (if (ok? etype-result)
                     (let ((etype (unwrap etype-result)))
                       (let ((proto (case etype
                                     ((#x0800) "IPv4")
                                     ((#x0806) "ARP")
                                     ((#x86DD) "IPv6")
                                     (else (str "0x" (format "~4,'0x" etype))))))
                         (hash-put! proto-count proto
                                   (+ 1 (or (hash-get proto-count proto) 0))))))))))
       (let ((sorted (sort (hash->list proto-count)
                          (lambda (a b) (> (cdr a) (cdr b))))))
         (for ((entry sorted))
           (displayln (str (car entry) ": " (cdr entry)))))))

    ((list)
     (let ((count (if (>= (length args) 3)
                     (string->number (caddr args))
                     10)))
       (displayln (str "First " count " packets\n"))
       (displayln "Pkt#  Size Protocol")
       (displayln "──── ──── ──────────────────")
       (let loop ((items packets) (idx 0))
         (if (or (>= idx count) (null? items))
             (displayln "")
             (let* ((pkt (car items))
                    (size (bytevector-length (cdr pkt))))
               (printf "~4d ~5d  " idx size)
               (displayln (describe-packet (cdr pkt)))
               (loop (cdr items) (+ idx 1)))))))

    (else
     (displayln (str "Unknown command: " command))
     (show-help))))

;; Entry point: interpreter mode calls wafter-main directly
(wafter-main)
