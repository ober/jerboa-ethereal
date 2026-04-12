#!/usr/bin/env scheme
;; jerboa-ethereal/tools/pcap-analyzer.ss
;; PCAP file analyzer: read, dissect, index, search
;;
;; Reads PCAP files, dissects packets through protocol layers,
;; and provides command-line interface for searching and analysis

(import (jerboa prelude))

;; Load dissector modules
(load "lib/dissector/protocol.ss")
(load "dissectors/ethernet.ss")
(load "dissectors/ipv4.ss")
(load "dissectors/tcp.ss")
(load "dissectors/udp.ss")
(load "dissectors/icmpv6.ss")
(load "dissectors/igmp.ss")
(load "dissectors/arp.ss")
(load "dissectors/dns.ss")

;; Load PCAP reader
(load "lib/pcap/reader.ss")

;; ── Local Protocol Registry ────────────────────────────────────────────────

(def protocol-dissectors (make-hash-table))

(def (register-dissector! name fn)
  (hash-put! protocol-dissectors name fn))

(def (get-dissector name)
  (hash-get protocol-dissectors name))

;; Register all dissectors
(register-dissector! 'ethernet dissect-ethernet)
(register-dissector! 'ipv4 dissect-ipv4)
(register-dissector! 'tcp dissect-tcp)
(register-dissector! 'udp dissect-udp)
(register-dissector! 'icmpv6 dissect-icmpv6)
(register-dissector! 'igmp dissect-igmp)
(register-dissector! 'arp dissect-arp)
(register-dissector! 'dns dissect-dns)

;; ── Protocol Discovery Rules ──────────────────────────────────────────────

(def (ethertype->protocol etype)
  (case etype
    ((#x0800) 'ipv4)
    ((#x0806) 'arp)
    ((#x86DD) 'ipv6)
    (else #f)))

(def (ip-protocol->protocol proto-num)
  (case proto-num
    ((1) 'icmp)
    ((2) 'igmp)
    ((6) 'tcp)
    ((17) 'udp)
    ((58) 'icmpv6)
    (else #f)))

(def (port->protocol port-num)
  (case port-num
    ((53) 'dns)
    ((80) 'http)
    ((443) 'https)
    ((22) 'ssh)
    ((21) 'ftp)
    ((25 587) 'smtp)
    ((110) 'pop3)
    ((143) 'imap)
    (else #f)))

;; ── Dissection Pipeline ────────────────────────────────────────────────────

(def (dissect-packet buffer (start-proto 'ethernet))
  "Dissect packet starting with given protocol"
  (dissect-protocol-chain buffer start-proto '()))

(def (dissect-protocol-chain buffer proto-name layers)
  "Recursively dissect protocol and chain to next layer"
  (let ((dissector (get-dissector proto-name)))
    (cond
      ((not dissector)
       (if (null? layers)
           (err (str "Unknown protocol: " proto-name))
           (ok (reverse layers))))

      (else
       (try
         (let ((result (dissector buffer)))
           (cond
             ((err? result)
              (if (null? layers)
                  result
                  (ok (reverse layers))))

             (else
              (let* ((fields (unwrap result))
                     (payload (assoc-get fields 'payload #f))
                     (next-proto (find-next-protocol proto-name fields)))

                (if (and next-proto payload
                        (> (bytevector-length payload) 0))
                    (dissect-protocol-chain payload next-proto
                                           (cons (cons proto-name fields) layers))
                    (ok (reverse (cons (cons proto-name fields) layers))))))))

         (catch (e)
           (if (null? layers)
               (err (str "Dissection error in " proto-name ": " e))
               (ok (reverse layers)))))))))

(def (find-next-protocol proto-name fields)
  "Determine next protocol in chain"
  (case proto-name
    ((ethernet)
     (let ((etype-field (assoc-get fields 'etype #f)))
       (if etype-field
           (let ((etype (assoc-get etype-field 'raw)))
             (ethertype->protocol etype))
           #f)))

    ((ipv4)
     (let ((proto-field (assoc-get fields 'protocol #f)))
       (if proto-field
           (let ((proto-num (assoc-get proto-field 'raw)))
             (ip-protocol->protocol proto-num))
           #f)))

    ((tcp udp)
     (let ((dst-port-field (assoc-get fields 'dst-port #f)))
       (if dst-port-field
           (let ((port (assoc-get dst-port-field 'raw)))
             (port->protocol port))
           #f)))

    (else #f)))

;; ── Display Functions ──────────────────────────────────────────────────────

(def (display-dissected-packet layers)
  "Pretty-print dissected packet tree"
  (string-join
    (map (lambda (layer)
           (let ((proto-name (car layer))
                 (fields (cdr layer)))
             (str (format-protocol-name proto-name) ":"
                  "\n"
                  (display-fields fields 2))))
         layers)
    "\n\n"))

(def (format-protocol-name name)
  "Format protocol name for display"
  (case name
    ((ethernet) "Ethernet")
    ((ipv4) "IPv4")
    ((ipv6) "IPv6")
    ((tcp) "TCP")
    ((udp) "UDP")
    ((icmp) "ICMP")
    ((icmpv6) "ICMPv6")
    ((igmp) "IGMP")
    ((arp) "ARP")
    ((dns) "DNS")
    (else (str name))))

(def (display-fields fields indent)
  "Format fields for display with indentation"
  (let ((space (make-string indent #\space)))
    (string-join
      (map (lambda (field)
             (let ((name (car field))
                   (value (cdr field)))
               (cond
                 ((pair? value)
                  (let ((formatted (assoc-get value 'formatted #f)))
                    (if formatted
                        (str space (format-field-name name) " = " formatted)
                        (let ((raw (assoc-get value 'raw #f)))
                          (if raw
                              (str space (format-field-name name) " = " (truncate-value raw 60))
                              (str space (format-field-name name) " = ?"))))))
                 (else
                  (str space (format-field-name name) " = " (truncate-value value 60))))))
           fields)
      "\n")))

(def (format-field-name name)
  "Format field name for display"
  (string-replace (string-replace (str name) "-" " ") "_" " "))

(def (truncate-value val max-len)
  "Truncate value display to max length"
  (let ((str-val (str val)))
    (if (> (string-length str-val) max-len)
        (str (string-take str-val (- max-len 3)) "...")
        str-val)))

;; ── Dissect All Packets ───────────────────────────────────────────────────

(def (dissect-all-packets packets)
  "Dissect all packets and collect results"
  (map (lambda (pkt idx)
         (let ((payload (assoc-get pkt 'payload #f)))
           (if (not payload)
               (list pkt #f)
               (let ((result (dissect-packet payload 'ethernet)))
                 (list pkt
                       (if (ok? result)
                           (unwrap result)
                           #f))))))
       packets
       (in-naturals)))

;; ── Extract Packet Info ────────────────────────────────────────────────────

(def (get-packet-protocol dissected-pkt)
  "Extract top-level protocol name"
  (if (not (cdr dissected-pkt))
      'unknown
      (let ((layers (cdr dissected-pkt)))
        (if (null? layers)
            'unknown
            (car (car layers))))))

(def (get-packet-ips dissected-pkt)
  "Extract source and destination IPs"
  (if (not (cdr dissected-pkt))
      (cons #f #f)
      (let loop ((layers (cdr dissected-pkt)))
        (if (null? layers)
            (cons #f #f)
            (let ((proto (caar layers))
                  (fields (cdar layers)))
              (if (eq? proto 'ipv4)
                  (let ((src (assoc-get fields 'src-ip #f))
                        (dst (assoc-get fields 'dst-ip #f)))
                    (cons (if src (assoc-get src 'formatted) #f)
                          (if dst (assoc-get dst 'formatted) #f)))
                  (loop (cdr layers))))))))

(def (get-packet-ports dissected-pkt)
  "Extract source and destination ports"
  (if (not (cdr dissected-pkt))
      (cons #f #f)
      (let loop ((layers (cdr dissected-pkt)))
        (if (null? layers)
            (cons #f #f)
            (let ((proto (caar layers))
                  (fields (cdar layers)))
              (if (or (eq? proto 'tcp) (eq? proto 'udp))
                  (let ((src (assoc-get fields 'src-port #f))
                        (dst (assoc-get fields 'dst-port #f)))
                    (cons (if src (assoc-get src 'raw) #f)
                          (if dst (assoc-get dst 'raw) #f)))
                  (loop (cdr layers))))))))

;; ── Command Handlers ──────────────────────────────────────────────────────

(def (cmd-stats dissected)
  "Show file statistics"
  (displayln "PCAP File Statistics")
  (displayln "════════════════════════════════════════════════════════════")
  (displayln (str "Total packets: " (length dissected)))

  (let ((total-size (apply + (map (lambda (d)
                                    (assoc-get (car d) 'size 0))
                                  dissected))))
    (displayln (str "Total bytes: " total-size)))

  (let ((successfully-dissected
         (length (filter (lambda (d) (cdr d)) dissected))))
    (displayln (str "Successfully dissected: " successfully-dissected)))

  (let ((proto-counts (make-hash-table)))
    (for ((d dissected))
      (let ((proto (get-packet-protocol d)))
        (hash-put! proto-counts proto
                   (+ 1 (hash-get proto-counts proto 0)))))

    (displayln "\nProtocol Summary:")
    (hash-for-each (lambda (proto count)
                     (displayln (str "  " proto ": " count)))
                   proto-counts)))

(def (cmd-list dissected count)
  "List first N packets with key info"
  (displayln (str "Packet List (first " count " of " (length dissected) ")\n"))
  (displayln "Pkt# Protocol SrcIP:Port       DstIP:Port       Size")
  (displayln "──── ──────── ────────────────── ────────────────── ────")

  (let loop ((items dissected)
            (idx 0))
    (if (or (null? items) (>= idx count))
        (displayln "")
        (let* ((d (car items))
               (pkt-meta (car d))
               (pkt-num (assoc-get pkt-meta 'packet-number 0))
               (size (assoc-get pkt-meta 'size 0))
               (proto (get-packet-protocol d))
               (ips (get-packet-ips d))
               (ports (get-packet-ports d))
               (src-ip (car ips))
               (dst-ip (cdr ips))
               (src-port (car ports))
               (dst-port (cdr ports)))

          (let ((src-str (if (and src-ip src-port)
                            (str src-ip ":" src-port)
                            (if src-ip src-ip "?")))
                (dst-str (if (and dst-ip dst-port)
                            (str dst-ip ":" dst-port)
                            (if dst-ip dst-ip "?"))))

            (printf "~4d ~8s ~18s ~18s ~4d\n"
                    pkt-num proto
                    (if (> (string-length src-str) 18)
                        (string-take src-str 15) "..."
                        src-str)
                    (if (> (string-length dst-str) 18)
                        (string-take dst-str 15) "..."
                        dst-str)
                    size)

            (loop (cdr items) (+ idx 1)))))))

(def (cmd-protocols dissected)
  "Show protocol summary"
  (displayln "Protocol Summary")
  (displayln "════════════════════════════════════════════════════════════")

  (let ((proto-counts (make-hash-table))
        (proto-bytes (make-hash-table)))

    (for ((d dissected))
      (let ((proto (get-packet-protocol d))
            (size (assoc-get (car d) 'size 0)))
        (hash-put! proto-counts proto
                   (+ 1 (hash-get proto-counts proto 0)))
        (hash-put! proto-bytes proto
                   (+ size (hash-get proto-bytes proto 0)))))

    (displayln "\nProtocol  Count    Bytes  Avg Size")
    (displayln "────────── ──── ───────── ─────────")

    (hash-for-each (lambda (proto count)
                     (let ((bytes (hash-get proto-bytes proto 0)))
                       (let ((avg (if (> count 0)
                                     (quotient bytes count)
                                     0)))
                         (printf "~10s ~4d ~8d ~8d\n"
                                proto count bytes avg))))
                   proto-counts)

    (displayln "")))

(def (cmd-find-protocol dissected protocol-name)
  "Find packets by protocol"
  (let ((matches (filter (lambda (d)
                          (eq? (get-packet-protocol d)
                               (string->symbol protocol-name)))
                        dissected)))

    (displayln (str "Found " (length matches)
                   " " protocol-name " packets\n"))

    (cmd-list matches (min 20 (length matches)))))

(def (cmd-find-ip dissected ip-addr)
  "Find packets by IP"
  (let ((matches (filter (lambda (d)
                          (let ((ips (get-packet-ips d)))
                            (or (string=? (or (car ips) "") ip-addr)
                                (string=? (or (cdr ips) "") ip-addr))))
                        dissected)))

    (displayln (str "Found " (length matches) " packets for IP " ip-addr "\n"))

    (cmd-list matches (min 20 (length matches)))))

(def (cmd-find-port dissected port-num)
  "Find packets by port"
  (let ((matches (filter (lambda (d)
                          (let ((ports (get-packet-ports d)))
                            (or (= (or (car ports) -1) port-num)
                                (= (or (cdr ports) -1) port-num))))
                        dissected)))

    (displayln (str "Found " (length matches) " packets for port " port-num "\n"))

    (cmd-list matches (min 20 (length matches)))))

(def (cmd-dissect dissected pkt-num)
  "Dissect and display full packet details"
  (if (or (< pkt-num 0) (>= pkt-num (length dissected)))
      (displayln (str "Error: packet " pkt-num " not found"))
      (let* ((d (list-ref dissected pkt-num))
             (layers (cdr d)))

        (displayln (str "Packet " pkt-num " Details"))
        (displayln "════════════════════════════════════════════════════════════")
        (displayln "")

        (if (not layers)
            (displayln "Failed to dissect packet")
            (displayln (display-dissected-packet layers)))

        (displayln ""))))

;; ── Help ───────────────────────────────────────────────────────────────────

(def (show-help)
  "Show usage help"
  (displayln "")
  (displayln "════════════════════════════════════════════════════════════")
  (displayln "  jerboa-ethereal PCAP Analyzer")
  (displayln "════════════════════════════════════════════════════════════")
  (displayln "")
  (displayln "Usage: scheme pcap-analyzer.ss <pcap-file> <command> [args]")
  (displayln "")
  (displayln "Commands:")
  (displayln "  stats               - Show file statistics")
  (displayln "  list [count]        - List first N packets")
  (displayln "  protocols           - Show protocol summary")
  (displayln "  find-protocol PROTO - Find packets by protocol")
  (displayln "  find-ip IP          - Find packets by source/dest IP")
  (displayln "  find-port PORT      - Find packets by port number")
  (displayln "  dissect N           - Dissect and display packet N in detail")
  (displayln "")
  (displayln "Examples:")
  (displayln "  scheme pcap-analyzer.ss capture.pcap stats")
  (displayln "  scheme pcap-analyzer.ss capture.pcap list 10")
  (displayln "  scheme pcap-analyzer.ss capture.pcap find-protocol dns")
  (displayln "  scheme pcap-analyzer.ss capture.pcap find-ip 192.168.1.1")
  (displayln "  scheme pcap-analyzer.ss capture.pcap find-port 80")
  (displayln "  scheme pcap-analyzer.ss capture.pcap dissect 5")
  (displayln "")
  (displayln "Status: Phase 2 (full dissection and analysis)")
  (displayln ""))

;; ── Main Entry Point ──────────────────────────────────────────────────────

(def (main)
  "Main analyzer entry point"
  (try
    (let* ((args (command-line-arguments)))
      (cond
        ((< (length args) 2)
         (show-help))

        (else
         (let* ((pcap-file (car args))
                (command (string-downcase (cadr args)))
                (cmd-args (cddr args)))

           (displayln (str "Reading PCAP file: " pcap-file))
           (let* ((packets-result (read-pcap-packets pcap-file))
                  (packets (unwrap packets-result)))

             (displayln (str "Loaded " (length packets) " packets"))
             (displayln "Dissecting packets...")

             (let ((dissected (dissect-all-packets packets)))
               (displayln (str "Dissected " (length dissected) " packets\n"))

               (case (string->symbol command)
                 ((stats)
                  (cmd-stats dissected))

                 ((list)
                  (let ((count (if (null? cmd-args) 10
                                 (string->number (car cmd-args)))))
                    (cmd-list dissected count)))

                 ((protocols)
                  (cmd-protocols dissected))

                 ((find-protocol)
                  (if (null? cmd-args)
                      (displayln "Error: specify protocol (dns, tcp, etc)")
                      (cmd-find-protocol dissected (car cmd-args))))

                 ((find-ip)
                  (if (null? cmd-args)
                      (displayln "Error: specify IP address")
                      (cmd-find-ip dissected (car cmd-args))))

                 ((find-port)
                  (if (null? cmd-args)
                      (displayln "Error: specify port number")
                      (cmd-find-port dissected (string->number (car cmd-args)))))

                 ((dissect)
                  (if (null? cmd-args)
                      (displayln "Error: specify packet number")
                      (cmd-dissect dissected (string->number (car cmd-args)))))

                 (else
                  (displayln (str "Unknown command: " command))
                  (show-help)))))))

    (catch (e)
      (displayln (str "Error: " e "\n"))
      (show-help))))

;; Run
(main)
