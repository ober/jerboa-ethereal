;;  jerboa-ethereal/lib/dissector/manifest.ss
;; Dissector manifest - metadata about all available dissectors
;;
;; This file defines what dissectors are available, their dependencies,
;; and how they integrate with the protocol discovery system.
;; Used by the build system to compile the static binary.

(import (jerboa prelude))

;; ── Dissector Manifest ────────────────────────────────────────────────────

(def dissector-manifest
  "Complete list of dissectors with metadata
   Format: (name rfc layers protocols file-path)"

  '((ethernet
     "802.3"
     '(link)
     '(ethernet)
     "dissectors/ethernet.ss")

    (ipv4
     "RFC 791"
     '(network)
     '(ipv4)
     "dissectors/ipv4.ss")

    (ipv6
     "RFC 2460"
     '(network)
     '(ipv6)
     "dissectors/ipv6.ss")

    (arp
     "RFC 826"
     '(link)
     '(arp)
     "dissectors/arp.ss")

    (tcp
     "RFC 793"
     '(transport)
     '(tcp)
     "dissectors/tcp.ss")

    (udp
     "RFC 768"
     '(transport)
     '(udp)
     "dissectors/udp.ss")

    (icmp
     "RFC 792"
     '(network)
     '(icmp)
     "dissectors/icmp.ss")

    (icmpv6
     "RFC 4443"
     '(network)
     '(icmpv6)
     "dissectors/icmpv6.ss")

    (igmp
     "RFC 3376"
     '(network)
     '(igmp)
     "dissectors/igmp.ss")

    (dns
     "RFC 1035"
     '(application)
     '(dns)
     "dissectors/dns.ss")

    (dhcp
     "RFC 2131"
     '(application)
     '(dhcp)
     "dissectors/dhcp.ss")

    (ntp
     "RFC 5905"
     '(application)
     '(ntp)
     "dissectors/ntp.ss")

    (ssh
     "RFC 4251"
     '(application)
     '(ssh)
     "dissectors/ssh.ss")))

;; ── Helper Functions ───────────────────────────────────────────────────────

(def (dissector-by-name name)
  "Look up dissector metadata by name"
  (let loop ((entries dissector-manifest))
    (if (null? entries)
        #f
        (let ((entry (car entries)))
          (if (eq? (car entry) name)
              entry
              (loop (cdr entries)))))))

(def (dissectors-by-layer layer)
  "Get all dissectors for a specific layer
   layer: 'link, 'network, 'transport, 'application"

  (filter (lambda (entry)
            (member layer (caddr entry)))
          dissector-manifest))

(def (dissector-count)
  "Total number of dissectors"
  (length dissector-manifest))

(def (list-dissectors)
  "Display all dissectors with metadata"

  (displayln "Available Dissectors")
  (displayln "════════════════════════════════════════════════════════")
  (displayln "")

  ;; Group by layer
  (let ((layers '(link network transport application)))
    (for ((layer layers))
      (let ((dissectors (dissectors-by-layer layer)))
        (if (> (length dissectors) 0)
            (begin
              (displayln (str (string-upcase (symbol->string layer)) " Layer:"))
              (for ((d dissectors))
                (let ((name (car d))
                      (rfc (cadr d))
                      (protos (car (cdddr d))))
                  (displayln (str "  • " (string-upcase (symbol->string name))
                                 " (" rfc ")"))))
              (displayln "")))))))

;; ── Build System Integration ───────────────────────────────────────────────

(def (generate-build-list)
  "Generate list of files to compile for static binary
   Used by build-wafter-musl.ss"

  (map (lambda (entry)
         (let ((file (car (cddddr entry))))
           file))
       dissector-manifest))

(def (generate-imports)
  "Generate import statements for all dissectors
   Used by build system to create a loader module"

  (map (lambda (entry)
         (let ((name (car entry)))
           (str "(import (dissectors " (symbol->string name) "))")))
       dissector-manifest))

;; ── Export ────────────────────────────────────────────────────────────────

;; dissector-manifest: complete metadata list
;; dissector-by-name: lookup by protocol name
;; dissectors-by-layer: filter by OSI layer
;; dissector-count: total count
;; list-dissectors: display all with info
;; generate-build-list: for build system
;; generate-imports: for code generation
;;
;; Phase 7 Usage:
;;   - Build system reads manifest to compile all dissectors
;;   - Static binary embeds all protocols
;;   - Runtime uses manifest for protocol discovery
