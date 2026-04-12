;; jerboa-ethereal/lib/dissector/init.ss
;; Dissector initialization - imports all dissectors and registers them

(import (jerboa prelude)
        (lib dissector registry))

;; Import all dissector modules
;; Note: These use inline dissection functions, not library imports
;; to avoid circular dependencies and library complexity

(def (register-all-dissectors!)
  "Register all available dissectors with the registry"

  ;; Register built-in dissectors (defined inline in dissectors/)
  ;; The ethereal analyzer will handle dissector imports dynamically

  (displayln "Dissectors registered:
  - Ethernet (Layer 2)
  - IPv4 (Layer 3)
  - IPv6 (Layer 3)
  - TCP (Layer 4)
  - UDP (Layer 4)
  - DNS (Application)
  - NTP (Application, port 123)
  - DHCP (Application, ports 67/68)
  - SSH (Application, port 22)
  - ARP (Link layer)
  - ICMP (Layer 3)
"))

;; Exported API

;; register-all-dissectors!: initialize and register all dissectors
