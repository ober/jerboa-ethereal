;; jerboa-ethereal/lib/dissector/registry.ss
;; Protocol registry and discovery
;;
;; Maps protocol names to their definitions, enables protocol chaining

(import (jerboa prelude))

;; ── Protocol Registry ──────────────────────────────────────────────────────

(def protocol-registry (make-hash-table))

(def (register-protocol! proto-name proto-definition)
  "Register a protocol definition by name
   proto-definition is output from parse-protocol-def"
  (hash-put! protocol-registry proto-name proto-definition))

(def (lookup-protocol proto-name)
  "Look up protocol by name, returns #f if not found"
  (hash-get protocol-registry proto-name))

(def (protocol-registered? proto-name)
  "Check if protocol is registered"
  (hash-key? protocol-registry proto-name))

(def (list-protocols)
  "Get list of all registered protocol names"
  (hash-keys protocol-registry))

;; ── Standard Protocol Registration ─────────────────────────────────────────
;; These are placeholder stubs; real definitions come from dissector modules

(def ethernet-stub
  '(ethernet
     "IEEE 802.3 Ethernet Frame"
     ((dest-mac u48be :formatter format-mac :desc "Destination MAC address")
      (src-mac u48be :formatter format-mac :desc "Source MAC address")
      (type u16be :formatter format-ethertype :desc "EtherType")
      (payload bytes :desc "Payload"))
     #f
     'type))

(def ipv4-stub
  '(ipv4
     "RFC 791: Internet Protocol Version 4"
     ((version u8 :mask #xF0 :shift 4 :desc "IP version")
      (ihl u8 :mask #x0F :desc "Header length (32-bit words)")
      (dscp u8 :mask #xFC :shift 2 :desc "DSCP")
      (ecn u8 :mask #x03 :desc "Explicit Congestion Notification")
      (total-length u16be :desc "Total packet length")
      (identification u16be :formatter format-hex :desc "ID")
      (flags u8 :mask #xE0 :shift 5 :formatter format-ipv4-flags :desc "Flags")
      (fragment-offset u16be :mask #x1FFF :desc "Fragment offset")
      (ttl u8 :desc "Time to Live")
      (protocol u8 :formatter format-ip-protocol :desc "Protocol number")
      (header-checksum u16be :formatter format-hex :desc "Checksum")
      (src-ip u32be :formatter format-ipv4 :desc "Source IP")
      (dst-ip u32be :formatter format-ipv4 :desc "Destination IP")
      (payload bytes :desc "Payload"))
     #f
     'protocol))

(def udp-stub
  '(udp
     "RFC 768: User Datagram Protocol"
     ((src-port u16be :formatter format-port :desc "Source port")
      (dst-port u16be :formatter format-port :desc "Destination port")
      (length u16be :desc "UDP length")
      (checksum u16be :formatter format-hex :desc "Checksum")
      (payload bytes :desc "UDP payload"))
     #f
     #f))

(def tcp-stub
  '(tcp
     "RFC 793: Transmission Control Protocol"
     ((src-port u16be :formatter format-port :desc "Source port")
      (dst-port u16be :formatter format-port :desc "Destination port")
      (sequence u32be :formatter format-hex :desc "Sequence number")
      (acknowledgment u32be :formatter format-hex :desc "Acknowledgment")
      (data-offset u8 :mask #xF0 :shift 4 :desc "Data offset")
      (flags u8 :formatter format-tcp-flags :desc "Flags (SYN, ACK, etc.)")
      (window-size u16be :desc "Window size")
      (checksum u16be :formatter format-hex :desc "Checksum")
      (urgent-pointer u16be :desc "Urgent pointer")
      (payload bytes :desc "Payload"))
     #f
     #f))

(def icmp-stub
  '(icmp
     "RFC 792: Internet Control Message Protocol"
     ((type u8 :formatter format-icmp-type :desc "Message type")
      (code u8 :desc "Message code")
      (checksum u16be :formatter format-hex :desc "Checksum")
      (rest-of-header u32be :desc "Rest of header")
      (payload bytes :desc "ICMP payload"))
     #f
     #f))

;; Register all standard protocols
(register-protocol! 'ethernet ethernet-stub)
(register-protocol! 'ipv4 ipv4-stub)
(register-protocol! 'tcp tcp-stub)
(register-protocol! 'udp udp-stub)
(register-protocol! 'icmp icmp-stub)

;; ── Formatter Stubs ───────────────────────────────────────────────────────
;; These will be implemented in lib/dsl/formatters.ss and imported here
;; For now, placeholder functions for the registry stubs

(def (format-mac addr)
  "Format u48 as MAC address (placeholder)"
  (str "MAC:" addr))

(def (format-ethertype type)
  "Format EtherType (placeholder)"
  (cond
    [(= type #x0800) "IPv4 (0x0800)"]
    [(= type #x0806) "ARP (0x0806)"]
    [(= type #x86DD) "IPv6 (0x86DD)"]
    [#t (format "0x~4,'0x" type)]))

(def (format-ipv4 addr)
  "Format u32 as IPv4 address (placeholder)"
  (let* ([b0 (bitwise-arithmetic-shift-right addr 24)]
         [b1 (bitwise-and (bitwise-arithmetic-shift-right addr 16) 255)]
         [b2 (bitwise-and (bitwise-arithmetic-shift-right addr 8) 255)]
         [b3 (bitwise-and addr 255)])
    (str b0 "." b1 "." b2 "." b3)))

(def (format-ipv4-flags flags)
  "Format IPv4 flags (DF, MF) (placeholder)"
  (str "flags:" flags))

(def (format-ip-protocol num)
  "Format IP protocol number (placeholder)"
  (cond
    [(= num 1) "ICMP (1)"]
    [(= num 6) "TCP (6)"]
    [(= num 17) "UDP (17)"]
    [#t (str "proto:" num)]))

(def (format-port port-num)
  "Format port number with service name (placeholder)"
  (cond
    [(= port-num 22) "ssh (22)"]
    [(= port-num 80) "http (80)"]
    [(= port-num 443) "https (443)"]
    [(= port-num 53) "dns (53)"]
    [#t (str port-num)]))

(def (format-tcp-flags flags)
  "Format TCP flags (SYN, ACK, etc.) (placeholder)"
  (str "flags:" flags))

(def (format-icmp-type type)
  "Format ICMP type (placeholder)"
  (cond
    [(= type 0) "Echo Reply"]
    [(= type 8) "Echo Request"]
    [#t (str "icmp:" type)]))

(def (format-hex val)
  "Format as hexadecimal (placeholder)"
  (if (integer? val)
      (format "0x~x" val)
      (str val)))