;; jerboa-ethereal/dissectors/ipv4.ss
;; RFC 791: Internet Protocol Version 4 (IPv4) dissector
;;
;; Layer 3 network-layer protocol.
;; Provides source/destination IP addresses and routing.

(import (jerboa prelude))

;; IPv4 protocol definition
(def ipv4-protocol
  '(defprotocol ipv4
     :description "RFC 791: Internet Protocol Version 4"
     :field-specs (
       ;; First byte: version (4 bits) + IHL (4 bits)
       (version u8 :mask 0xF0 :shift 4 :desc "IP version (4 for IPv4)")
       (ihl u8 :mask 0x0F :desc "Internet Header Length (32-bit words)")

       ;; DSCP + ECN
       (dscp u8 :mask 0xFC :shift 2 :desc "Differentiated Services Code Point")
       (ecn u8 :mask 0x03 :desc "Explicit Congestion Notification")

       ;; Packet sizing
       (total-length u16be :desc "Total length including header and payload")
       (identification u16be :formatter format-hex :desc "Packet ID for reassembly")

       ;; Flags + Fragment Offset
       (flags u8 :mask 0xE0 :shift 5 :formatter format-ipv4-flags :desc "DF, MF flags")
       (fragment-offset u16be :mask 0x1FFF :desc "Fragment offset (8-byte units)")

       ;; TTL + Protocol
       (ttl u8 :desc "Time to Live (hop limit)")
       (protocol u8 :formatter format-ip-protocol :desc "Protocol number")

       ;; Checksum
       (header-checksum u16be :formatter format-hex :desc "Header checksum")

       ;; Addresses
       (src-ip u32be :formatter format-ipv4 :desc "Source IP address")
       (dst-ip u32be :formatter format-ipv4 :desc "Destination IP address")

       ;; Options (only if IHL > 5)
       (options bytes :size (* (- ihl 5) 4) :conditional (> ihl 5)
        :desc "Options (variable length)")

       ;; Payload determined by protocol field
       (payload bytes :size (- total-length (* ihl 4)) :desc "Encapsulated payload"))))

;; IPv4 flag names
(def ipv4-flag-names
  (alist
    (#x4 "DF")  ;; Don't Fragment
    (#x2 "MF"))) ;; More Fragments

(def (format-ipv4-flags flags)
  "Format IPv4 flags
   Example: 0x4 -> \"DF\""
  (let ([df? (bitwise-and flags 0x4)]
        [mf? (bitwise-and flags 0x2)])
    (str
      (if (> df? 0) "DF" "")
      (if (and (> df? 0) (> mf? 0)) "|" "")
      (if (> mf? 0) "MF" ""))))

;; IP protocol numbers
(def ip-protocols
  (alist
    (1 "ICMP")
    (6 "TCP")
    (17 "UDP")
    (41 "IPv6")
    (47 "GRE")
    (50 "ESP")
    (51 "AH")
    (58 "ICMPv6")))

(def (format-ip-protocol num)
  "Format IP protocol number with name
   Example: 6 -> \"TCP (6)\""
  (let ([name (assoc-in ip-protocols num)])
    (if name
        (str (cdr name) " (" num ")")
        (str num))))

;; Protocol registration would happen here
;; (register-dissector-handler 'ipv4 'ethertype #x0800)
;; (register-dissector-by-protocol 6 'tcp)
;; (register-dissector-by-protocol 17 'udp)

;; Exported API
;; ipv4-protocol: the protocol definition
;; format-ipv4-flags, format-ip-protocol: formatters
;; ipv4-flag-names, ip-protocols: value mappings
