;; jerboa-ethereal/dissectors/ethernet.ss
;; IEEE 802.3 Ethernet Frame dissector
;;
;; Layer 2 link-layer protocol. Every packet starts here.
;; Format:
;;   Destination MAC (6 bytes)
;;   Source MAC (6 bytes)
;;   EtherType (2 bytes) → determines payload protocol
;;   Payload (variable)

(import (jerboa prelude))

;; Ethernet protocol definition
(def ethernet-protocol
  '(defprotocol ethernet
     :description "IEEE 802.3 Ethernet Frame (Layer 2)"
     :field-specs (
       (dest-mac u48be :formatter format-mac :desc "Destination MAC address")
       (src-mac u48be :formatter format-mac :desc "Source MAC address")
       (type u16be :formatter format-ethertype :desc "EtherType: determines payload protocol")
       (payload bytes :size (- buffer-length 14) :desc "Payload (IP, ARP, VLAN, etc.)"))))

;; Well-known EtherType values
(def ethertype-names
  (alist
    (#x0800 "IPv4")
    (#x0806 "ARP")
    (#x0835 "RARP")
    (#x86DD "IPv6")
    (#x8100 "VLAN")
    (#x8847 "MPLS")
    (#x888E "802.1X")))

(def (format-ethertype type)
  "Format EtherType value with name if known
   Example: #x0800 -> \"IPv4 (0x0800)\""
  (let ([name (assoc-in ethertype-names type)])
    (if name
        (str (cdr name) " (0x" (format "~4,'0x" type) ")")
        (str "0x" (format "~4,'0x" type)))))

;; Protocol registration (will be used by dissection engine)
;; (register-dissector-handler 'ethernet 'link-type 1)
;; (register-ethertype-handler #x0800 'ipv4)
;; (register-ethertype-handler #x0806 'arp)
;; (register-ethertype-handler #x86DD 'ipv6)

;; Exported API
;; ethernet-protocol: the protocol definition
;; format-ethertype: formatter for EtherType field
;; ethertype-names: alist of well-known values
