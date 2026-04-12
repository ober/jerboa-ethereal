;; jerboa-ethereal/dissectors/udp.ss
;; RFC 768: User Datagram Protocol (UDP) dissector
;;
;; Layer 4 transport-layer protocol.
;; Provides connectionless, unreliable datagram delivery.

(import (jerboa prelude))

;; UDP protocol definition
(def udp-protocol
  '(defprotocol udp
     :description "RFC 768: User Datagram Protocol"
     :field-specs (
       (src-port u16be :formatter format-port :desc "Source port")
       (dst-port u16be :formatter format-port :desc "Destination port")
       (length u16be :desc "UDP length (header + payload)")
       (checksum u16be :formatter format-hex :desc "Checksum")
       (payload bytes :size (- length 8) :desc "UDP payload data"))))

;; Well-known UDP service ports
(def udp-services
  (alist
    (53 "dns")
    (67 "dhcp-server")
    (68 "dhcp-client")
    (69 "tftp")
    (123 "ntp")
    (161 "snmp")
    (162 "snmp-trap")
    (389 "ldap")
    (514 "syslog")
    (631 "ipp")
    (1194 "openvpn")))

(def (format-port port)
  "Format port number with service name if known
   Example: 53 -> \"dns (53)\", 12345 -> \"12345\""
  (let ([service (assoc-in udp-services port)])
    (if service
        (str (cdr service) " (" port ")")
        (str port))))

;; TCP/UDP common ports
(def (format-hex value)
  "Format as hexadecimal"
  (cond
    [(integer? value) (format "0x~4,'0x" value)]
    [(bytevector? value)
     (str "0x"
       (string-join
         (for/collect ([b (in-bytes value)])
           (format "~2,'0x" b)) ""))]
    [else (str value)]))

;; Exported API
;; udp-protocol: the protocol definition
;; format-port, format-hex: formatters
;; udp-services: well-known port names
