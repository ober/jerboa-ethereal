;; packet-dhcp.c
;; Routines for DHCP/BOOTP packet disassembly
;;
;; Copyright 1998, Gilbert Ramirez <gram@alumni.rice.edu>
;; Copyright 2004, Thomas Anders <thomas.anders [AT] blue-cable.de>
;;
;; Added option field filters
;; Copyright 2011, Michael Mann
;;
;; Added option	 77 : RFC 3004 - The User Class Option for DHCP
;; Added option 117 : RFC 2937 - The Name Service Search Option for DHCP
;; Added option 119 : RFC 3397 - Dynamic Host Configuration Protocol (DHCP) Domain Search Option
;; RFC 3396 - Encoding Long Options in the Dynamic Host Configuration Protocol (DHCPv4)
;; Improved opt 120 : Add support of RFC 3396 - Encoding Long Options in the Dynamic Host Configuration Protocol (DHCPv4)
;; Add support compression according to the encoding in Section 4.1.4 of RFC 1035 - DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION
;;
;;
;; Copyright 2012, Jerome LAFORGE <jerome.laforge [AT] gmail.com>
;;
;; The information used comes from:
;; RFC	951: Bootstrap Protocol
;; RFC 1035: Domain Names - Implementation And Specification
;; RFC 1497: BOOTP extensions
;; RFC 1542: Clarifications and Extensions for the Bootstrap Protocol
;; RFC 2131: Dynamic Host Configuration Protocol
;; RFC 2132: DHCP Options and BOOTP Vendor Extensions
;; RFC 2241: DHCP Options for Novell Directory Services
;; RFC 2242: NetWare/IP Domain Name and Information
;; RFC 2489: Procedure for Defining New DHCP Options
;; RFC 2610: DHCP Options for Service Location Protocol
;; RFC 2685: Virtual Private Networks Identifier
;; RFC 2937: The Name Service Search Option for DHCP
;; RFC 3004: The User Class Option for DHCP
;; RFC 3046: DHCP Relay Agent Information Option
;; RFC 3118: Authentication for DHCP Messages
;; RFC 3203: DHCP reconfigure extension
;; RFC 3315: Dynamic Host Configuration Protocol for IPv6 (DHCPv6)
;; RFC 3396: Encoding Long Options in the Dynamic Host Configuration Protocol (DHCPv4)
;; RFC 3397: Dynamic Host Configuration Protocol (DHCP) Domain Search Option
;; RFC 3495: DHCP Option (122) for CableLabs Client Configuration
;; RFC 3594: PacketCable Security Ticket Control Sub-Option (122.9)
;; RFC 3442: Classless Static Route Option for DHCP version 4
;; RFC 3825: Dynamic Host Configuration Protocol Option for Coordinate-based Location Configuration Information
;; RFC 3925: Vendor-Identifying Vendor Options for Dynamic Host Configuration Protocol version 4 (DHCPv4)
;; RFC 3942: Reclassifying DHCPv4 Options
;; RFC 4174: The IPv4 Dynamic Host Configuration Protocol (DHCP) Option for the Internet Storage Name Service
;; RFC 4243: Vendor-Specific Information Suboption for the Dynamic Host Configuration Protocol (DHCP) Relay Agent Option
;; RFC 4361: Node-specific Client Identifiers for Dynamic Host Configuration Protocol Version Four (DHCPv4)
;; RFC 4388: Dynamic Host Configuration Protocol (DHCP) Leasequery
;; RFC 4578: Dynamic Host Configuration Protocol (DHCP) Options for PXE
;; RFC 4776: Dynamic Host Configuration Protocol (DHCPv4 and DHCPv6) Option for Civic Addresses Configuration Information
;; RFC 5192: DHCP Options for Protocol for Carrying Authentication for Network Access (PANA) Authentication Agent
;; RFC 5223: Discovering Location-to-Service Translation (LoST) Servers Using the Dynamic Host Configuration Protocol (DHCP)
;; RFC 5417: CAPWAP Access Controller DHCP Option
;; RFC 5969: IPv6 Rapid Deployment on IPv4 Infrastructures (6rd)
;; RFC 6225: Dynamic Host Configuration Protocol Options for Coordinate-Based Location Configuration Information
;; RFC 6607: Virtual Subnet Selection Options for DHCPv4 and DHCPv6
;; RFC 6704: Forcerenew Nonce Authentication
;; RFC 6731: Improved Recursive DNS Server Selection for Multi-Interfaced Nodes
;; RFC 6926: DHCPv4 Bulk Leasequery
;; RFC 7291: DHCP Options for the Port Control Protocol (PCP)
;; RFC 7618: Dynamic Allocation of Shared IPv4 Addresses
;; RFC 7710: Captive-Portal Identification Using DHCP or Router Advertisements (RAs)
;; RFC 7724: Active DHCPv4 Lease Query
;; RFC 7839: Access-Network-Identifier Option in DHCP
;; RFC 8357: Generalized UDP Source Port for DHCP Relay
;; RFC 8910: Captive-Portal Identification in DHCP and Router Advertisements (RAs)
;; RFC 8925: IPv6-Only Preferred Option for DHCPv4
;; RFC 8973: DDoS Open Threat Signaling (DOTS) Agent Discovery
;; draft-ietf-dhc-fqdn-option-07.txt
;; TFTP Server Address Option for DHCPv4 [draft-raj-dhc-tftp-addr-option-06.txt: https://tools.ietf.org/html/draft-raj-dhc-tftp-addr-option-06]
;; BOOTP and DHCP Parameters
;; https://www.iana.org/assignments/bootp-dhcp-parameters
;; DOCSIS(TM) 2.0 Radio Frequency Interface Specification
;; https://specification-search.cablelabs.com/radio-frequency-interface-specification-2
;; DOCSIS(TM) 3.0 MAC and Upper Layer Protocols Interface Specification
;; https://specification-search.cablelabs.com/CM-SP-MULPIv3.0
;; PacketCable(TM) 1.0 MTA Device Provisioning Specification
;; https://specification-search.cablelabs.com/packetcable-mta-device-provisioning-specification
;; PacketCable(TM) 1.5 MTA Device Provisioning Specification
;; https://specification-search.cablelabs.com/packetcable-1-5-mta-device-provisioning-specification
;; PacketCable(TM) 2.0 E-UE Device Provisioning Data Model Specification
;; https://specification-search.cablelabs.com/e-ue-provisioning-data-model-specification
;; Business Services over DOCSIS(R) Layer 2 Virtual Private Networks
;; https://specification-search.cablelabs.com/business-services-over-docsis-layer-2-virtual-private-networks
;; CableHome(TM) 1.1 Specification
;; https://web.archive.org/web/20060628173459/http://www.cablelabs.com/projects/cablehome/downloads/specs/CH-SP-CH1.1-I11-060407.pdf
;; Broadband Forum TR-111
;; https://web.archive.org/web/20150307135117/http://www.broadband-forum.org/technical/download/TR-111.pdf
;; Boot Server Discovery Protocol (BSDP)
;; https://opensource.apple.com/source/bootp/bootp-198.1/Documentation/BSDP.doc
;; [MS-DHCPE] DHCPv4 Option Code 77 (0x4D) - User Class Option
;; https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dhcpe/fe8a2dd4-1e8c-4546-bacd-4ae10de02058
;;
;; * Copyright 2023, Colin McInnes <colin.mcinnes [AT] vecima.com>
;; Added additional CableLabs Vendor Class IDs (Option 60) to CableLabs heuristic from:
;; Remote PHY Specification
;; https://www.cablelabs.com/specifications/CM-SP-R-PHY
;; Flexible MAC Architecture System Specification
;; https://www.cablelabs.com/specifications/CM-SP-FMA-SYS
;; Data-Over-Cable Service Interface Specifications, eDOCSIS Specification
;; https://www.cablelabs.com/specifications/CM-SP-eDOCSIS
;; Data-Over-Cable Service Interface Specifications, IPv4 and IPv6 eRouter Specification
;; https://www.cablelabs.com/specifications/CM-SP-eRouter
;; OpenCable Tuning Resolver Interface Specification
;; https://www.cablelabs.com/specifications/OC-SP-TRIF
;; DPoE Demarcation Device Specification
;; https://www.cablelabs.com/specifications/DPoE-SP-DEMARCv1.0
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/dhcp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-dhcp.c
;; RFC 3004

(import (jerboa prelude))

;; ── Protocol Helpers ─────────────────────────────────────────────────
(def (read-u8 buf offset)
  (if (>= offset (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u8-ref buf offset))))

(def (read-u16be buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u16-ref buf offset (endianness big)))))

(def (read-u24be buf offset)
  (if (> (+ offset 3) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (+ (* (bytevector-u8-ref buf offset) 65536)
             (* (bytevector-u8-ref buf (+ offset 1)) 256)
             (bytevector-u8-ref buf (+ offset 2))))))

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

(def (read-u64be buf offset)
  (if (> (+ offset 8) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u64-ref buf offset (endianness big)))))

(def (read-u64le buf offset)
  (if (> (+ offset 8) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u64-ref buf offset (endianness little)))))

(def (slice buf offset len)
  (if (> (+ offset len) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (let ((result (make-bytevector len)))
            (bytevector-copy! buf offset result 0 len)
            result))))

(def (extract-bits val mask shift)
  (bitwise-arithmetic-shift-right (bitwise-and val mask) shift))

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

(def (fmt-oct val)
  (str "0" (number->string val 8)))

(def (fmt-port port)
  (number->string port))

(def (fmt-bytes bv)
  (string-join
    (map (lambda (b) (string-pad (number->string b 16) 2 #\0))
         (bytevector->list bv))
    " "))

(def (fmt-ipv6-address bytes)
  (let loop ((i 0) (parts '()))
    (if (>= i 16)
        (string-join (reverse parts) ":")
        (loop (+ i 2)
              (cons (let ((w (+ (* (bytevector-u8-ref bytes i) 256)
                                (bytevector-u8-ref bytes (+ i 1)))))
                      (number->string w 16))
                    parts)))))

;; ── Dissector ──────────────────────────────────────────────────────
(def (dissect-dhcp buffer)
  "Dynamic Host Configuration Protocol"
  (try
    (let* (
           (bootp (unwrap (read-u8 buffer 0)))
           (option-vendor-class-data (unwrap (slice buffer 0 1)))
           (option-portparams-offset (unwrap (read-u8 buffer 0)))
           (option-captive-portal (unwrap (slice buffer 0 1)))
           (option-vendor-class-id (unwrap (slice buffer 0 1)))
           (option-policy-filter-ip (unwrap (read-u32be buffer 0)))
           (option-static-route-ip (unwrap (read-u32be buffer 0)))
           (option43-value (unwrap (slice buffer 0 1)))
           (option-parameter-request-list-item (unwrap (read-u8 buffer 0)))
           (hw-ether-addr (unwrap (slice buffer 0 6)))
           (client-hardware-address (unwrap (slice buffer 0 6)))
           (client-identifier-uuid (unwrap (slice buffer 0 16)))
           (client-id-iaid (unwrap (slice buffer 0 4)))
           (option77-user-class-binary-data-length (unwrap (read-u16be buffer 0)))
           (option-slp-directory-agent-slpda-address (unwrap (read-u32be buffer 0)))
           (option-slp-service-scope-string (unwrap (slice buffer 0 1)))
           (fqdn-flags (unwrap (read-u8 buffer 0)))
           (fqdn-mbz (extract-bits fqdn-flags 0x0 0))
           (fqdn-n (extract-bits fqdn-flags 0x0 0))
           (fqdn-e (extract-bits fqdn-flags 0x0 0))
           (fqdn-o (extract-bits fqdn-flags 0x0 0))
           (fqdn-s (extract-bits fqdn-flags 0x0 0))
           (fqdn-rcode1 (unwrap (read-u8 buffer 0)))
           (fqdn-rcode2 (unwrap (read-u8 buffer 0)))
           (fqdn-name (unwrap (slice buffer 0 1)))
           (fqdn-asciiname (unwrap (slice buffer 0 1)))
           (option-novell-dss-string (unwrap (slice buffer 0 1)))
           (option-novell-dss-ip (unwrap (read-u32be buffer 0)))
           (option-dhcp-authentication-algorithm (unwrap (read-u8 buffer 0)))
           (option-dhcp-authentication-rdm-replay-detection (unwrap (read-u64be buffer 0)))
           (option-dhcp-authentication-rdm-rdv (unwrap (slice buffer 0 8)))
           (option-client-network-id-major-ver (unwrap (read-u8 buffer 0)))
           (option-client-network-id-minor-ver (unwrap (read-u8 buffer 0)))
           (option-civic-location-country (unwrap (slice buffer 0 2)))
           (option-dhcp-name-service-search-option (unwrap (slice buffer 0 2)))
           (option-dhcp-dns-domain-search-list-fqdn (unwrap (slice buffer 0 1)))
           (option-classless-static-route (unwrap (slice buffer 0 1)))
           (option-rfc3825-latitude (unwrap (read-u64be buffer 0)))
           (option-rfc3825-longitude (unwrap (read-u64be buffer 0)))
           (option-rfc3825-latitude-res (unwrap (read-u64be buffer 0)))
           (option-rfc3825-longitude-res (unwrap (read-u64be buffer 0)))
           (option-rfc3825-altitude (unwrap (read-u64be buffer 0)))
           (option-rfc3825-altitude-res (unwrap (read-u64be buffer 0)))
           (option-cl-dss-id-len (unwrap (read-u8 buffer 0)))
           (option-cl-dss-id (unwrap (slice buffer 0 1)))
           (option-rdnss-reserved (unwrap (read-u8 buffer 0)))
           (dnr-instance-len (unwrap (read-u16be buffer 0)))
           (option-pcp-list-length (unwrap (read-u8 buffer 0)))
           (option-6RD-ipv4-mask-len (unwrap (read-u8 buffer 0)))
           (option-6RD-prefix-len (unwrap (read-u8 buffer 0)))
           (option-6RD-prefix (unwrap (slice buffer 0 16)))
           (option-6RD-border-relay-ip (unwrap (read-u32be buffer 0)))
           (option242-avaya (unwrap (slice buffer 0 1)))
           (option-isns-functions (unwrap (read-u16be buffer 0)))
           (option-isns-functions-enabled (extract-bits option-isns-functions 0x0 0))
           (option-isns-functions-dd-authorization (extract-bits option-isns-functions 0x0 0))
           (option-isns-functions-sec-policy-distibution (extract-bits option-isns-functions 0x0 0))
           (option-isns-functions-reserved (extract-bits option-isns-functions 0x0 0))
           (option43-arubaap-controllerip (unwrap (slice buffer 0 1)))
           (option43-arubaiap (unwrap (slice buffer 0 1)))
           (option43-arubaiap-nameorg (unwrap (slice buffer 0 1)))
           (option43-arubaiap-ampip (unwrap (slice buffer 0 1)))
           (option43-arubaiap-password (unwrap (slice buffer 0 1)))
           (suboption-length (unwrap (read-u8 buffer 0)))
           (option125-value (unwrap (slice buffer 0 1)))
           (option-portparams-psid-length (unwrap (read-u8 buffer 1)))
           (option-bulk-lease-status-message (unwrap (slice buffer 1 1)))
           (option-sip-server-name (unwrap (slice buffer 1 1)))
           (option-sip-server-address (unwrap (read-u32be buffer 1)))
           (option-rdnss-prim-dns-server (unwrap (read-u32be buffer 1)))
           (option-pcp-server (unwrap (read-u32be buffer 1)))
           (hw-len (unwrap (read-u8 buffer 2)))
           (option-portparams-psid (unwrap (slice buffer 2 2)))
           (option77-user-class-binary-data (unwrap (slice buffer 2 1)))
           (option77-user-class-padding (unwrap (slice buffer 2 1)))
           (option77-user-class-name-length (unwrap (read-u16be buffer 2)))
           (option-civic-location-ca-length (unwrap (read-u8 buffer 2)))
           (option-civic-location-ca-value (unwrap (slice buffer 2 1)))
           (dnr-svcpriority (unwrap (read-u16be buffer 2)))
           (option-isns-discovery-domain-access (unwrap (read-u16be buffer 2)))
           (option-isns-discovery-domain-access-enabled (extract-bits option-isns-discovery-domain-access 0x0 0))
           (option-isns-discovery-domain-access-control-node (extract-bits option-isns-discovery-domain-access 0x0 0))
           (option-isns-discovery-domain-access-iscsi-target (extract-bits option-isns-discovery-domain-access 0x0 0))
           (option-isns-discovery-domain-access-iscsi-inititator (extract-bits option-isns-discovery-domain-access 0x0 0))
           (option-isns-discovery-domain-access-ifcp-target-port (extract-bits option-isns-discovery-domain-access 0x0 0))
           (option-isns-discovery-domain-access-ifcp-initiator-port (extract-bits option-isns-discovery-domain-access 0x0 0))
           (option-isns-discovery-domain-access-reserved (extract-bits option-isns-discovery-domain-access 0x0 0))
           (hops (unwrap (read-u8 buffer 3)))
           (id (unwrap (read-u32be buffer 4)))
           (option-policy-filter-subnet-mask (unwrap (read-u32be buffer 4)))
           (option-static-route-router (unwrap (read-u32be buffer 4)))
           (option77-user-class-name (unwrap (slice buffer 4 1)))
           (option77-user-class-description-length (unwrap (read-u16be buffer 4)))
           (option-vi-class-data-length (unwrap (read-u8 buffer 4)))
           (dnr-auth-domain-name-len (unwrap (read-u8 buffer 4)))
           (dnr-auth-domain-name (unwrap (slice buffer 4 1)))
           (dnr-addrs-len (unwrap (read-u8 buffer 4)))
           (option-isns-administrative-flags (unwrap (read-u16be buffer 4)))
           (option-isns-administrative-flags-enabled (extract-bits option-isns-administrative-flags 0x0 0))
           (option-isns-administrative-flags-heartbeat (extract-bits option-isns-administrative-flags 0x0 0))
           (option-isns-administrative-flags-management-scns (extract-bits option-isns-administrative-flags 0x0 0))
           (option-isns-administrative-flags-default-dd (extract-bits option-isns-administrative-flags 0x0 0))
           (option-isns-administrative-flags-reserved (extract-bits option-isns-administrative-flags 0x0 0))
           (option125-length (unwrap (read-u8 buffer 4)))
           (client-identifier-time (unwrap (read-u32be buffer 5)))
           (client-identifier-link-layer-address (unwrap (slice buffer 5 1)))
           (client-identifier-link-layer-address-ether (unwrap (slice buffer 5 6)))
           (client-identifier (unwrap (slice buffer 5 1)))
           (client-identifier-type (unwrap (read-u8 buffer 5)))
           (client-identifier-undef (unwrap (slice buffer 5 1)))
           (option-vi-class-data-item-length (unwrap (read-u8 buffer 5)))
           (option-rdnss-sec-dns-server (unwrap (read-u32be buffer 5)))
           (option77-user-class-description (unwrap (slice buffer 6 1)))
           (option77-user-class-text (unwrap (slice buffer 6 1)))
           (option77-user-class (unwrap (read-u8 buffer 6)))
           (option77-user-class-length (unwrap (read-u8 buffer 6)))
           (option77-user-class-data (unwrap (slice buffer 6 1)))
           (option-vi-class-data-item-data (unwrap (slice buffer 6 1)))
           (option-isns-server-security-bitmap (unwrap (read-u32be buffer 6)))
           (option-isns-server-security-bitmap-enabled (extract-bits option-isns-server-security-bitmap 0x0 0))
           (option-isns-server-security-bitmap-ike-ipsec-enabled (extract-bits option-isns-server-security-bitmap 0x0 0))
           (option-isns-server-security-bitmap-main-mode (extract-bits option-isns-server-security-bitmap 0x0 0))
           (option-isns-server-security-bitmap-aggressive-mode (extract-bits option-isns-server-security-bitmap 0x0 0))
           (option-isns-server-security-bitmap-pfs (extract-bits option-isns-server-security-bitmap 0x0 0))
           (option-isns-server-security-bitmap-transport-mode (extract-bits option-isns-server-security-bitmap 0x0 0))
           (option-isns-server-security-bitmap-tunnel-mode (extract-bits option-isns-server-security-bitmap 0x0 0))
           (option-isns-server-security-bitmap-reserved (extract-bits option-isns-server-security-bitmap 0x0 0))
           (secs (unwrap (read-u16be buffer 8)))
           (option-dhcp-authentication-secret-id (unwrap (read-u32be buffer 8)))
           (option-rdnss-domain (unwrap (slice buffer 9 1)))
           (flags (unwrap (read-u16be buffer 10)))
           (flags-broadcast (extract-bits flags 0x0 0))
           (flags-reserved (extract-bits flags 0x0 0))
           (option-isns-heartbeat-originator-addr (unwrap (read-u32be buffer 10)))
           (ip-client (unwrap (read-u32be buffer 12)))
           (option-dhcp-authentication-hmac-md5-hash (unwrap (slice buffer 12 16)))
           (option-dhcp-authentication-information (unwrap (slice buffer 12 1)))
           (option-isns-primary-server-addr (unwrap (read-u32be buffer 14)))
           (ip-your (unwrap (read-u32be buffer 16)))
           (ip-server (unwrap (read-u32be buffer 20)))
           (ip-relay (unwrap (read-u32be buffer 24)))
           (hw-addr (unwrap (slice buffer 28 16)))
           )

      (ok (list
        (cons 'bootp (list (cons 'raw bootp) (cons 'formatted (number->string bootp))))
        (cons 'option-vendor-class-data (list (cons 'raw option-vendor-class-data) (cons 'formatted (utf8->string option-vendor-class-data))))
        (cons 'option-portparams-offset (list (cons 'raw option-portparams-offset) (cons 'formatted (number->string option-portparams-offset))))
        (cons 'option-captive-portal (list (cons 'raw option-captive-portal) (cons 'formatted (utf8->string option-captive-portal))))
        (cons 'option-vendor-class-id (list (cons 'raw option-vendor-class-id) (cons 'formatted (utf8->string option-vendor-class-id))))
        (cons 'option-policy-filter-ip (list (cons 'raw option-policy-filter-ip) (cons 'formatted (fmt-ipv4 option-policy-filter-ip))))
        (cons 'option-static-route-ip (list (cons 'raw option-static-route-ip) (cons 'formatted (fmt-ipv4 option-static-route-ip))))
        (cons 'option43-value (list (cons 'raw option43-value) (cons 'formatted (fmt-bytes option43-value))))
        (cons 'option-parameter-request-list-item (list (cons 'raw option-parameter-request-list-item) (cons 'formatted (number->string option-parameter-request-list-item))))
        (cons 'hw-ether-addr (list (cons 'raw hw-ether-addr) (cons 'formatted (fmt-mac hw-ether-addr))))
        (cons 'client-hardware-address (list (cons 'raw client-hardware-address) (cons 'formatted (utf8->string client-hardware-address))))
        (cons 'client-identifier-uuid (list (cons 'raw client-identifier-uuid) (cons 'formatted (fmt-bytes client-identifier-uuid))))
        (cons 'client-id-iaid (list (cons 'raw client-id-iaid) (cons 'formatted (utf8->string client-id-iaid))))
        (cons 'option77-user-class-binary-data-length (list (cons 'raw option77-user-class-binary-data-length) (cons 'formatted (number->string option77-user-class-binary-data-length))))
        (cons 'option-slp-directory-agent-slpda-address (list (cons 'raw option-slp-directory-agent-slpda-address) (cons 'formatted (fmt-ipv4 option-slp-directory-agent-slpda-address))))
        (cons 'option-slp-service-scope-string (list (cons 'raw option-slp-service-scope-string) (cons 'formatted (utf8->string option-slp-service-scope-string))))
        (cons 'fqdn-flags (list (cons 'raw fqdn-flags) (cons 'formatted (fmt-hex fqdn-flags))))
        (cons 'fqdn-mbz (list (cons 'raw fqdn-mbz) (cons 'formatted (if (= fqdn-mbz 0) "Not set" "Set"))))
        (cons 'fqdn-n (list (cons 'raw fqdn-n) (cons 'formatted (if (= fqdn-n 0) "Some server updates" "No server updates"))))
        (cons 'fqdn-e (list (cons 'raw fqdn-e) (cons 'formatted (if (= fqdn-e 0) "ASCII encoding" "Binary encoding"))))
        (cons 'fqdn-o (list (cons 'raw fqdn-o) (cons 'formatted (if (= fqdn-o 0) "No override" "Override"))))
        (cons 'fqdn-s (list (cons 'raw fqdn-s) (cons 'formatted (if (= fqdn-s 0) "Not set" "Set"))))
        (cons 'fqdn-rcode1 (list (cons 'raw fqdn-rcode1) (cons 'formatted (number->string fqdn-rcode1))))
        (cons 'fqdn-rcode2 (list (cons 'raw fqdn-rcode2) (cons 'formatted (number->string fqdn-rcode2))))
        (cons 'fqdn-name (list (cons 'raw fqdn-name) (cons 'formatted (utf8->string fqdn-name))))
        (cons 'fqdn-asciiname (list (cons 'raw fqdn-asciiname) (cons 'formatted (utf8->string fqdn-asciiname))))
        (cons 'option-novell-dss-string (list (cons 'raw option-novell-dss-string) (cons 'formatted (utf8->string option-novell-dss-string))))
        (cons 'option-novell-dss-ip (list (cons 'raw option-novell-dss-ip) (cons 'formatted (fmt-ipv4 option-novell-dss-ip))))
        (cons 'option-dhcp-authentication-algorithm (list (cons 'raw option-dhcp-authentication-algorithm) (cons 'formatted (number->string option-dhcp-authentication-algorithm))))
        (cons 'option-dhcp-authentication-rdm-replay-detection (list (cons 'raw option-dhcp-authentication-rdm-replay-detection) (cons 'formatted (fmt-hex option-dhcp-authentication-rdm-replay-detection))))
        (cons 'option-dhcp-authentication-rdm-rdv (list (cons 'raw option-dhcp-authentication-rdm-rdv) (cons 'formatted (utf8->string option-dhcp-authentication-rdm-rdv))))
        (cons 'option-client-network-id-major-ver (list (cons 'raw option-client-network-id-major-ver) (cons 'formatted (number->string option-client-network-id-major-ver))))
        (cons 'option-client-network-id-minor-ver (list (cons 'raw option-client-network-id-minor-ver) (cons 'formatted (number->string option-client-network-id-minor-ver))))
        (cons 'option-civic-location-country (list (cons 'raw option-civic-location-country) (cons 'formatted (utf8->string option-civic-location-country))))
        (cons 'option-dhcp-name-service-search-option (list (cons 'raw option-dhcp-name-service-search-option) (cons 'formatted (utf8->string option-dhcp-name-service-search-option))))
        (cons 'option-dhcp-dns-domain-search-list-fqdn (list (cons 'raw option-dhcp-dns-domain-search-list-fqdn) (cons 'formatted (utf8->string option-dhcp-dns-domain-search-list-fqdn))))
        (cons 'option-classless-static-route (list (cons 'raw option-classless-static-route) (cons 'formatted (fmt-bytes option-classless-static-route))))
        (cons 'option-rfc3825-latitude (list (cons 'raw option-rfc3825-latitude) (cons 'formatted (number->string option-rfc3825-latitude))))
        (cons 'option-rfc3825-longitude (list (cons 'raw option-rfc3825-longitude) (cons 'formatted (number->string option-rfc3825-longitude))))
        (cons 'option-rfc3825-latitude-res (list (cons 'raw option-rfc3825-latitude-res) (cons 'formatted (number->string option-rfc3825-latitude-res))))
        (cons 'option-rfc3825-longitude-res (list (cons 'raw option-rfc3825-longitude-res) (cons 'formatted (number->string option-rfc3825-longitude-res))))
        (cons 'option-rfc3825-altitude (list (cons 'raw option-rfc3825-altitude) (cons 'formatted (number->string option-rfc3825-altitude))))
        (cons 'option-rfc3825-altitude-res (list (cons 'raw option-rfc3825-altitude-res) (cons 'formatted (number->string option-rfc3825-altitude-res))))
        (cons 'option-cl-dss-id-len (list (cons 'raw option-cl-dss-id-len) (cons 'formatted (number->string option-cl-dss-id-len))))
        (cons 'option-cl-dss-id (list (cons 'raw option-cl-dss-id) (cons 'formatted (utf8->string option-cl-dss-id))))
        (cons 'option-rdnss-reserved (list (cons 'raw option-rdnss-reserved) (cons 'formatted (fmt-hex option-rdnss-reserved))))
        (cons 'dnr-instance-len (list (cons 'raw dnr-instance-len) (cons 'formatted (number->string dnr-instance-len))))
        (cons 'option-pcp-list-length (list (cons 'raw option-pcp-list-length) (cons 'formatted (number->string option-pcp-list-length))))
        (cons 'option-6RD-ipv4-mask-len (list (cons 'raw option-6RD-ipv4-mask-len) (cons 'formatted (number->string option-6RD-ipv4-mask-len))))
        (cons 'option-6RD-prefix-len (list (cons 'raw option-6RD-prefix-len) (cons 'formatted (number->string option-6RD-prefix-len))))
        (cons 'option-6RD-prefix (list (cons 'raw option-6RD-prefix) (cons 'formatted (fmt-ipv6-address option-6RD-prefix))))
        (cons 'option-6RD-border-relay-ip (list (cons 'raw option-6RD-border-relay-ip) (cons 'formatted (fmt-ipv4 option-6RD-border-relay-ip))))
        (cons 'option242-avaya (list (cons 'raw option242-avaya) (cons 'formatted (utf8->string option242-avaya))))
        (cons 'option-isns-functions (list (cons 'raw option-isns-functions) (cons 'formatted (fmt-hex option-isns-functions))))
        (cons 'option-isns-functions-enabled (list (cons 'raw option-isns-functions-enabled) (cons 'formatted (if (= option-isns-functions-enabled 0) "Not set" "Set"))))
        (cons 'option-isns-functions-dd-authorization (list (cons 'raw option-isns-functions-dd-authorization) (cons 'formatted (if (= option-isns-functions-dd-authorization 0) "Not set" "Set"))))
        (cons 'option-isns-functions-sec-policy-distibution (list (cons 'raw option-isns-functions-sec-policy-distibution) (cons 'formatted (if (= option-isns-functions-sec-policy-distibution 0) "Not set" "Set"))))
        (cons 'option-isns-functions-reserved (list (cons 'raw option-isns-functions-reserved) (cons 'formatted (if (= option-isns-functions-reserved 0) "Not set" "Set"))))
        (cons 'option43-arubaap-controllerip (list (cons 'raw option43-arubaap-controllerip) (cons 'formatted (utf8->string option43-arubaap-controllerip))))
        (cons 'option43-arubaiap (list (cons 'raw option43-arubaiap) (cons 'formatted (utf8->string option43-arubaiap))))
        (cons 'option43-arubaiap-nameorg (list (cons 'raw option43-arubaiap-nameorg) (cons 'formatted (utf8->string option43-arubaiap-nameorg))))
        (cons 'option43-arubaiap-ampip (list (cons 'raw option43-arubaiap-ampip) (cons 'formatted (utf8->string option43-arubaiap-ampip))))
        (cons 'option43-arubaiap-password (list (cons 'raw option43-arubaiap-password) (cons 'formatted (utf8->string option43-arubaiap-password))))
        (cons 'suboption-length (list (cons 'raw suboption-length) (cons 'formatted (number->string suboption-length))))
        (cons 'option125-value (list (cons 'raw option125-value) (cons 'formatted (fmt-bytes option125-value))))
        (cons 'option-portparams-psid-length (list (cons 'raw option-portparams-psid-length) (cons 'formatted (number->string option-portparams-psid-length))))
        (cons 'option-bulk-lease-status-message (list (cons 'raw option-bulk-lease-status-message) (cons 'formatted (utf8->string option-bulk-lease-status-message))))
        (cons 'option-sip-server-name (list (cons 'raw option-sip-server-name) (cons 'formatted (utf8->string option-sip-server-name))))
        (cons 'option-sip-server-address (list (cons 'raw option-sip-server-address) (cons 'formatted (fmt-ipv4 option-sip-server-address))))
        (cons 'option-rdnss-prim-dns-server (list (cons 'raw option-rdnss-prim-dns-server) (cons 'formatted (fmt-ipv4 option-rdnss-prim-dns-server))))
        (cons 'option-pcp-server (list (cons 'raw option-pcp-server) (cons 'formatted (fmt-ipv4 option-pcp-server))))
        (cons 'hw-len (list (cons 'raw hw-len) (cons 'formatted (number->string hw-len))))
        (cons 'option-portparams-psid (list (cons 'raw option-portparams-psid) (cons 'formatted (fmt-bytes option-portparams-psid))))
        (cons 'option77-user-class-binary-data (list (cons 'raw option77-user-class-binary-data) (cons 'formatted (fmt-bytes option77-user-class-binary-data))))
        (cons 'option77-user-class-padding (list (cons 'raw option77-user-class-padding) (cons 'formatted (fmt-bytes option77-user-class-padding))))
        (cons 'option77-user-class-name-length (list (cons 'raw option77-user-class-name-length) (cons 'formatted (number->string option77-user-class-name-length))))
        (cons 'option-civic-location-ca-length (list (cons 'raw option-civic-location-ca-length) (cons 'formatted (number->string option-civic-location-ca-length))))
        (cons 'option-civic-location-ca-value (list (cons 'raw option-civic-location-ca-value) (cons 'formatted (utf8->string option-civic-location-ca-value))))
        (cons 'dnr-svcpriority (list (cons 'raw dnr-svcpriority) (cons 'formatted (number->string dnr-svcpriority))))
        (cons 'option-isns-discovery-domain-access (list (cons 'raw option-isns-discovery-domain-access) (cons 'formatted (fmt-hex option-isns-discovery-domain-access))))
        (cons 'option-isns-discovery-domain-access-enabled (list (cons 'raw option-isns-discovery-domain-access-enabled) (cons 'formatted (if (= option-isns-discovery-domain-access-enabled 0) "Not set" "Set"))))
        (cons 'option-isns-discovery-domain-access-control-node (list (cons 'raw option-isns-discovery-domain-access-control-node) (cons 'formatted (if (= option-isns-discovery-domain-access-control-node 0) "Not set" "Set"))))
        (cons 'option-isns-discovery-domain-access-iscsi-target (list (cons 'raw option-isns-discovery-domain-access-iscsi-target) (cons 'formatted (if (= option-isns-discovery-domain-access-iscsi-target 0) "Not set" "Set"))))
        (cons 'option-isns-discovery-domain-access-iscsi-inititator (list (cons 'raw option-isns-discovery-domain-access-iscsi-inititator) (cons 'formatted (if (= option-isns-discovery-domain-access-iscsi-inititator 0) "Not set" "Set"))))
        (cons 'option-isns-discovery-domain-access-ifcp-target-port (list (cons 'raw option-isns-discovery-domain-access-ifcp-target-port) (cons 'formatted (if (= option-isns-discovery-domain-access-ifcp-target-port 0) "Not set" "Set"))))
        (cons 'option-isns-discovery-domain-access-ifcp-initiator-port (list (cons 'raw option-isns-discovery-domain-access-ifcp-initiator-port) (cons 'formatted (if (= option-isns-discovery-domain-access-ifcp-initiator-port 0) "Not set" "Set"))))
        (cons 'option-isns-discovery-domain-access-reserved (list (cons 'raw option-isns-discovery-domain-access-reserved) (cons 'formatted (if (= option-isns-discovery-domain-access-reserved 0) "Not set" "Set"))))
        (cons 'hops (list (cons 'raw hops) (cons 'formatted (number->string hops))))
        (cons 'id (list (cons 'raw id) (cons 'formatted (fmt-hex id))))
        (cons 'option-policy-filter-subnet-mask (list (cons 'raw option-policy-filter-subnet-mask) (cons 'formatted (fmt-ipv4 option-policy-filter-subnet-mask))))
        (cons 'option-static-route-router (list (cons 'raw option-static-route-router) (cons 'formatted (fmt-ipv4 option-static-route-router))))
        (cons 'option77-user-class-name (list (cons 'raw option77-user-class-name) (cons 'formatted (utf8->string option77-user-class-name))))
        (cons 'option77-user-class-description-length (list (cons 'raw option77-user-class-description-length) (cons 'formatted (number->string option77-user-class-description-length))))
        (cons 'option-vi-class-data-length (list (cons 'raw option-vi-class-data-length) (cons 'formatted (number->string option-vi-class-data-length))))
        (cons 'dnr-auth-domain-name-len (list (cons 'raw dnr-auth-domain-name-len) (cons 'formatted (number->string dnr-auth-domain-name-len))))
        (cons 'dnr-auth-domain-name (list (cons 'raw dnr-auth-domain-name) (cons 'formatted (utf8->string dnr-auth-domain-name))))
        (cons 'dnr-addrs-len (list (cons 'raw dnr-addrs-len) (cons 'formatted (number->string dnr-addrs-len))))
        (cons 'option-isns-administrative-flags (list (cons 'raw option-isns-administrative-flags) (cons 'formatted (fmt-hex option-isns-administrative-flags))))
        (cons 'option-isns-administrative-flags-enabled (list (cons 'raw option-isns-administrative-flags-enabled) (cons 'formatted (if (= option-isns-administrative-flags-enabled 0) "Not set" "Set"))))
        (cons 'option-isns-administrative-flags-heartbeat (list (cons 'raw option-isns-administrative-flags-heartbeat) (cons 'formatted (if (= option-isns-administrative-flags-heartbeat 0) "Not set" "Set"))))
        (cons 'option-isns-administrative-flags-management-scns (list (cons 'raw option-isns-administrative-flags-management-scns) (cons 'formatted (if (= option-isns-administrative-flags-management-scns 0) "Not set" "Set"))))
        (cons 'option-isns-administrative-flags-default-dd (list (cons 'raw option-isns-administrative-flags-default-dd) (cons 'formatted (if (= option-isns-administrative-flags-default-dd 0) "Not set" "Set"))))
        (cons 'option-isns-administrative-flags-reserved (list (cons 'raw option-isns-administrative-flags-reserved) (cons 'formatted (if (= option-isns-administrative-flags-reserved 0) "Not set" "Set"))))
        (cons 'option125-length (list (cons 'raw option125-length) (cons 'formatted (number->string option125-length))))
        (cons 'client-identifier-time (list (cons 'raw client-identifier-time) (cons 'formatted (number->string client-identifier-time))))
        (cons 'client-identifier-link-layer-address (list (cons 'raw client-identifier-link-layer-address) (cons 'formatted (utf8->string client-identifier-link-layer-address))))
        (cons 'client-identifier-link-layer-address-ether (list (cons 'raw client-identifier-link-layer-address-ether) (cons 'formatted (fmt-mac client-identifier-link-layer-address-ether))))
        (cons 'client-identifier (list (cons 'raw client-identifier) (cons 'formatted (fmt-bytes client-identifier))))
        (cons 'client-identifier-type (list (cons 'raw client-identifier-type) (cons 'formatted (number->string client-identifier-type))))
        (cons 'client-identifier-undef (list (cons 'raw client-identifier-undef) (cons 'formatted (utf8->string client-identifier-undef))))
        (cons 'option-vi-class-data-item-length (list (cons 'raw option-vi-class-data-item-length) (cons 'formatted (number->string option-vi-class-data-item-length))))
        (cons 'option-rdnss-sec-dns-server (list (cons 'raw option-rdnss-sec-dns-server) (cons 'formatted (fmt-ipv4 option-rdnss-sec-dns-server))))
        (cons 'option77-user-class-description (list (cons 'raw option77-user-class-description) (cons 'formatted (utf8->string option77-user-class-description))))
        (cons 'option77-user-class-text (list (cons 'raw option77-user-class-text) (cons 'formatted (utf8->string option77-user-class-text))))
        (cons 'option77-user-class (list (cons 'raw option77-user-class) (cons 'formatted (number->string option77-user-class))))
        (cons 'option77-user-class-length (list (cons 'raw option77-user-class-length) (cons 'formatted (number->string option77-user-class-length))))
        (cons 'option77-user-class-data (list (cons 'raw option77-user-class-data) (cons 'formatted (fmt-bytes option77-user-class-data))))
        (cons 'option-vi-class-data-item-data (list (cons 'raw option-vi-class-data-item-data) (cons 'formatted (fmt-bytes option-vi-class-data-item-data))))
        (cons 'option-isns-server-security-bitmap (list (cons 'raw option-isns-server-security-bitmap) (cons 'formatted (fmt-hex option-isns-server-security-bitmap))))
        (cons 'option-isns-server-security-bitmap-enabled (list (cons 'raw option-isns-server-security-bitmap-enabled) (cons 'formatted (if (= option-isns-server-security-bitmap-enabled 0) "Not set" "Set"))))
        (cons 'option-isns-server-security-bitmap-ike-ipsec-enabled (list (cons 'raw option-isns-server-security-bitmap-ike-ipsec-enabled) (cons 'formatted (if (= option-isns-server-security-bitmap-ike-ipsec-enabled 0) "Not set" "Set"))))
        (cons 'option-isns-server-security-bitmap-main-mode (list (cons 'raw option-isns-server-security-bitmap-main-mode) (cons 'formatted (if (= option-isns-server-security-bitmap-main-mode 0) "Not set" "Set"))))
        (cons 'option-isns-server-security-bitmap-aggressive-mode (list (cons 'raw option-isns-server-security-bitmap-aggressive-mode) (cons 'formatted (if (= option-isns-server-security-bitmap-aggressive-mode 0) "Not set" "Set"))))
        (cons 'option-isns-server-security-bitmap-pfs (list (cons 'raw option-isns-server-security-bitmap-pfs) (cons 'formatted (if (= option-isns-server-security-bitmap-pfs 0) "Not set" "Set"))))
        (cons 'option-isns-server-security-bitmap-transport-mode (list (cons 'raw option-isns-server-security-bitmap-transport-mode) (cons 'formatted (if (= option-isns-server-security-bitmap-transport-mode 0) "Not set" "Set"))))
        (cons 'option-isns-server-security-bitmap-tunnel-mode (list (cons 'raw option-isns-server-security-bitmap-tunnel-mode) (cons 'formatted (if (= option-isns-server-security-bitmap-tunnel-mode 0) "Not set" "Set"))))
        (cons 'option-isns-server-security-bitmap-reserved (list (cons 'raw option-isns-server-security-bitmap-reserved) (cons 'formatted (if (= option-isns-server-security-bitmap-reserved 0) "Not set" "Set"))))
        (cons 'secs (list (cons 'raw secs) (cons 'formatted (number->string secs))))
        (cons 'option-dhcp-authentication-secret-id (list (cons 'raw option-dhcp-authentication-secret-id) (cons 'formatted (fmt-hex option-dhcp-authentication-secret-id))))
        (cons 'option-rdnss-domain (list (cons 'raw option-rdnss-domain) (cons 'formatted (utf8->string option-rdnss-domain))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (fmt-hex flags))))
        (cons 'flags-broadcast (list (cons 'raw flags-broadcast) (cons 'formatted (if (= flags-broadcast 0) "Unicast" "Broadcast"))))
        (cons 'flags-reserved (list (cons 'raw flags-reserved) (cons 'formatted (if (= flags-reserved 0) "Not set" "Set"))))
        (cons 'option-isns-heartbeat-originator-addr (list (cons 'raw option-isns-heartbeat-originator-addr) (cons 'formatted (fmt-ipv4 option-isns-heartbeat-originator-addr))))
        (cons 'ip-client (list (cons 'raw ip-client) (cons 'formatted (fmt-ipv4 ip-client))))
        (cons 'option-dhcp-authentication-hmac-md5-hash (list (cons 'raw option-dhcp-authentication-hmac-md5-hash) (cons 'formatted (fmt-bytes option-dhcp-authentication-hmac-md5-hash))))
        (cons 'option-dhcp-authentication-information (list (cons 'raw option-dhcp-authentication-information) (cons 'formatted (utf8->string option-dhcp-authentication-information))))
        (cons 'option-isns-primary-server-addr (list (cons 'raw option-isns-primary-server-addr) (cons 'formatted (fmt-ipv4 option-isns-primary-server-addr))))
        (cons 'ip-your (list (cons 'raw ip-your) (cons 'formatted (fmt-ipv4 ip-your))))
        (cons 'ip-server (list (cons 'raw ip-server) (cons 'formatted (fmt-ipv4 ip-server))))
        (cons 'ip-relay (list (cons 'raw ip-relay) (cons 'formatted (fmt-ipv4 ip-relay))))
        (cons 'hw-addr (list (cons 'raw hw-addr) (cons 'formatted (fmt-bytes hw-addr))))
        )))

    (catch (e)
      (err (str "DHCP parse error: " e)))))

;; dissect-dhcp: parse DHCP from bytevector
;; Returns (ok fields-alist) or (err message)