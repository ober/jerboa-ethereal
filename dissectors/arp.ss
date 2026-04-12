;; jerboa-ethereal/dissectors/arp.ss
;; RFC 826: An Ethernet Address Resolution Protocol
;;
;; Maps IP addresses to hardware (MAC) addresses
;; Supports Ethernet, IP, and other address types

(import (jerboa prelude)
        (lib dissector protocol))

;; ── Hardware Type Constants ────────────────────────────────────────────

(def (format-hw-type type-val)
  "Format ARP hardware type"
  (case type-val
    ((1) "Ethernet")
    ((2) "Experimental Ethernet")
    ((3) "AX.25")
    ((4) "ProNET Token Ring")
    ((5) "Chaos")
    ((6) "IEEE 802 Networks")
    ((7) "ARCNET")
    ((8) "Hyperchannel")
    ((9) "Lanstar")
    ((10) "Autonet Short Address")
    ((11) "LocalTalk")
    ((12) "LocalNet (IBM)")
    ((13) "Ultra link")
    ((14) "SMDS")
    ((15) "Frame Relay")
    ((16) "ATM")
    ((17) "HDLC")
    ((18) "Fibre Channel")
    ((19) "ATM")
    ((20) "Serial Line")
    ((21) "ATM")
    ((22) "MIL-STD-188-220")
    ((23) "Metricom")
    ((24) "IEEE 1394.1995")
    ((25) "MAPOS")
    ((26) "Twinaxial")
    ((27) "EUI-64")
    ((28) "HIPARP")
    ((29) "IP and ARP over ISO 7816-3")
    ((30) "ARPSec")
    ((31) "IPsec tunnel")
    ((32) "Infiniband")
    ((33) "CAT")
    ((34) "IEEE 802.15.4")
    ((35) "IEEE 802.15.4 Frame")
    (else (str "Type " type-val))))

(def (format-proto-type type-val)
  "Format ARP protocol type (EtherType)"
  (case type-val
    ((#x0800) "IPv4")
    ((#x0806) "ARP")
    ((#x86DD) "IPv6")
    ((#x8137) "IPX")
    ((#x0802) "X.25 Level 3")
    (else (str "0x" (string-pad (number->string type-val 16) 4 #\0)))))

(def (format-arp-operation op-val)
  "Format ARP operation code"
  (case op-val
    ((1) "Request")
    ((2) "Reply")
    ((3) "Request Reverse")
    ((4) "Reply Reverse")
    ((5) "DRARP-Request")
    ((6) "DRARP-Reply")
    ((7) "DRARP-Error")
    ((8) "InARP-Request")
    ((9) "InARP-Reply")
    ((10) "ARP-NAK")
    ((11) "MARS-Request")
    ((12) "MARS-Multi")
    ((13) "MARS-MServ")
    ((14) "MARS-Unserv")
    ((15) "Mars-SJoin")
    ((16) "Mars-SLeave")
    ((17) "MARS-Grouplist-Request")
    ((18) "MARS-Grouplist-Reply")
    ((19) "MARS-Redirect-Map")
    ((20) "MAPOS-UNARP")
    ((24) "OP_EXP1")
    ((25) "OP_EXP2")
    ((0xf000) "Reserved for Experiments")
    ((0xffff) "Reserved for Vendor")
    (else (str "Op " op-val))))

;; ── Core ARP Dissector ────────────────────────────────────────────────

(def (dissect-arp buffer)
  "Parse ARP message from bytevector
   Returns (ok fields) or (err message)

   Structure (28 bytes minimum for Ethernet/IPv4):
   [0:2)   hardware type (Ethernet, token ring, etc.)
   [2:4)   protocol type (IPv4, IPv6, IPX, etc.)
   [4]     hardware address length (6 for Ethernet)
   [5]     protocol address length (4 for IPv4)
   [6:8)   operation (Request, Reply, etc.)
   [8:)    sender hardware address (variable length)
   [*:)    sender protocol address (variable length)
   [*:)    target hardware address (variable length)
   [*:)    target protocol address (variable length)"

  (try
    ;; Validate minimum fixed header (8 bytes)
    (_ (unwrap (validate (>= (bytevector-length buffer) 8)
                         "ARP message too short (< 8 bytes)")))

    (let* ((hw-type-res (read-u16be buffer 0))
           (hw-type (unwrap hw-type-res))

           (proto-type-res (read-u16be buffer 2))
           (proto-type (unwrap proto-type-res))

           (hw-addr-len-res (read-u8 buffer 4))
           (hw-addr-len (unwrap hw-addr-len-res))

           (proto-addr-len-res (read-u8 buffer 5))
           (proto-addr-len (unwrap proto-addr-len-res))

           (operation-res (read-u16be buffer 6))
           (operation (unwrap operation-res)))

      ;; Validate total message length
      (let ((expected-len (+ 8 (* 2 hw-addr-len) (* 2 proto-addr-len))))
        (_ (unwrap (validate (>= (bytevector-length buffer) expected-len)
                             (str "ARP message truncated (expected " expected-len " bytes)")))))

      ;; Parse variable-length addresses
      (let ((addresses (parse-arp-addresses buffer 8 hw-addr-len proto-addr-len)))
        (ok `((hardware-type . ((raw . ,hw-type)
                              (formatted . ,(format-hw-type hw-type))))
              (protocol-type . ((raw . ,proto-type)
                               (formatted . ,(format-proto-type proto-type))))
              (hardware-address-length . ,hw-addr-len)
              (protocol-address-length . ,proto-addr-len)
              (operation . ((raw . ,operation)
                           (formatted . ,(format-arp-operation operation))))
              ,@addresses))))

    ;; Error handling
    (catch (e)
      (err (str "ARP parse error: " e)))))

;; ── Variable Address Parsing ──────────────────────────────────────────

(def (parse-arp-addresses buffer offset hw-len proto-len)
  "Parse sender and target addresses from ARP message
   Returns alist with sender/target hardware and protocol addresses"

  (try
    (let* (;; Sender hardware address
           (sender-hw-start offset)
           (sender-hw (unwrap (slice buffer sender-hw-start hw-len)))

           ;; Sender protocol address
           (sender-proto-start (+ sender-hw-start hw-len))
           (sender-proto (unwrap (slice buffer sender-proto-start proto-len)))

           ;; Target hardware address
           (target-hw-start (+ sender-proto-start proto-len))
           (target-hw (unwrap (slice buffer target-hw-start hw-len)))

           ;; Target protocol address
           (target-proto-start (+ target-hw-start hw-len))
           (target-proto (unwrap (slice buffer target-proto-start proto-len))))

      `((sender-hardware-address . ((raw . ,sender-hw)
                                   (formatted . ,(format-address sender-hw hw-len))))
        (sender-protocol-address . ((raw . ,sender-proto)
                                   (formatted . ,(format-address sender-proto proto-len))))
        (target-hardware-address . ((raw . ,target-hw)
                                   (formatted . ,(format-address target-hw hw-len))))
        (target-protocol-address . ((raw . ,target-proto)
                                   (formatted . ,(format-address target-proto proto-len))))))

    (catch (e) '())))

(def (format-address addr-bytes addr-len)
  "Format address bytes based on length and context"
  (cond
    ;; MAC address (6 bytes)
    ((= addr-len 6)
     (string-join
       (for/collect ((i (in-range 0 6)))
         (string-pad (number->string (bytevector-u8-ref addr-bytes i) 16) 2 #\0))
       ":"))

    ;; IPv4 address (4 bytes)
    ((= addr-len 4)
     (fmt-ipv4 (bytevector-u32-ref addr-bytes 0 (endianness big))))

    ;; IPv6 address (16 bytes)
    ((= addr-len 16)
     (fmt-ipv6-address addr-bytes))

    ;; Other lengths: hex dump
    (else
     (string-join
       (for/collect ((i (in-range 0 (min (bytevector-length addr-bytes) 16))))
         (string-pad (number->string (bytevector-u8-ref addr-bytes i) 16) 2 #\0))
       " "))))

(def (fmt-ipv6-address addr-bytes)
  "Format 16-byte IPv6 address"
  (string-join
    (for/collect ((i (in-range 0 16 2)))
      (string-pad (number->string
                   (bytevector-u16-ref addr-bytes i (endianness big))
                   16)
                  4 #\0))
    ":"))

;; ── Exported API ───────────────────────────────────────────────────────

;; dissect-arp: main entry point
;; format-hw-type: hardware type formatter
;; format-proto-type: protocol type formatter
;; format-arp-operation: operation formatter
