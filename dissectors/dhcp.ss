;; jerboa-ethereal/dissectors/dhcp.ss
;; RFC 2131: Dynamic Host Configuration Protocol
;;
;; Bootstrap protocol for DHCP
;; 8-byte fixed header + variable-length options

(import (jerboa prelude))

;; ── DHCP Operation Type Formatter ──────────────────────────────────────────

(def (format-dhcp-opcode op)
  "Format DHCP operation code"
  (case op
    ((1) "BOOTREQUEST")
    ((2) "BOOTREPLY")
    (else (str "Op " op))))

(def (format-dhcp-message-type msg-type)
  "Format DHCP message type option (option 53)"
  (case msg-type
    ((1) "DHCPDISCOVER")
    ((2) "DHCPOFFER")
    ((3) "DHCPREQUEST")
    ((4) "DHCPDECLINE")
    ((5) "DHCPACK")
    ((6) "DHCPNAK")
    ((7) "DHCPRELEASE")
    ((8) "DHCPINFORM")
    ((9) "DHCPFORCERENEW")
    ((10) "DHCPLEASEQUERY")
    ((11) "DHCPLEASEUNASSIGNED")
    ((12) "DHCPLEASEUNKNOWN")
    ((13) "DHCPLEASEACTIVE")
    (else (str "Type " msg-type))))

(def (format-htype htype)
  "Format DHCP hardware type"
  (case htype
    ((1) "Ethernet")
    ((6) "Token Ring")
    ((7) "ARCNET")
    ((15) "Frame Relay")
    ((20) "Serial Line")
    (else (str "Type " htype))))

;; ── Core DHCP Dissector ───────────────────────────────────────────────────

(def (dissect-dhcp buffer)
  "Parse DHCP message from bytevector
   Returns (ok fields) or (err message)

   Structure (minimum 236 bytes):
   [0]     Operation (request/reply)
   [1]     Hardware type
   [2]     Hardware address length
   [3]     Hops
   [4:8)   Transaction ID (xid)
   [8:10)  Seconds elapsed
   [10:12) Flags
   [12:16) Client IP
   [16:20) Your IP (offered)
   [20:24) Server IP
   [24:28) Gateway IP
   [28:34) Client hardware address (6 bytes for Ethernet)
   [34:236) Server hostname (64 bytes)
   [100:236) Boot filename (128 bytes)
   [236:240) Magic cookie (0x63825363)
   [240:)  Options"

  (try
    ;; Validate minimum size
    (_ (unwrap (validate (>= (bytevector-length buffer) 240)
                         "DHCP packet too short (< 240 bytes)")))

    (let* ((opcode-res (read-u8 buffer 0))
           (opcode (unwrap opcode-res))

           (htype-res (read-u8 buffer 1))
           (htype (unwrap htype-res))

           (hlen-res (read-u8 buffer 2))
           (hlen (unwrap hlen-res))

           (hops-res (read-u8 buffer 3))
           (hops (unwrap hops-res))

           (xid-res (read-u32be buffer 4))
           (xid (unwrap xid-res))

           (secs-res (read-u16be buffer 8))
           (secs (unwrap secs-res))

           (flags-res (read-u16be buffer 10))
           (flags (unwrap flags-res))

           (client-ip-res (read-u32be buffer 12))
           (client-ip (unwrap client-ip-res))

           (your-ip-res (read-u32be buffer 16))
           (your-ip (unwrap your-ip-res))

           (server-ip-res (read-u32be buffer 20))
           (server-ip (unwrap server-ip-res))

           (gw-ip-res (read-u32be buffer 24))
           (gw-ip (unwrap gw-ip-res))

           (client-hw (unwrap (slice buffer 28 (min 6 hlen))))

           ;; Magic cookie at offset 236
           (magic-res (read-u32be buffer 236))
           (magic (unwrap magic-res))

           ;; Extract message type from options if present
           (msg-type (extract-dhcp-message-type buffer 240)))

      (ok `((opcode . ((raw . ,opcode)
                      (formatted . ,(format-dhcp-opcode opcode))))
            (hardware-type . ((raw . ,htype)
                             (formatted . ,(format-htype htype))))
            (hardware-address-length . ,hlen)
            (hops . ,hops)
            (transaction-id . ((raw . ,xid)
                              (formatted . ,(fmt-hex xid))))
            (seconds-elapsed . ,secs)
            (broadcast-flag . ,(if (> (bitwise-and flags #x8000) 0) 1 0))
            (client-ip . ((raw . ,client-ip)
                         (formatted . ,(fmt-ipv4 client-ip))))
            (your-ip . ((raw . ,your-ip)
                       (formatted . ,(fmt-ipv4 your-ip))))
            (server-ip . ((raw . ,server-ip)
                         (formatted . ,(fmt-ipv4 server-ip))))
            (gateway-ip . ((raw . ,gw-ip)
                          (formatted . ,(fmt-ipv4 gw-ip))))
            (client-hardware . ((raw . ,client-hw)
                               (formatted . ,(fmt-mac client-hw))))
            (magic-cookie . ((raw . ,magic)
                            (formatted . ,(if (= magic #x63825363) "Valid" "Invalid"))))
            ,@(if msg-type
                  `((message-type . ((raw . ,msg-type)
                                    (formatted . ,(format-dhcp-message-type msg-type)))))
                  '()))))

    ;; Error handling
    (catch (e)
      (err (str "DHCP parse error: " e)))))

;; ── Option Parsing ────────────────────────────────────────────────────────

(def (extract-dhcp-message-type buffer offset)
  "Extract DHCP message type (option 53) from options section
   Returns integer 1-13 or #f if not found"

  (let loop ((pos offset))
    (if (>= pos (bytevector-length buffer))
        #f
        (let ((opt-type-res (read-u8 buffer pos)))
          (if (err? opt-type-res)
              #f
              (let ((opt-type (unwrap opt-type-res)))
                (cond
                  ;; End of options
                  ((= opt-type 255) #f)

                  ;; Pad option (no length)
                  ((= opt-type 0) (loop (+ pos 1)))

                  ;; Message type option (option 53, always 1 byte)
                  ((= opt-type 53)
                   (let ((len-res (read-u8 buffer (+ pos 1))))
                     (if (err? len-res)
                         #f
                         (let ((len (unwrap len-res)))
                           (if (>= (+ pos 3) (bytevector-length buffer))
                               #f
                               (unwrap (read-u8 buffer (+ pos 2))))))))

                  ;; Other options: skip past option data
                  (else
                   (let ((len-res (read-u8 buffer (+ pos 1))))
                     (if (err? len-res)
                         #f
                         (let ((len (unwrap len-res)))
                           (loop (+ pos 2 len)))))))))))))

;; ── Exported API ───────────────────────────────────────────────────────────

;; dissect-dhcp: main entry point
;; format-dhcp-opcode: operation formatter
;; format-dhcp-message-type: message type formatter
;; format-htype: hardware type formatter
