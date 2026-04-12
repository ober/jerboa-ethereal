;; jerboa-ethereal/lib/dsl/formatters.ss
;; Built-in formatters for converting raw field values to human-readable strings
;;
;; Formatters are functions that take a raw value (integer, bytes, etc.)
;; and return a formatted string suitable for display.

(import (jerboa prelude))

;; ── IPv4 Address Formatter ──────────────────────────────────────────────────

(def (format-ipv4 addr)
  "Format u32 as dotted-decimal IPv4 address
   Example: 3232235777 -> \"192.168.1.1\""
  (let* ([b0 (bitwise-arithmetic-shift-right addr 24)]
         [b1 (bitwise-and (bitwise-arithmetic-shift-right addr 16) 255)]
         [b2 (bitwise-and (bitwise-arithmetic-shift-right addr 8) 255)]
         [b3 (bitwise-and addr 255)])
    (str b0 "." b1 "." b2 "." b3)))

;; ── IPv6 Address Formatter ──────────────────────────────────────────────────

(def (format-ipv6 addr-bytes)
  "Format 16 bytes as IPv6 address (compressed notation)
   Example: #vu8(0x20 0x01 0x0d 0xb8 ...) -> \"2001:db8::1\""
  ;; TODO: Implement full IPv6 compression (:: notation)
  ;; For now, return simple colon-separated format
  (if (not (bytevector? addr-bytes))
      (str "invalid:" addr-bytes)
      (string-join
        (for/collect ([i (in-range 0 16 2)])
          (let ([b0 (bytevector-u8-ref addr-bytes i)]
                [b1 (bytevector-u8-ref addr-bytes (+ i 1))])
            (format "~x" (bitwise-ior (bitwise-arithmetic-shift-left b0 8) b1))))
        ":")))

;; ── MAC Address Formatter ───────────────────────────────────────────────────

(def (format-mac addr)
  "Format u48 as MAC address
   Example: 282430699069695 -> \"00:11:22:33:44:55\""
  (let ([bytes (for/collect ([i (in-range 5 -1 -1)])
                 (bitwise-and
                   (bitwise-arithmetic-shift-right addr (* i 8))
                   255))])
    (string-join
      (map (lambda (b) (format "~2,'0x" b)) bytes)
      ":")))

;; ── Port Formatter ──────────────────────────────────────────────────────────
;; Well-known port names (IANA service names)

(def well-known-ports
  (alist
    (21 "ftp")
    (22 "ssh")
    (23 "telnet")
    (25 "smtp")
    (53 "dns")
    (67 "dhcp")
    (80 "http")
    (110 "pop3")
    (143 "imap")
    (443 "https")
    (465 "smtp-ssl")
    (587 "smtp-submission")
    (993 "imap-ssl")
    (995 "pop3-ssl")
    (3306 "mysql")
    (5432 "postgres")
    (6379 "redis")
    (8080 "http-proxy")
    (8443 "https-alt")))

(def (format-port port-num)
  "Format port number with service name if known
   Example: 22 -> \"ssh\", 12345 -> \"12345\""
  (let ([service (assoc-in well-known-ports port-num)])
    (if service
        (str (cdr service) " (" port-num ")")
        (str port-num))))

;; ── Hexadecimal Formatter ───────────────────────────────────────────────────

(def (format-hex bytes-or-int)
  "Format bytes or integer as hexadecimal string
   Example: #vu8(222 173 190 239) -> \"0xdeadbeef\""
  (cond
    [(bytevector? bytes-or-int)
     (let ([hex-str (string-join
                      (for/collect ([b (in-bytes bytes-or-int)])
                        (format "~2,'0x" b))
                      "")])
       (str "0x" hex-str))]
    [(integer? bytes-or-int)
     (format "0x~x" bytes-or-int)]
    [else (str bytes-or-int)]))

;; ── Boolean Formatter ───────────────────────────────────────────────────────

(def (format-boolean value)
  "Format boolean as yes/no
   Example: 1 -> \"yes\", 0 -> \"no\""
  (if value "yes" "no"))

;; ── CIDR Notation Formatter (IP mask) ───────────────────────────────────────

(def (format-ipv4-mask mask-byte)
  "Format IPv4 netmask byte as CIDR prefix length
   Example: 255 -> \"/24\", 254 -> \"/23\""
  (let ([bits (for/fold ([count 0]) ([i (in-range 8)])
                (if (bitwise-and (bitwise-arithmetic-shift-left 1 i) mask-byte)
                    (+ count 1)
                    count))])
    (str "/" bits)))

;; ── Decimal Formatter (passthrough) ─────────────────────────────────────────

(def (format-decimal value)
  "Format integer as decimal (default, identity for integers)"
  (str value))

;; ── Protocol Number Formatter ──────────────────────────────────────────────

(def ip-protocol-names
  (alist
    (0 "HOPOPT")
    (1 "ICMP")
    (2 "IGMP")
    (3 "GGP")
    (4 "IP")
    (5 "ST")
    (6 "TCP")
    (7 "CBT")
    (8 "EGP")
    (9 "IGP")
    (17 "UDP")
    (41 "IPv6")
    (47 "GRE")
    (50 "ESP")
    (51 "AH")
    (58 "ICMPv6")
    (112 "VRRP")
    (255 "Reserved")))

(def (format-ip-protocol protocol-num)
  "Format IP protocol number with name if known
   Example: 6 -> \"TCP\", 17 -> \"UDP\""
  (let ([name (assoc-in ip-protocol-names protocol-num)])
    (if name
        (str (cdr name) " (" protocol-num ")")
        (str protocol-num))))

;; ── Formatter Registry ──────────────────────────────────────────────────────
;; Maps field type names to their default formatters

(def formatter-registry (make-hash-table))

(def (register-formatter! type-name formatter-func)
  "Register a formatter function for a field type"
  (hash-put! formatter-registry type-name formatter-func))

(def (get-formatter type-name)
  "Get formatter function for a field type, or format-decimal if none"
  (or (hash-get formatter-registry type-name) format-decimal))

;; Register standard formatters
(register-formatter! 'ipv4 format-ipv4)
(register-formatter! 'ipv6 format-ipv6)
(register-formatter! 'mac format-mac)
(register-formatter! 'port format-port)
(register-formatter! 'hex format-hex)
(register-formatter! 'boolean format-boolean)
(register-formatter! 'ipv4-mask format-ipv4-mask)
(register-formatter! 'ip-protocol format-ip-protocol)

;; Public API: formatters and registry
;; format-ipv4, format-ipv6, format-mac, format-port, format-hex,
;; format-boolean, format-ipv4-mask, format-ip-protocol,
;; register-formatter!, get-formatter, formatter-registry
