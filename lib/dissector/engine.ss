;; jerboa-ethereal/lib/dissector/engine.ss
;; Core dissection pipeline: buffer parsing, field extraction, tree building

(import (jerboa prelude))

;; Data structures for packet dissection

(defstruct buffer (bytes pos end-offset))

(defstruct field-value (name type raw-value formatted description))

(defstruct dissected-packet (protocol-name fields raw-bytes payload-start payload-bytes next-protocol))

;; Protocol discovery helper

(def (raw-value-to-protocol value)
  "Map protocol field value to protocol name"
  (cond
    [(= value #x0800) 'ipv4]
    [(= value #x86DD) 'ipv6]
    [(= value #x0806) 'arp]
    [(= value 6) 'tcp]
    [(= value 17) 'udp]
    [(= value 1) 'icmp]
    [#t #f]))

;; Placeholder dissection engine (Phase 3 implementation)

(def (dissect-protocol protocol buf offset)
  "Parse protocol from buffer [Phase 3 stub]"
  (error 'dissect-protocol "Not yet implemented"))
