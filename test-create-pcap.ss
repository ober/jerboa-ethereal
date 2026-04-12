#!/usr/bin/env scheme
;; Create a test PCAP file for testing the analyzer

(import (jerboa prelude))

(def (create-test-pcap filename)
  (call-with-output-file filename
    (lambda (port)
      (set-port-mode! port (file-options binary)))
      ;; Write PCAP global header (24 bytes)
      ;; Magic: 0xa1b2c3d4 (little-endian: 0xd4c3b2a1)
      ;; Version: 2.4
      ;; Timezone: 0
      ;; Timestamp accuracy: 0
      ;; Snaplen: 65535
      ;; Network: 1 (Ethernet)

      (let ((global-header (make-bytevector 24 0)))
        (bytevector-u32-set! global-header 0 #xd4c3b2a1 (endianness little))  ; magic
        (bytevector-u16-set! global-header 4 2 (endianness little))             ; version major
        (bytevector-u16-set! global-header 6 4 (endianness little))             ; version minor
        (bytevector-u32-set! global-header 8 0 (endianness little))             ; timezone
        (bytevector-u32-set! global-header 12 0 (endianness little))            ; timestamp accuracy
        (bytevector-u32-set! global-header 16 65535 (endianness little))        ; snaplen
        (bytevector-u32-set! global-header 20 1 (endianness little))            ; network (Ethernet)
        (put-bytevector port global-header))

      ;; Write packet 1: Simple Ethernet/IPv4 packet (34 bytes)
      (let ((pkt1 (make-bytevector 34)))
        ;; Ethernet header
        (bytevector-u8-set! pkt1 0 #x00)
        (bytevector-u8-set! pkt1 1 #x11)
        (bytevector-u8-set! pkt1 2 #x22)
        (bytevector-u8-set! pkt1 3 #x33)
        (bytevector-u8-set! pkt1 4 #x44)
        (bytevector-u8-set! pkt1 5 #x55)
        (bytevector-u8-set! pkt1 6 #xaa)
        (bytevector-u8-set! pkt1 7 #xbb)
        (bytevector-u8-set! pkt1 8 #xcc)
        (bytevector-u8-set! pkt1 9 #xdd)
        (bytevector-u8-set! pkt1 10 #xee)
        (bytevector-u8-set! pkt1 11 #xff)
        ;; EtherType = 0x0800 (IPv4)
        (bytevector-u16-set! pkt1 12 #x0800 (endianness big))

        ;; IPv4 header (20 bytes min)
        (bytevector-u8-set! pkt1 14 #x45)  ; Version=4, IHL=5
        (bytevector-u8-set! pkt1 15 #x00)  ; DSCP/ECN
        (bytevector-u16-set! pkt1 16 20 (endianness big))  ; Length
        (bytevector-u8-set! pkt1 23 6)     ; Protocol = TCP
        ;; Source IP: 192.168.1.1
        (bytevector-u32-set! pkt1 26
                            (+ (bitwise-arithmetic-shift-left 192 24)
                               (bitwise-arithmetic-shift-left 168 16)
                               (bitwise-arithmetic-shift-left 1 8)
                               1)
                            (endianness big))
        ;; Dest IP: 8.8.8.8
        (bytevector-u32-set! pkt1 30
                            (+ (bitwise-arithmetic-shift-left 8 24)
                               (bitwise-arithmetic-shift-left 8 16)
                               (bitwise-arithmetic-shift-left 8 8)
                               8)
                            (endianness big))

        ;; Write packet 1 header
        (let ((pkt1-hdr (make-bytevector 16)))
          (bytevector-u32-set! pkt1-hdr 0 1000 (endianness little))    ; timestamp sec
          (bytevector-u32-set! pkt1-hdr 4 0 (endianness little))       ; timestamp usec
          (bytevector-u32-set! pkt1-hdr 8 34 (endianness little))      ; captured length
          (bytevector-u32-set! pkt1-hdr 12 34 (endianness little))     ; original length
          (put-bytevector port pkt1-hdr))
        (put-bytevector port pkt1))

      ;; Write packet 2: Another Ethernet/IPv4 packet
      (let ((pkt2 (make-bytevector 28)))
        ;; Ethernet header
        (bytevector-u8-set! pkt2 0 #xff)
        (bytevector-u8-set! pkt2 1 #xff)
        (bytevector-u8-set! pkt2 2 #xff)
        (bytevector-u8-set! pkt2 3 #xff)
        (bytevector-u8-set! pkt2 4 #xff)
        (bytevector-u8-set! pkt2 5 #xff)
        (bytevector-u8-set! pkt2 6 #xaa)
        (bytevector-u8-set! pkt2 7 #xbb)
        (bytevector-u8-set! pkt2 8 #xcc)
        (bytevector-u8-set! pkt2 9 #xdd)
        (bytevector-u8-set! pkt2 10 #xee)
        (bytevector-u8-set! pkt2 11 #xff)
        ;; EtherType = 0x0800 (IPv4)
        (bytevector-u16-set! pkt2 12 #x0800 (endianness big))

        ;; Minimal IPv4 header
        (bytevector-u8-set! pkt2 14 #x45)
        (bytevector-u8-set! pkt2 15 #x00)
        (bytevector-u16-set! pkt2 16 20 (endianness big))
        (bytevector-u8-set! pkt2 23 17)    ; Protocol = UDP
        ;; Source IP: 10.0.0.1
        (bytevector-u32-set! pkt2 26
                            (+ (bitwise-arithmetic-shift-left 10 24)
                               1)
                            (endianness big))
        ;; Dest IP: 10.0.0.255
        (bytevector-u32-set! pkt2 30
                            (+ (bitwise-arithmetic-shift-left 10 24)
                               255)
                            (endianness big))

        ;; Write packet 2 header
        (let ((pkt2-hdr (make-bytevector 16)))
          (bytevector-u32-set! pkt2-hdr 0 1001 (endianness little))    ; timestamp sec
          (bytevector-u32-set! pkt2-hdr 4 0 (endianness little))       ; timestamp usec
          (bytevector-u32-set! pkt2-hdr 8 28 (endianness little))      ; captured length
          (bytevector-u32-set! pkt2-hdr 12 28 (endianness little))     ; original length
          (put-bytevector port pkt2-hdr))
        (put-bytevector port pkt2))))

  (displayln (str "Created test PCAP: " filename " (2 packets)")))

(create-test-pcap "test-packets.pcap")
