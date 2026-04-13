(import (jerboa prelude))

(def (write-u16le! bv offset val)
  (bytevector-u16-set! bv offset val (endianness little)))

(def (write-u32le! bv offset val)
  (bytevector-u32-set! bv offset val (endianness little)))

(def (write-u16be! bv offset val)
  (bytevector-u16-set! bv offset val (endianness big)))

(def (write-u32be! bv offset val)
  (bytevector-u32-set! bv offset val (endianness big)))

(def (write-pcap-global-header port)
  (let ((hdr (make-bytevector 24 0)))
    (write-u32le! hdr 0 #xd4c3b2a1)  ;; magic
    (write-u16le! hdr 4 2)             ;; version major
    (write-u16le! hdr 6 4)             ;; version minor
    (write-u32le! hdr 8 0)             ;; timezone
    (write-u32le! hdr 12 0)            ;; timestamp accuracy
    (write-u32le! hdr 16 65535)        ;; snaplen
    (write-u32le! hdr 20 1)            ;; network = Ethernet
    (put-bytevector port hdr)))

(def (write-pcap-packet port ts-sec data)
  (let* ((len (bytevector-length data))
         (hdr (make-bytevector 16 0)))
    (write-u32le! hdr 0 ts-sec)
    (write-u32le! hdr 4 0)
    (write-u32le! hdr 8 len)
    (write-u32le! hdr 12 len)
    (put-bytevector port hdr)
    (put-bytevector port data)))

(def (make-eth-ipv4-packet src-mac dst-mac src-ip dst-ip proto)
  ;; Ethernet (14) + IPv4 header (20) = 34 bytes minimum
  (let ((pkt (make-bytevector 34 0)))
    ;; Dst MAC
    (for ((i (in-range 6))) (bytevector-u8-set! pkt i (bytevector-u8-ref dst-mac i)))
    ;; Src MAC
    (for ((i (in-range 6))) (bytevector-u8-set! pkt (+ 6 i) (bytevector-u8-ref src-mac i)))
    ;; EtherType = IPv4
    (write-u16be! pkt 12 #x0800)
    ;; IPv4: Version=4, IHL=5
    (bytevector-u8-set! pkt 14 #x45)
    ;; Total length = 20
    (write-u16be! pkt 16 20)
    ;; TTL = 64
    (bytevector-u8-set! pkt 22 64)
    ;; Protocol
    (bytevector-u8-set! pkt 23 proto)
    ;; Src IP
    (write-u32be! pkt 26 src-ip)
    ;; Dst IP
    (write-u32be! pkt 30 dst-ip)
    pkt))

(def (make-arp-packet)
  ;; Ethernet (14) + ARP (28) = 42 bytes
  (let ((pkt (make-bytevector 42 0)))
    ;; Dst MAC = broadcast
    (for ((i (in-range 6))) (bytevector-u8-set! pkt i #xff))
    ;; Src MAC
    (bytevector-u8-set! pkt 6 #xaa)
    (bytevector-u8-set! pkt 7 #xbb)
    (bytevector-u8-set! pkt 8 #xcc)
    (bytevector-u8-set! pkt 9 #xdd)
    (bytevector-u8-set! pkt 10 #xee)
    (bytevector-u8-set! pkt 11 #xff)
    ;; EtherType = ARP
    (write-u16be! pkt 12 #x0806)
    ;; ARP: hardware type = Ethernet
    (write-u16be! pkt 14 1)
    ;; Protocol type = IPv4
    (write-u16be! pkt 16 #x0800)
    ;; Hardware addr len = 6
    (bytevector-u8-set! pkt 18 6)
    ;; Protocol addr len = 4
    (bytevector-u8-set! pkt 19 4)
    ;; Operation = 1 (request)
    (write-u16be! pkt 20 1)
    ;; Sender MAC
    (bytevector-u8-set! pkt 22 #xaa)
    (bytevector-u8-set! pkt 23 #xbb)
    (bytevector-u8-set! pkt 24 #xcc)
    (bytevector-u8-set! pkt 25 #xdd)
    (bytevector-u8-set! pkt 26 #xee)
    (bytevector-u8-set! pkt 27 #xff)
    ;; Sender IP = 192.168.1.1
    (write-u32be! pkt 28 #xc0a80101)
    ;; Target IP = 192.168.1.2
    (write-u32be! pkt 38 #xc0a80102)
    pkt))

(def (create-test-pcap filename)
  (let ((port (open-file-output-port filename
                                     (file-options no-fail)
                                     (buffer-mode block)
                                     #f)))
    (unwind-protect
      (begin
        (write-pcap-global-header port)
        ;; Packet 1: TCP from 192.168.1.1 → 8.8.8.8
        (write-pcap-packet port 1000
          (make-eth-ipv4-packet
            #vu8(#xaa #xbb #xcc #xdd #xee #xff)
            #vu8(#x00 #x11 #x22 #x33 #x44 #x55)
            #xc0a80101 #x08080808 6))
        ;; Packet 2: UDP from 10.0.0.1 → 10.0.0.255
        (write-pcap-packet port 1001
          (make-eth-ipv4-packet
            #vu8(#xaa #xbb #xcc #xdd #xee #xff)
            #vu8(#xff #xff #xff #xff #xff #xff)
            #x0a000001 #x0a0000ff 17))
        ;; Packet 3: ARP request
        (write-pcap-packet port 1002 (make-arp-packet))
        (displayln (str "Created " filename " (3 packets)")))
      (close-port port))))

(create-test-pcap "test-packets.pcap")
