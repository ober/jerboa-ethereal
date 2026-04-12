;; jerboa-ethereal/lib/pcap/reader.ss
;; PCAP file reader: parse libpcap (.pcap) and pcapng (.pcapng) format files
;;
;; Returns a stream of packets with metadata (timestamp, captured length, etc.)

(import (jerboa prelude))

;; TODO: Phase 5 implementation
;; - Implement pcap file format parsing
;; - Implement pcapng format support
;; - Extract link-layer type, timestamps, capture metadata
;; - Provide stream-based reader for large files

(define-syntax TODO-pcap-reader
  (syntax-rules ()
    [(_ msg)
     (error 'pcap-reader "Not yet implemented: ~a" msg)]))

;; Placeholder exports
(export)
