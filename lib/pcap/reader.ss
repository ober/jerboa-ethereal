;; jerboa-ethereal/lib/pcap/reader.ss
;; PCAP file format reader
;;
;; Reads tcpdump/Wireshark pcap files and extracts packets

(import (jerboa prelude))

;; ── PCAP File Header Parsing ──────────────────────────────────────────

(def (read-pcap-packets file-path)
  "Read packets from PCAP file
   Returns (ok packet-list) or (err message)"

  (try-result*
    (call-with-input-file file-path
      (lambda (port)
        ;; Skip file header (24 bytes)
        (let ((skip-header (read-bytevector 24 port)))
          (if (eof-object? skip-header)
              '()
              ;; Read packets one by one
              (let loop ((packets '())
                        (packet-num 0))
                (let ((packet-header (read-bytevector 16 port)))
                  (if (or (eof-object? packet-header)
                         (< (bytevector-length packet-header) 16))
                      (reverse packets)
                      (try
                        (let* ((ts-sec (bytevector-u32-ref packet-header 0 (endianness little)))
                               (ts-usec (bytevector-u32-ref packet-header 4 (endianness little)))
                               (capt-len (bytevector-u32-ref packet-header 8 (endianness little)))
                               (orig-len (bytevector-u32-ref packet-header 12 (endianness little)))
                               (packet-data (read-bytevector capt-len port)))

                          (if (or (eof-object? packet-data)
                                 (< (bytevector-length packet-data) capt-len))
                              (reverse packets)
                              (loop (cons `((timestamp . ,ts-sec)
                                           (size . ,capt-len)
                                           (original-size . ,orig-len)
                                           (packet-number . ,packet-num)
                                           (payload . ,packet-data))
                                          packets)
                                    (+ packet-num 1))))
                        (catch (e)
                          (reverse packets)))))))))

    (catch (e)
      (err (str "Failed to read PCAP: " e)))))

;; ── Packet Statistics ─────────────────────────────────────────────────

(def (pcap-file-stats file-path)
  "Quick stats about a PCAP file without loading all packets"
  (try-result*
    (call-with-input-file file-path
      (lambda (port)
        (let ((header (read-bytevector 24 port)))
          (if (eof-object? header)
              `((status . "empty"))
              (let loop ((count 0)
                        (total-size 0))
                (let ((pkt-hdr (read-bytevector 16 port)))
                  (if (or (eof-object? pkt-hdr)
                         (< (bytevector-length pkt-hdr) 16))
                      `((packet-count . ,count)
                        (total-bytes . ,total-size))
                      (let ((capt-len (bytevector-u32-ref pkt-hdr 8 (endianness little))))
                        ;; Skip packet data
                        (read-bytevector capt-len port)
                        (loop (+ count 1)
                              (+ total-size capt-len))))))))))

    (catch (e)
      (err (str "Failed to stat PCAP: " e)))))

;; ── Exported API ───────────────────────────────────────────────────────

;; read-pcap-packets: read all packets from PCAP file
;; pcap-file-stats: get file statistics
