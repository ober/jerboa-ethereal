;; jerboa-ethereal/lib/dissector/statistics.ss
;; Packet statistics and aggregation
;;
;; Compute statistics about packets grouped by protocol, IP, port, etc.

(import (jerboa prelude))

;; ── Statistics Aggregation ────────────────────────────────────────────────

(def (aggregate-by-protocol dissected-packets)
  "Group packets by protocol and count
   Returns alist with protocol counts"

  (let ((stats (make-hash-table)))

    (for ((pkt dissected-packets))
      (let ((layers (cdr pkt)))
        (if (not (null? layers))
            (let ((proto (car (car layers))))
              (hash-put! stats proto
                        (+ 1 (hash-get stats proto 0)))))))

    (map (lambda (proto)
           (cons proto (hash-get stats proto 0)))
         (sort (hash-keys stats)
               (lambda (a b) (string<? (str a) (str b)))))))

(def (aggregate-by-ip-pair dissected-packets)
  "Group packets by (src-ip, dst-ip) pair and count"

  (let ((stats (make-hash-table)))

    (for ((pkt dissected-packets))
      (let loop ((layers (cdr pkt)))
        (if (not (null? layers))
            (let ((proto (car (car layers)))
                  (fields (cdr (car layers))))
              (if (eq? proto 'ipv4)
                  (let* ((src (assoc-get (assoc-get fields 'src-ip) 'formatted #f))
                         (dst (assoc-get (assoc-get fields 'dst-ip) 'formatted #f))
                         (key (if (and src dst)
                                 (str src "→" dst)
                                 "unknown")))
                    (hash-put! stats key
                              (+ 1 (hash-get stats key 0))))
                  (loop (cdr layers)))))))

    (sort (map (lambda (key)
                 (cons key (hash-get stats key 0)))
               (hash-keys stats))
          (lambda (a b) (> (cdr a) (cdr b))))))

(def (aggregate-by-port dissected-packets)
  "Group packets by (src-port, dst-port) pair and count"

  (let ((stats (make-hash-table)))

    (for ((pkt dissected-packets))
      (let loop ((layers (cdr pkt)))
        (if (not (null? layers))
            (let ((proto (car (car layers)))
                  (fields (cdr (car layers))))
              (cond
                ((or (eq? proto 'tcp) (eq? proto 'udp))
                 (let* ((src (assoc-get (assoc-get fields 'src-port) 'raw #f))
                        (dst (assoc-get (assoc-get fields 'dst-port) 'raw #f))
                        (key (if (and src dst)
                                (str src ":" dst "(" proto ")")
                                "unknown")))
                   (hash-put! stats key
                             (+ 1 (hash-get stats key 0)))))
                (#t (loop (cdr layers)))))))))

    (sort (map (lambda (key)
                 (cons key (hash-get stats key 0)))
               (hash-keys stats))
          (lambda (a b) (> (cdr a) (cdr b))))))

(def (packet-size-distribution dissected-packets)
  "Compute packet size distribution (buckets)"

  (let ((buckets (make-hash-table)))

    (for ((pkt dissected-packets))
      (let ((size (assoc-get (car pkt) 'size 0))
            (bucket (cond
                      ((< size 64) "< 64B")
                      ((< size 128) "64-128B")
                      ((< size 256) "128-256B")
                      ((< size 512) "256-512B")
                      ((< size 1024) "512-1KB")
                      ((< size 2048) "1-2KB")
                      ((< size 4096) "2-4KB")
                      ((< size 8192) "4-8KB")
                      (else "> 8KB"))))

        (hash-put! buckets bucket
                  (+ 1 (hash-get buckets bucket 0)))))

    (sort (map (lambda (bucket)
                 (cons bucket (hash-get buckets bucket 0)))
               (hash-keys buckets))
          (lambda (a b) (string<? (car a) (car b))))))

;; ── Summary Statistics ────────────────────────────────────────────────────

(def (compute-summary-stats dissected-packets)
  "Compute overall summary statistics"

  (let ((total-count (length dissected-packets))
        (total-bytes (apply + (map (lambda (p)
                                    (assoc-get (car p) 'size 0))
                                  dissected-packets)))
        (successful-dissect (length (filter (lambda (p) (not (null? (cdr p))))
                                           dissected-packets))))

    `((total-packets . ,total-count)
      (total-bytes . ,total-bytes)
      (successfully-dissected . ,successful-dissect)
      (dissection-rate . ,(if (> total-count 0)
                             (let* ((pct (* 100 (quotient (* successful-dissect 1000)
                                                          total-count))))
                               (str (quotient pct 10) "." (remainder pct 10) "%"))
                             "N/A"))
      (average-packet-size . ,(if (> total-count 0)
                                 (quotient total-bytes total-count)
                                 0))
      (min-packet-size . ,(if (> total-count 0)
                             (apply min (map (lambda (p)
                                             (assoc-get (car p) 'size 0))
                                           dissected-packets))
                             0))
      (max-packet-size . ,(if (> total-count 0)
                             (apply max (map (lambda (p)
                                             (assoc-get (car p) 'size 0))
                                           dissected-packets))
                             0)))))

;; ── Export ────────────────────────────────────────────────────────────────

;; aggregate-by-protocol: packet count per protocol
;; aggregate-by-ip-pair: packet count per (src, dst) IP pair
;; aggregate-by-port: packet count per (src, dst) port pair
;; packet-size-distribution: distribution of packet sizes
;; compute-summary-stats: overall summary statistics
