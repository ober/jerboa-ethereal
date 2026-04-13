;; jerboa-wafter/lib/pcap/live.ss
;; Live packet capture using (std pcap) → rscap Rust backend
;;
;; Usage:
;;   (import (jerboa prelude))
;;   (import (std pcap))
;;
;;   ;; List interfaces
;;   (displayln (pcap-interfaces))
;;
;;   ;; Capture N packets from an interface
;;   (def cap (pcap-open "eth0"))
;;   (dotimes (i 10)
;;     (let ((pkt (pcap-next cap)))
;;       (when pkt
;;         (let ((data    (vector-ref pkt 0))
;;               (ts-sec  (vector-ref pkt 1))
;;               (ts-usec (vector-ref pkt 2)))
;;           (displayln (str ts-sec "." ts-usec
;;                           "  " (bytevector-length data) " bytes"))))))
;;   (pcap-close cap)

(import (jerboa prelude))
(import (std pcap))

;; ── Capture loop helper ──────────────────────────────────────────────────────

(def (pcap-capture-loop iface count proc)
  "Capture COUNT packets on IFACE, calling (proc data ts-sec ts-usec) for each.
   Pass count = #f for unlimited capture.
   Returns the number of packets processed."
  (let ((cap (pcap-open iface))
        (captured 0))
    (unwind-protect
      (let loop ()
        (when (or (not count) (< captured count))
          (let ((pkt (pcap-next cap)))
            (when pkt
              (proc (vector-ref pkt 0)
                    (vector-ref pkt 1)
                    (vector-ref pkt 2))
              (set! captured (+ captured 1))
              (loop)))))
      (pcap-close cap))
    captured))

;; ── Quick display helper ─────────────────────────────────────────────────────

(def (pcap-sniff iface count)
  "Print COUNT live packets from IFACE to stdout.
   Requires root / CAP_NET_RAW."
  (displayln (str "Capturing " (or count "unlimited") " packets on " iface "..."))
  (displayln (str "Available interfaces: " (string-join (pcap-interfaces) ", ")))
  (displayln "")
  (let ((n (pcap-capture-loop iface count
             (lambda (data ts-sec ts-usec)
               (printf "  ~a.~6,'0a  ~a bytes\n"
                       ts-sec ts-usec
                       (bytevector-length data))))))
    (displayln (str "\nCaptured " n " packet(s)."))))
