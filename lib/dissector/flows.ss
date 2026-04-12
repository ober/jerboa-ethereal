;; jerboa-ethereal/lib/dissector/flows.ss
;; Flow analysis: Track conversations between hosts
;;
;; Groups packets into flows/conversations for analysis
;; Flow key: (src-ip, src-port, dst-ip, dst-port, protocol)

(import (jerboa prelude))

;; ── Flow Representation ────────────────────────────────────────────────────

(defstruct flow
  (key                ;; (src-ip src-port dst-ip dst-port protocol)
   packets            ;; list of packets in this flow
   src-ip
   src-port
   dst-ip
   dst-port
   protocol
   start-time
   end-time
   bytes-sent))

;; ── Flow Key Generation ────────────────────────────────────────────────────

(def (make-flow-key src-ip src-port dst-ip dst-port protocol)
  "Create a canonical flow key (normalizes direction for TCP/UDP)"
  ;; For TCP/UDP, normalize so lower IP comes first
  ;; This groups bidirectional flows together
  (let ((cmp (string<? src-ip dst-ip)))
    (if cmp
        (str src-ip ":" src-port "→" dst-ip ":" dst-port "/" protocol)
        (str dst-ip ":" dst-port "→" src-ip ":" src-port "/" protocol))))

;; ── Flow Analysis ─────────────────────────────────────────────────────────

(def (analyze-flows dissected-packets)
  "Build flow index from dissected packets
   Returns hash table mapping flow-key → flow-info"

  (let ((flows (make-hash-table)))

    (for ((pkt dissected-packets)
          (idx (in-naturals)))
      (try
        (let* ((pkt-meta (car pkt))
               (layers (cdr pkt))
               (ts (assoc-get pkt-meta 'timestamp 0))
               (size (assoc-get pkt-meta 'size 0))
               (protocol #f)
               (src-ip #f)
               (src-port #f)
               (dst-ip #f)
               (dst-port #f))

          ;; Extract relevant fields from dissected layers
          (for ((layer layers))
            (let ((proto (car layer))
                  (fields (cdr layer)))

              (cond
                ;; Extract IPv4 addresses
                ((eq? proto 'ipv4)
                 (set! src-ip (assoc-get (assoc-get fields 'src-ip) 'formatted #f))
                 (set! dst-ip (assoc-get (assoc-get fields 'dst-ip) 'formatted #f)))

                ;; Extract TCP ports
                ((eq? proto 'tcp)
                 (set! protocol 'tcp)
                 (set! src-port (assoc-get (assoc-get fields 'src-port) 'raw #f))
                 (set! dst-port (assoc-get (assoc-get fields 'dst-port) 'raw #f)))

                ;; Extract UDP ports
                ((eq? proto 'udp)
                 (set! protocol 'udp)
                 (set! src-port (assoc-get (assoc-get fields 'src-port) 'raw #f))
                 (set! dst-port (assoc-get (assoc-get fields 'dst-port) 'raw #f))))))

          ;; Create flow key if we have enough info
          (if (and src-ip dst-ip protocol)
              (let ((flow-key (make-flow-key src-ip (or src-port 0)
                                             dst-ip (or dst-port 0)
                                             protocol)))

                ;; Update or create flow entry
                (let ((existing (hash-get flows flow-key #f)))
                  (if existing
                      ;; Update existing flow
                      (let ((count (assoc-get existing 'count 0)))
                        (hash-put! flows flow-key
                                  `((count . ,(+ count 1))
                                    (last-packet . ,idx)
                                    (bytes . ,(+ (assoc-get existing 'bytes 0) size))
                                    (end-time . ,ts)
                                    ,@existing)))
                      ;; Create new flow
                      (hash-put! flows flow-key
                                `((count . 1)
                                  (first-packet . ,idx)
                                  (last-packet . ,idx)
                                  (bytes . ,size)
                                  (start-time . ,ts)
                                  (end-time . ,ts)
                                  (src-ip . ,src-ip)
                                  (src-port . ,(or src-port 0))
                                  (dst-ip . ,dst-ip)
                                  (dst-port . ,(or dst-port 0))
                                  (protocol . ,protocol)))))))

        (catch (e)
          ;; Silently skip packets with parse errors
          #f)))

    flows))

;; ── Flow Queries ──────────────────────────────────────────────────────────

(def (find-flow-by-ip flows ip)
  "Find all flows involving a specific IP (as src or dst)"
  (filter (lambda (flow-entry)
            (let ((flow-info (cdr flow-entry)))
              (or (string=? (assoc-get flow-info 'src-ip "") ip)
                  (string=? (assoc-get flow-info 'dst-ip "") ip))))
          (hash->list flows)))

(def (find-flow-by-port flows port)
  "Find all flows using a specific port (src or dst)"
  (filter (lambda (flow-entry)
            (let ((flow-info (cdr flow-entry)))
              (or (= (assoc-get flow-info 'src-port 0) port)
                  (= (assoc-get flow-info 'dst-port 0) port))))
          (hash->list flows)))

(def (find-flow-by-protocol flows protocol)
  "Find all flows of a specific protocol"
  (filter (lambda (flow-entry)
            (let ((flow-info (cdr flow-entry)))
              (eq? (assoc-get flow-info 'protocol) protocol)))
          (hash->list flows)))

(def (flow-stats flows)
  "Get statistics about flows"
  `((total-flows . ,(hash-count flows))
    (total-packets . ,(apply + (map (lambda (f)
                                     (assoc-get (cdr f) 'count 0))
                                   (hash->list flows))))
    (total-bytes . ,(apply + (map (lambda (f)
                                   (assoc-get (cdr f) 'bytes 0))
                                 (hash->list flows))))))

;; ── Export ─────────────────────────────────────────────────────────────────

;; analyze-flows: build flow index from dissected packets
;; find-flow-by-ip: query flows by IP address
;; find-flow-by-port: query flows by port number
;; find-flow-by-protocol: query flows by protocol (tcp, udp, etc)
;; flow-stats: get overall flow statistics
