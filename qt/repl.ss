#!chezscheme
;; qt/repl.ss — TCP debugging REPL for wafter-qt
;;
;; Start with: (start-repl! 7778)
;; Connect:    nc localhost 7778
;;
;; All wafter state is accessible — e.g.:
;;   wafter> (get-packet-count)
;;   wafter> (load-pcap! "/tmp/capture.pcap")
;;   wafter> (screenshot! "/tmp/snap.png")
;;   wafter> (filter-packets "TCP")
;;   wafter> (quit)    ; disconnect this session

(import (except (chezscheme)
                make-hash-table hash-table? sort sort!
                printf fprintf iota 1+ 1-
                partition make-date make-time
                path-extension path-absolute?
                with-input-from-string with-output-to-string)
        (jerboa prelude))

;; ── TCP shim FFI ─────────────────────────────────────────────────────────

(def *tcp-shim-ready* #f)

(def (ensure-tcp-shim!)
  (unless *tcp-shim-ready*
    (load-shared-object "tcp_repl_shim.so")
    (set! *tcp-shim-ready* #t)))

(def *tcp-server-socket*   #f)
(def *tcp-set-nonblocking* #f)
(def *tcp-accept-conn*     #f)
(def *tcp-get-bound-port*  #f)
(def *tcp-close-fd*        #f)

(def (init-tcp-ffi!)
  (ensure-tcp-shim!)
  (set! *tcp-server-socket*   (foreign-procedure "tcp_server_socket"   (int) int))
  (set! *tcp-set-nonblocking* (foreign-procedure "tcp_set_nonblocking" (int) int))
  (set! *tcp-accept-conn*     (foreign-procedure "tcp_accept_conn"     (int) int))
  (set! *tcp-get-bound-port*  (foreign-procedure "tcp_get_bound_port"  (int) int))
  (set! *tcp-close-fd*        (foreign-procedure "tcp_close_fd"        (int) int)))

;; ── REPL State ───────────────────────────────────────────────────────────

(def *repl-server-fd*  #f)
(def *repl-thread*     #f)
(def *repl-port-num*   #f)
(def *repl-running*    #f)

(def (repl-running?) *repl-running*)
(def (repl-port-num) *repl-port-num*)

;; ── Public API ────────────────────────────────────────────────────────────

(def (start-repl! port)
  "Start TCP REPL on the given port (0 = auto-assign).
   Returns the actual port number bound.
   All wafter-qt globals are accessible in the REPL environment."
  (when *repl-running* (stop-repl!))
  (init-tcp-ffi!)
  (let ([fd (*tcp-server-socket* port)])
    (when (< fd 0)
      (error 'start-repl! "Failed to bind TCP server on port ~a" port))
    (let ([bound-port (*tcp-get-bound-port* fd)])
      (set! *repl-server-fd* fd)
      (set! *repl-port-num*  bound-port)
      (set! *repl-running*   #t)
      ;; Background thread blocks on accept()
      (set! *repl-thread*
        (fork-thread
          (lambda ()
            (guard (e [#t (display (str "REPL thread error: " e "\n")
                                   (current-error-port))])
              (repl-accept-loop fd)))))
      (printf "REPL: listening on 127.0.0.1:~a\n" bound-port)
      (printf "      nc localhost ~a\n" bound-port)
      bound-port)))

(def (stop-repl!)
  "Stop the REPL server."
  (when *repl-server-fd*
    (set! *repl-running* #f)
    (*tcp-close-fd* *repl-server-fd*)
    (set! *repl-server-fd* #f)
    (set! *repl-thread*    #f)
    (set! *repl-port-num*  #f)))

;; ── Accept Loop ───────────────────────────────────────────────────────────

(def (repl-accept-loop server-fd)
  "Background thread: accept → serve → loop."
  (let loop ()
    (when *repl-running*
      (let ([client-fd (*tcp-accept-conn* server-fd)])
        (when (>= client-fd 0)
          (guard (e [#t #f])
            (repl-serve-client client-fd)))
        (loop)))))

;; ── Client Session ────────────────────────────────────────────────────────

(def (repl-serve-client client-fd)
  "Serve one REPL client. Blocks until client disconnects or types (quit)."
  (let ([in  (open-fd-input-port  client-fd (buffer-mode line) (native-transcoder))]
        [out (open-fd-output-port client-fd (buffer-mode line) (native-transcoder))])
    (unwind-protect
      (begin
        (put-string out
          (str "wafter-qt REPL  —  type (quit) to disconnect\n"
               "All wafter-qt state is accessible.\n"
               "Examples:\n"
               "  (get-packet-count)\n"
               "  (load-pcap! \"/path/to/capture.pcap\")\n"
               "  (screenshot! \"/tmp/snap.png\")\n"
               "  (filter-packets! \"TCP\")\n\n"))
        (flush-output-port out)
        (let loop ()
          (put-string out "wafter> ")
          (flush-output-port out)
          (let ([line (guard (e [#t #f]) (get-line in))])
            (cond
              [(not line)             #f]   ; connection closed
              [(eof-object? line)     #f]
              [(string=? (string-trim line) "") (loop)]
              [(member (string-trim line) '("(quit)" "quit" ":q" ",q"))
               (put-string out "bye\n") (flush-output-port out)]
              [else
               (let ([output (repl-eval-line (string-trim line))])
                 (put-string out output)
                 (put-string out "\n")
                 (flush-output-port out)
                 (loop))]))))
      ;; Cleanup: close the client fd via port
      (guard (e [#t #f])
        (close-port in)))))

;; ── Expression Evaluation ─────────────────────────────────────────────────

(def (repl-eval-line line)
  "Read and eval one line of Scheme. Returns result as a string."
  ;; Parse multi-form input (user might paste a block)
  (with-output-to-string
    (lambda ()
      (guard (e [#t
                 (display "Error: ")
                 (if (condition? e)
                     (display-condition e)
                     (display e))])
        (with-input-from-string line
          (lambda ()
            (let loop ([first #t])
              (let ([expr (guard (e [#t eof]) (read))])
                (unless (eof-object? expr)
                  (let ([val (eval expr (interaction-environment))])
                    ;; Print non-void results
                    (unless (eq? val (void))
                      (unless first (newline))
                      (write val)))
                  (loop #f))))))))))
