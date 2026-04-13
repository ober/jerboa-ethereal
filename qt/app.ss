#!chezscheme
;; qt/app.ss — Application state, lifecycle, and REPL integration for wafter-qt
;;
;; Assumes dissect.ss, window.ss, and repl.ss have already been loaded.
;;
;; REPL-accessible API (all globals via TCP REPL on --repl PORT):
;;   (load-pcap! "/path/to/file.pcap")   → load packets, refresh UI
;;   (screenshot! "/tmp/snap.png")        → capture window PNG
;;   (get-packet-count)                   → total loaded packets
;;   (get-shown-count)                    → displayed after filter
;;   (get-packets)                        → list of parsed-packet records
;;   (get-shown-packets)                  → filtered packet list
;;   (get-selected-packet)                → current packet or #f
;;   (filter-packets! "tcp")              → apply display filter
;;   (clear-filter!)                      → show all packets
;;   (select-packet! 0)                   → select by index (0-based)

(import (except (chezscheme)
                make-hash-table hash-table? sort sort!
                printf fprintf iota 1+ 1-
                partition make-date make-time
                path-extension path-absolute?
                with-input-from-string with-output-to-string)
        (jerboa prelude)
        (chez-qt qt))

;; ── App State ─────────────────────────────────────────────────────────────
;; defstruct generates setters (e.g., app-state-window-set!)

(defstruct app-state
  (window           ;; wafter-window record
   all-packets      ;; list: all parsed-packet records
   shown-packets    ;; list: currently displayed (after filter)
   selected-idx     ;; integer or #f: selected index in shown-packets
   pcap-path        ;; string or #f: currently loaded file path
   filter-text))    ;; string: current filter expression

(def *wafter-app* #f)   ;; single global app-state instance
(def *qt-app*     #f)   ;; Qt application object (for quit)

;; ── Path Utilities ────────────────────────────────────────────────────────

(def (path-last p)
  "Return the filename component of a path."
  (let* ([parts    (string-split p #\/)]
         [nonempty (filter (lambda (s) (not (string-empty? s))) parts)])
    (if (null? nonempty) p (car (take-last nonempty 1)))))

;; ── Filter Logic ──────────────────────────────────────────────────────────

(def (filter-match? text pkt)
  "Return #t if pkt matches the filter text (case-insensitive substring)."
  (if (string-empty? text)
      #t
      (let ([t   (string-downcase text)]
            [src (string-downcase (parsed-packet-src pkt))]
            [dst (string-downcase (parsed-packet-dst pkt))]
            [pr  (string-downcase (parsed-packet-protocol pkt))]
            [inf (string-downcase (parsed-packet-info pkt))])
        ;; string-contains returns index (truthy) or #f
        (or (string-contains src t)
            (string-contains dst t)
            (string-contains pr t)
            (string-contains inf t)))))

(def (apply-filter packets text)
  "Return filtered packet list."
  (if (string-empty? text)
      packets
      (filter (lambda (p) (filter-match? text p)) packets)))

;; ── Status Bar ────────────────────────────────────────────────────────────

(def (refresh-status! app)
  (let* ([ww      (app-state-window app)]
         [n-all   (length (app-state-all-packets app))]
         [n-shown (length (app-state-shown-packets app))]
         [sel     (app-state-selected-idx app)])
    (set-window-status! ww
      (str "Packets: " n-all
           "  Displayed: " n-shown
           (if sel (str "  Selected: " (+ sel 1)) "")))))

;; ── REPL-Accessible API ───────────────────────────────────────────────────

(def (load-pcap! path)
  "Load a PCAP file and populate the UI. Returns packet count or error string."
  (unless *wafter-app* (error 'load-pcap! "App not initialized"))
  (let ([result (read-pcap-file path)])
    (if (err? result)
        (let ([msg (str "Error loading " path ": " (unwrap-or result "unknown error"))])
          (set-window-status! (app-state-window *wafter-app*) msg)
          msg)
        (let* ([pkts  (unwrap result)]
               [text  (app-state-filter-text *wafter-app*)]
               [shown (apply-filter pkts text)]
               [app   *wafter-app*])
          (app-state-all-packets-set!  app pkts)
          (app-state-shown-packets-set! app shown)
          (app-state-selected-idx-set! app #f)
          (app-state-pcap-path-set!    app path)
          ;; Refresh UI (anti-flicker handled inside each call)
          (populate-packet-list-relative! (app-state-window app) shown)
          (update-proto-tree! (app-state-window app) #f)
          (update-hex-view!   (app-state-window app) #f)
          (set-window-title!  (app-state-window app) (path-last path))
          (refresh-status! app)
          (length pkts)))))

(def (screenshot! path)
  "Capture the main window as a PNG. Returns #t on success."
  (unless *wafter-app* (error 'screenshot! "App not initialized"))
  (window-screenshot! (app-state-window *wafter-app*) path))

(def (get-packet-count)
  "Return total packets loaded."
  (if *wafter-app* (length (app-state-all-packets *wafter-app*)) 0))

(def (get-shown-count)
  "Return number of packets currently displayed."
  (if *wafter-app* (length (app-state-shown-packets *wafter-app*)) 0))

(def (get-packets)
  "Return list of all parsed-packet records."
  (if *wafter-app* (app-state-all-packets *wafter-app*) '()))

(def (get-shown-packets)
  "Return list of currently displayed packets."
  (if *wafter-app* (app-state-shown-packets *wafter-app*) '()))

(def (get-selected-packet)
  "Return the currently selected parsed-packet, or #f."
  (if *wafter-app*
      (let ([idx   (app-state-selected-idx *wafter-app*)]
            [shown (app-state-shown-packets *wafter-app*)])
        (and idx (>= idx 0) (< idx (length shown))
             (list-ref shown idx)))
      #f))

(def (filter-packets! text)
  "Apply a display filter. Returns count of matching packets."
  (unless *wafter-app* (error 'filter-packets! "App not initialized"))
  (let* ([app   *wafter-app*]
         [shown (apply-filter (app-state-all-packets app) text)])
    (app-state-shown-packets-set! app shown)
    (app-state-selected-idx-set!  app #f)
    (app-state-filter-text-set!   app text)
    (populate-packet-list-relative! (app-state-window app) shown)
    (update-proto-tree! (app-state-window app) #f)
    (update-hex-view!   (app-state-window app) #f)
    (refresh-status! app)
    (length shown)))

(def (clear-filter!)
  "Clear the display filter and show all packets."
  (filter-packets! ""))

(def (select-packet! idx)
  "Select a packet by 0-based index in the shown list. Returns idx or #f."
  (unless *wafter-app* (error 'select-packet! "App not initialized"))
  (let* ([app   *wafter-app*]
         [shown (app-state-shown-packets app)])
    (if (and (>= idx 0) (< idx (length shown)))
        (let ([pkt (list-ref shown idx)])
          (app-state-selected-idx-set! app idx)
          (update-proto-tree! (app-state-window app) pkt)
          (update-hex-view!   (app-state-window app) pkt)
          (refresh-status! app)
          idx)
        #f)))

;; ── UI Event Callbacks ────────────────────────────────────────────────────

(def (on-packet-selected! row)
  "Called when the user clicks a row in the packet table."
  (when *wafter-app*
    (select-packet! row)))

(def (on-open-file!)
  "Called when the user clicks Open or File → Open PCAP."
  (when *wafter-app*
    (let ([path (open-pcap-dialog (app-state-window *wafter-app*))])
      (when path
        (load-pcap! path)))))

(def (on-filter-apply! text)
  "Called when the user applies a filter."
  (when *wafter-app*
    (filter-packets! text)))

(def (on-quit!)
  "Called when the user quits."
  (when *qt-app*
    (qt-app-quit! *qt-app*)))

;; ── App Initialization ────────────────────────────────────────────────────

(def (init-app!)
  "Create the main window and initialize global app state."
  (let ([ww (create-wafter-window!
              on-open-file!
              on-packet-selected!
              on-filter-apply!
              on-quit!)])
    (set! *wafter-app*
      (make-app-state ww '() '() #f #f ""))
    (show-window! ww)
    *wafter-app*))

;; ── Argument Parsing ─────────────────────────────────────────────────────

(def (parse-repl-arg args)
  "Return (port . remaining-args) if --repl PORT is present, else #f."
  (let loop ([rest args] [acc '()])
    (cond
      [(null? rest) #f]
      [(and (string=? (car rest) "--repl")
            (pair? (cdr rest))
            (string->number (cadr rest)))
       (cons (string->number (cadr rest))
             (append (reverse acc) (cddr rest)))]
      [else (loop (cdr rest) (cons (car rest) acc))])))

(def (pcap-file? s)
  (or (string-suffix? ".pcap"   s)
      (string-suffix? ".pcapng" s)
      (string-suffix? ".cap"    s)))

;; ── Entry Point ───────────────────────────────────────────────────────────

(def (start-wafter-qt! args)
  "Parse args, create Qt app and window, start REPL if requested, run event loop."
  (cond
    [(member "--version" args)
     (displayln "wafter-qt 0.7.0")]
    [(member "--help" args)
     (for-each displayln
       '("Usage: wafter-qt [OPTIONS] [FILE.pcap]"
         ""
         "Options:"
         "  --version        Show version"
         "  --help           Show this help"
         "  --repl PORT      Start TCP debug REPL on PORT (0 = auto-assign)"
         "  --offscreen      Force offscreen rendering (set QT_QPA_PLATFORM=offscreen)"
         ""
         "REPL commands once connected (nc localhost PORT):"
         "  (load-pcap! \"/path/file.pcap\")"
         "  (screenshot! \"/tmp/snap.png\")"
         "  (get-packet-count)"
         "  (filter-packets! \"tcp\")"
         "  (select-packet! 0)"
         "  (get-selected-packet)"
         "  (quit)"))]
    [else
     (let* ([repl-info   (parse-repl-arg args)]
            [repl-port   (and repl-info (car repl-info))]
            [rest-args   (if repl-info (cdr repl-info) args)]
            [pcap-files  (filter pcap-file? rest-args)])
       ;; Create Qt application (no argv needed — Qt args handled by env)
       (let ([app (qt-app-create)])
         (set! *qt-app* app)
         ;; Build main window and initialize state
         (init-app!)
         ;; Start TCP REPL if --repl was given
         (when repl-port
           (start-repl! repl-port))
         ;; Load initial PCAP if provided as argument
         (unless (null? pcap-files)
           (load-pcap! (car pcap-files)))
         ;; Run Qt event loop (blocks until quit)
         (qt-app-exec! app)
         ;; Cleanup
         (when repl-port
           (stop-repl!))
         (qt-app-destroy! app)))]))
