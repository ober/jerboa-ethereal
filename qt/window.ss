#!chezscheme
;; qt/window.ss — Wireshark-like 3-pane Qt main window
;;
;; Layout:
;;   ┌─────────────────────────────────────────────────┐
;;   │ File  View  Statistics  Help         [MenuBar]   │
;;   ├─────────────────────────────────────────────────┤
;;   │ [Open] [Filter: ____________] [Apply] [Clear]    │ ← Toolbar
;;   ├─────────────────────────────────────────────────┤
;;   │ #  │ Time  │ Source │ Dest │ Proto │ Len │ Info │ ← Packet list
;;   ├─────────────────────────────────────────────────┤
;;   │ ▼ Ethernet II      ...                           │ ← Proto tree
;;   │   ▶ Source: xx:xx...                             │
;;   ├─────────────────────────────────────────────────┤
;;   │ 0000  ff ff ff ff ...  │ ........               │ ← Hex view
;;   ├─────────────────────────────────────────────────┤
;;   │ Packets: 1234  Displayed: 100  Selected: 1       │ ← Status bar
;;   └─────────────────────────────────────────────────┘

(import (except (chezscheme)
                make-hash-table hash-table? sort sort!
                printf fprintf iota 1+ 1-
                partition make-date make-time
                path-extension path-absolute?
                with-input-from-string with-output-to-string)
        (jerboa prelude)
        (chez-qt qt))

;; ── Window State Record ──────────────────────────────────────────────────

(defrecord wafter-window
  (main-win       ;; QMainWindow
   toolbar        ;; QToolBar
   filter-edit    ;; QLineEdit
   splitter       ;; QSplitter (vertical)
   packet-table   ;; QTableWidget
   proto-tree     ;; QTreeWidget
   hex-view       ;; QTextEdit
   open-action    ;; QAction
   quit-action    ;; QAction
   apply-action)) ;; QAction (filter apply)

;; ── Protocol Row Colors ──────────────────────────────────────────────────

(define (proto->color proto)
  "Return a CSS background color for the protocol."
  (cond
    [(or (string-prefix? "TCP" proto) (string-prefix? "Transmission" proto))
     "#e8f5e8"]   ; light green
    [(string-prefix? "UDP" proto)             "#daeeff"]   ; light blue
    [(string-prefix? "Domain" proto)          "#ffffd0"]   ; DNS – yellow
    [(string-prefix? "ARP" proto)             "#faecc8"]   ; orange
    [(string-prefix? "ICMP" proto)            "#fde8e8"]   ; light red
    [(string-prefix? "DHCP" proto)            "#ede8fe"]   ; purple
    [(string-prefix? "NTP" proto)             "#e8feee"]   ; mint
    [(string-prefix? "HTTP" proto)            "#ffd9d9"]   ; salmon
    [(string-prefix? "SSH" proto)             "#f0f0f0"]   ; gray
    [else "#ffffff"]))

;; ── Main Window Creation ─────────────────────────────────────────────────

(def (create-wafter-window! on-open on-select on-filter on-quit)
  "Create and return a wafter-window record.
   on-open   : (lambda ()) → called when user opens a file
   on-select : (lambda (row)) → called when a packet row is clicked
   on-filter : (lambda (filter-text)) → called when filter is applied
   on-quit   : (lambda ()) → called when user quits"

  ;; ── Main window ────────────────────────────────────────────────────────
  (let* ([win    (qt-main-window-create)]
         [_      (qt-main-window-set-title! win "wafter — Packet Analyzer")]
         [_      (qt-widget-resize! win 1280 800)]

         ;; ── Menu Bar ───────────────────────────────────────────────────
         [mbar   (qt-main-window-menu-bar win)]

         ;; File menu
         [file-m (qt-menu-bar-add-menu mbar "File")]
         [open-a (qt-action-create "Open PCAP…")]
         [_      (qt-action-set-shortcut! open-a "Ctrl+O")]
         [_      (qt-menu-add-action! file-m open-a)]
         [_      (qt-menu-add-separator! file-m)]
         [quit-a (qt-action-create "Quit")]
         [_      (qt-action-set-shortcut! quit-a "Ctrl+Q")]
         [_      (qt-menu-add-action! file-m quit-a)]

         ;; View menu
         [view-m (qt-menu-bar-add-menu mbar "View")]
         [expand-a  (qt-action-create "Expand All")]
         [collapse-a (qt-action-create "Collapse All")]
         [_      (qt-menu-add-action! view-m expand-a)]
         [_      (qt-menu-add-action! view-m collapse-a)]

         ;; Statistics menu
         [stat-m (qt-menu-bar-add-menu mbar "Statistics")]
         [proto-hierarchy-a (qt-action-create "Protocol Hierarchy")]
         [_      (qt-menu-add-action! stat-m proto-hierarchy-a)]

         ;; Help menu
         [help-m (qt-menu-bar-add-menu mbar "Help")]
         [about-a (qt-action-create "About wafter")]
         [_      (qt-menu-add-action! help-m about-a)]

         ;; ── Toolbar ────────────────────────────────────────────────────
         [tbar   (qt-toolbar-create "Main")]
         [_      (qt-toolbar-set-movable! tbar #f)]
         [_      (qt-main-window-add-toolbar! win tbar)]

         ;; Open button
         [open-btn (qt-push-button-create "📂 Open")]
         [_      (qt-widget-set-tooltip! open-btn "Open a PCAP file (Ctrl+O)")]
         [_      (qt-toolbar-add-widget! tbar open-btn)]
         [_      (qt-toolbar-add-separator! tbar)]

         ;; Filter area
         [filter-lbl (qt-label-create "Filter:")]
         [_      (qt-toolbar-add-widget! tbar filter-lbl)]
         [filter-ed  (qt-line-edit-create)]
         [_      (qt-line-edit-set-placeholder! filter-ed
                   "Filter by protocol, IP, or port (e.g. tcp, 192.168.1.1, 53)")]
         [_      (qt-widget-set-minimum-width! filter-ed 380)]
         [_      (qt-toolbar-add-widget! tbar filter-ed)]

         [apply-btn (qt-push-button-create "Apply")]
         [_      (qt-widget-set-style-sheet! apply-btn
                   "QPushButton { background-color: #4a9eff; color: white; border-radius: 3px; padding: 4px 10px; }
                    QPushButton:hover { background-color: #3a8eef; }")]
         [_      (qt-toolbar-add-widget! tbar apply-btn)]

         [clear-btn  (qt-push-button-create "✕")]
         [_      (qt-widget-set-tooltip! clear-btn "Clear filter")]
         [_      (qt-toolbar-add-widget! tbar clear-btn)]

         ;; ── Central splitter ───────────────────────────────────────────
         ;; QT_VERTICAL = stacks children top-to-bottom (Wireshark layout)
         [splitter (qt-splitter-create QT_VERTICAL 0)]
         [_      (qt-splitter-set-handle-width! splitter 3)]

         ;; ── Packet List (top pane) ─────────────────────────────────────
         ;; Columns: #  Time  Source  Destination  Protocol  Length  Info
         [ptbl   (qt-table-widget-create 0 7)]
         [_      (for-each
                   (lambda (idx hdr)
                     (qt-table-widget-set-horizontal-header! ptbl idx hdr))
                   '(0 1 2 3 4 5 6)
                   '("No." "Time" "Source" "Destination" "Protocol" "Length" "Info"))]
         [_      (qt-widget-set-style-sheet! ptbl
                   (string-append
                     "QTableWidget { font-family: monospace; font-size: 12px; "
                     "gridline-color: #d0d0d0; selection-background-color: #0078d4; "
                     "selection-color: white; }"
                     "QHeaderView::section { background-color: #f0f0f0; "
                     "padding: 4px; border: 1px solid #d0d0d0; font-weight: bold; }"))]
         [_      (qt-view-header-set-stretch-last-section! ptbl #t #t)]
         [_      (qt-table-view-set-column-width! ptbl 0 50)]    ; #
         [_      (qt-table-view-set-column-width! ptbl 1 100)]   ; Time
         [_      (qt-table-view-set-column-width! ptbl 2 150)]   ; Source
         [_      (qt-table-view-set-column-width! ptbl 3 150)]   ; Destination
         [_      (qt-table-view-set-column-width! ptbl 4 90)]    ; Protocol
         [_      (qt-table-view-set-column-width! ptbl 5 60)]    ; Length
         ;; Info column (6) stretches to fill

         ;; ── Protocol Tree (middle pane) ────────────────────────────────
         [ptree  (qt-tree-widget-create)]
         [_      (qt-tree-widget-set-column-count! ptree 2)]
         [_      (qt-tree-widget-set-header-item-text! ptree 0 "Field")]
         [_      (qt-tree-widget-set-header-item-text! ptree 1 "Value")]
         [_      (qt-widget-set-style-sheet! ptree
                   (string-append
                     "QTreeWidget { font-family: monospace; font-size: 12px; "
                     "selection-background-color: #0078d4; selection-color: white; }"
                     "QHeaderView::section { background-color: #f0f0f0; "
                     "padding: 4px; border: 1px solid #d0d0d0; font-weight: bold; }"))]
         [_      (qt-view-header-set-stretch-last-section! ptree #t #t)]
         [_      (qt-tree-view-set-column-width! ptree 0 280)]

         ;; ── Hex View (bottom pane) ─────────────────────────────────────
         [hex    (qt-text-edit-create)]
         [_      (qt-text-edit-set-read-only! hex #t)]
         [_      (qt-widget-set-style-sheet! hex
                   (string-append
                     "QTextEdit { font-family: 'Courier New', Courier, monospace; "
                     "font-size: 12px; background-color: #1e1e1e; color: #d4d4d4; "
                     "selection-background-color: #264f78; }"))]
         [_      (qt-text-edit-set-placeholder! hex "(select a packet to see hex dump)")]

         ;; ── Assemble splitter ──────────────────────────────────────────
         [_      (qt-splitter-add-widget! splitter ptbl)]
         [_      (qt-splitter-add-widget! splitter ptree)]
         [_      (qt-splitter-add-widget! splitter hex)]
         ;; Initial proportions: 40% / 30% / 30%
         [_      (qt-splitter-set-sizes! splitter '(320 240 240))]
         [_      (qt-splitter-set-collapsible! splitter 0 #f)]
         [_      (qt-splitter-set-collapsible! splitter 1 #f)]
         [_      (qt-splitter-set-collapsible! splitter 2 #f)]

         ;; ── Central widget = splitter ─────────────────────────────────
         [_      (qt-main-window-set-central-widget! win splitter)]

         ;; ── Status bar ─────────────────────────────────────────────────
         [_      (qt-main-window-set-status-bar-text! win
                   "Ready — open a PCAP file to start")]

         ;; ── Wire signals ───────────────────────────────────────────────
         ;; File open
         [_      (qt-on-clicked! open-btn on-open)]
         [_      (qt-on-triggered! open-a  on-open)]
         ;; Quit
         [_      (qt-on-triggered! quit-a  on-quit)]
         ;; Packet selection
         [_      (qt-on-cell-clicked! ptbl
                   (lambda (row col) (on-select row)))]
         ;; Filter
         [_      (qt-on-clicked!          apply-btn
                   (lambda () (on-filter (qt-line-edit-text filter-ed))))]
         [_      (qt-on-return-pressed!   filter-ed
                   (lambda () (on-filter (qt-line-edit-text filter-ed))))]
         [_      (qt-on-clicked!          clear-btn
                   (lambda ()
                     (qt-line-edit-set-text! filter-ed "")
                     (on-filter "")))]
         ;; View menu
         [_      (qt-on-triggered! expand-a
                   (lambda () (qt-tree-widget-expand-all! ptree)))]
         [_      (qt-on-triggered! collapse-a
                   (lambda () (qt-tree-widget-collapse-all! ptree)))]
         ;; About
         [_      (qt-on-triggered! about-a
                   (lambda ()
                     (qt-message-box-information win "About wafter"
                       (str "wafter — PCAP Packet Analyzer\n"
                            "Version 0.7.0\n\n"
                            "Built with Jerboa + chez-qt.\n"
                            "Supports: Ethernet, IPv4, IPv6, ARP, TCP, UDP,\n"
                            "ICMP, ICMPv6, DNS, DHCP, NTP, SSH, HTTP."))))])

    (make-wafter-window win tbar filter-ed splitter
                        ptbl ptree hex
                        open-a quit-a apply-btn)))

;; ── Populate Packet List ──────────────────────────────────────────────────

(def (populate-packet-list! ww packets)
  "Fill the packet table with a list of parsed-packet records.
   Anti-flicker: updates are batched via setUpdatesEnabled."
  (let ([tbl (wafter-window-packet-table ww)])
    (qt-widget-set-updates-enabled! tbl #f)
    (qt-table-widget-set-row-count! tbl 0)  ; clear
    (qt-table-widget-set-row-count! tbl (length packets))
    (let loop ([pkts packets] [row 0])
      (unless (null? pkts)
        (let* ([pkt  (car pkts)]
               [ts   (parsed-packet-timestamp pkt)]
               [src  (parsed-packet-src pkt)]
               [dst  (parsed-packet-dst pkt)]
               [pr   (parsed-packet-protocol pkt)]
               [len  (parsed-packet-caplen pkt)]
               [info (parsed-packet-info pkt)]
               ;; Format relative time (first packet = 0.000000)
               [ts-str (format "~,6f" ts)])
          (qt-table-widget-set-item! tbl row 0 (format "~a" (+ row 1)))
          (qt-table-widget-set-item! tbl row 1 ts-str)
          (qt-table-widget-set-item! tbl row 2 src)
          (qt-table-widget-set-item! tbl row 3 dst)
          (qt-table-widget-set-item! tbl row 4 pr)
          (qt-table-widget-set-item! tbl row 5 (format "~a" len))
          (qt-table-widget-set-item! tbl row 6 info))
        (loop (cdr pkts) (+ row 1))))
    (qt-widget-set-updates-enabled! tbl #t)))

;; ── Populate Packet List with Time-Relative Offset ───────────────────────

(def (populate-packet-list-relative! ww packets)
  "Like populate-packet-list! but timestamps are relative to first packet."
  (let* ([tbl    (wafter-window-packet-table ww)]
         [base-ts (if (null? packets)
                      0.0
                      (parsed-packet-timestamp (car packets)))])
    (qt-widget-set-updates-enabled! tbl #f)
    (qt-table-widget-set-row-count! tbl 0)
    (qt-table-widget-set-row-count! tbl (length packets))
    (let loop ([pkts packets] [row 0])
      (unless (null? pkts)
        (let* ([pkt  (car pkts)]
               [rel  (- (parsed-packet-timestamp pkt) base-ts)]
               [src  (parsed-packet-src pkt)]
               [dst  (parsed-packet-dst pkt)]
               [pr   (parsed-packet-protocol pkt)]
               [len  (parsed-packet-caplen pkt)]
               [info (parsed-packet-info pkt)])
          (qt-table-widget-set-item! tbl row 0 (format "~a" (+ row 1)))
          (qt-table-widget-set-item! tbl row 1 (format "~,6f" rel))
          (qt-table-widget-set-item! tbl row 2 src)
          (qt-table-widget-set-item! tbl row 3 dst)
          (qt-table-widget-set-item! tbl row 4 pr)
          (qt-table-widget-set-item! tbl row 5 (format "~a" len))
          (qt-table-widget-set-item! tbl row 6 info))
        (loop (cdr pkts) (+ row 1))))
    (qt-widget-set-updates-enabled! tbl #t)))

;; ── Update Protocol Tree ──────────────────────────────────────────────────

(def (update-proto-tree! ww pkt)
  "Populate the protocol tree for the selected packet."
  (let ([tree (wafter-window-proto-tree ww)])
    (qt-widget-set-updates-enabled! tree #f)
    (qt-tree-widget-clear! tree)
    (when pkt
      (for-each
        (lambda (l)
          (let* ([top  (qt-tree-item-create)]
                 [_    (qt-tree-item-set-text! top 0 (layer-name l))]
                 [_    (qt-tree-item-set-text! top 1
                          (format "~a bytes"
                                  (- (layer-end l) (layer-start l))))])
            ;; Add field children
            (for-each
              (lambda (field)
                (let ([child (qt-tree-item-create)])
                  (qt-tree-item-set-text! child 0 (car field))
                  (qt-tree-item-set-text! child 1 (cdr field))
                  (qt-tree-item-add-child! top child)))
              (layer-fields l))
            (qt-tree-widget-add-top-level-item! tree top)
            (qt-tree-widget-expand-item! tree top)))
        (parsed-packet-layers pkt)))
    (qt-widget-set-updates-enabled! tree #t)))

;; ── Update Hex View ───────────────────────────────────────────────────────

(def (update-hex-view! ww pkt)
  "Populate the hex dump view for the selected packet."
  (let ([hex (wafter-window-hex-view ww)])
    (if pkt
        (let ([dump (format-hex-dump (parsed-packet-data pkt))])
          (qt-text-edit-set-text! hex dump))
        (qt-text-edit-set-text! hex "(no packet selected)"))))

;; ── Set Status Bar ────────────────────────────────────────────────────────

(def (set-window-status! ww msg)
  (qt-main-window-set-status-bar-text! (wafter-window-main-win ww) msg))

;; ── Screenshot ────────────────────────────────────────────────────────────

(def (window-screenshot! ww path)
  "Capture the main window as a PNG. Returns #t on success."
  (qt-widget-screenshot! (wafter-window-main-win ww) path))

;; ── Show / Hide ───────────────────────────────────────────────────────────

(def (show-window! ww)
  (qt-widget-show! (wafter-window-main-win ww)))

(def (hide-window! ww)
  (qt-widget-hide! (wafter-window-main-win ww)))

;; ── Open File Dialog ──────────────────────────────────────────────────────

(def (open-pcap-dialog ww)
  "Show file-open dialog filtered to PCAP files. Returns path string or #f."
  (let ([path (qt-file-dialog-open-file
                (wafter-window-main-win ww)
                "Open PCAP File"
                ""
                "PCAP Files (*.pcap *.pcapng *.cap);;All Files (*)")])
    (and path
         (not (string=? path ""))
         path)))

;; ── Update Window Title ───────────────────────────────────────────────────

(def (set-window-title! ww title)
  (qt-main-window-set-title!
    (wafter-window-main-win ww)
    (if (string=? title "")
        "wafter — Packet Analyzer"
        (str "wafter — " title))))

;; ── Select Row Programmatically (from REPL) ──────────────────────────────

(def (select-row! ww row)
  "Note: chez-qt has no qt-table-widget-set-current-row! binding yet.
   The proto-tree and hex view are updated by the caller (select-packet!).
   This stub is intentionally empty — visual highlight only on user click."
  (void))
