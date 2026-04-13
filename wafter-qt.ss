#!/usr/bin/env scheme-script
#!chezscheme
;; wafter-qt.ss — Qt GUI entry point for wafter packet analyzer
;;
;; Must be run from the project root directory.
;;
;; Via Makefile (recommended):
;;   make qt              — interactive mode (requires X11 or Wayland)
;;   make qt-offscreen    — headless, no display needed
;;   make qt-screenshot   — headless, saves PNG screenshot and exits
;;
;; Directly (env setup required):
;;   export CHEZ_QT_LIB=~/mine/chez-qt
;;   export CHEZ_QT_SHIM_DIR=<dir-with-libqt_shim.so>
;;   export LD_PRELOAD=$CHEZ_QT_LIB/qt_chez_shim.so
;;   export LD_LIBRARY_PATH=$CHEZ_QT_SHIM_DIR:$CHEZ_QT_LIB:$LD_LIBRARY_PATH
;;   scheme --libdirs ~/mine/chez-qt:lib --script wafter-qt.ss [FILE.pcap]

(import (except (chezscheme)
                make-hash-table hash-table? sort sort!
                printf fprintf iota 1+ 1-
                partition make-date make-time
                path-extension path-absolute?
                with-input-from-string with-output-to-string)
        (jerboa prelude))

;; ── Load component modules in dependency order ───────────────────────────

(load "qt/dissect.ss")   ;; parsed-packet, layer, read-pcap-file, format-hex-dump
(load "qt/window.ss")    ;; wafter-window, create-wafter-window!, populate-*, etc.
(load "qt/repl.ss")      ;; start-repl!, stop-repl!
(load "qt/app.ss")       ;; *wafter-app*, start-wafter-qt!, load-pcap!, screenshot!, ...

;; ── --screenshot shortcut ────────────────────────────────────────────────
;; Usage: wafter-qt.ss --screenshot /tmp/out.png [file.pcap]
;; Renders the window offscreen, saves PNG, then exits.
;; Useful for automated LLM review: make qt-screenshot

(define (extract-flag flag args)
  "Return (value . remaining-args) if --flag VALUE found, else (#f . args)."
  (let loop ([rest args] [acc '()])
    (cond
      [(null? rest)
       (cons #f (reverse acc))]
      [(and (string=? (car rest) flag) (pair? (cdr rest)))
       (cons (cadr rest) (append (reverse acc) (cddr rest)))]
      [else
       (loop (cdr rest) (cons (car rest) acc))])))

(define (run-screenshot-mode ss-path remaining-args)
  "Initialize Qt offscreen, optionally load pcap, save screenshot, quit."
  (let ([app (qt-app-create)])
    (set! *qt-app* app)
    (init-app!)
    ;; Load first .pcap argument if present
    (let ([pcap-files (filter (lambda (a)
                                (or (string-suffix? ".pcap"   a)
                                    (string-suffix? ".pcapng" a)
                                    (string-suffix? ".cap"    a)))
                              remaining-args)])
      (unless (null? pcap-files)
        (load-pcap! (car pcap-files))))
    ;; Pump the event loop twice so widgets fully render
    (qt-app-process-events! app)
    (qt-app-process-events! app)
    ;; Capture
    (let ([ok (screenshot! ss-path)])
      (if ok
          (displayln (str "wafter-qt: screenshot saved to " ss-path))
          (displayln (str "wafter-qt: WARNING — screenshot failed for " ss-path))))
    (qt-app-quit! app)
    (qt-app-destroy! app)))

;; ── Main dispatch ─────────────────────────────────────────────────────────

(let* ([args    (command-line-arguments)]
       [pair    (extract-flag "--screenshot" args)]
       [ss-path (car pair)]
       [rest    (cdr pair)])
  (if ss-path
      (run-screenshot-mode ss-path rest)
      (apply start-wafter-qt! args)))
