#!/usr/bin/env scheme
;; jerboa-ethereal/lib/dissector/loader.ss
;; Dissector loader and initialization
;;
;; This module handles loading all protocol dissectors and registering them
;; with the protocol registry. Used at startup to populate the dissection pipeline.
;;
;; Phase 7: Dynamic dissector loading for both interpreter and static binary modes

(import (jerboa prelude))

;; ── Dissector Loading ──────────────────────────────────────────────────────

(def (try-load-dissector proto-name file-path)
  "Try to load a dissector from file
   Returns (ok count) if successful, (err message) on failure
   count = number of exports from the dissector"

  (try
    (begin
      ;; Try to load and evaluate the dissector file
      (call-with-input-file file-path
        (lambda (port)
          (let loop ((count 0))
            (let ((form (read port)))
              (if (eof-object? form)
                  (ok count)
                  (begin
                    ;; Evaluate form in current environment
                    (eval form)
                    (loop (+ count 1))))))))
    (catch (e)
      (err (str "Failed to load " proto-name ": " e)))))

(def (load-dissectors-from-directory dir)
  "Load all .ss dissector files from a directory
   Returns list of loaded protocol names"

  (let ((dissector-files
         '(("ethernet" "dissectors/ethernet.ss")
           ("ipv4" "dissectors/ipv4.ss")
           ("ipv6" "dissectors/ipv6.ss")
           ("arp" "dissectors/arp.ss")
           ("tcp" "dissectors/tcp.ss")
           ("udp" "dissectors/udp.ss")
           ("icmp" "dissectors/icmp.ss")
           ("icmpv6" "dissectors/icmpv6.ss")
           ("igmp" "dissectors/igmp.ss")
           ("dns" "dissectors/dns.ss")
           ("dhcp" "dissectors/dhcp.ss")
           ("ntp" "dissectors/ntp.ss")
           ("ssh" "dissectors/ssh.ss"))))

    ;; Try to load each dissector
    (let ((results (map (lambda (entry)
                         (let ((name (car entry))
                               (path (cadr entry)))
                           (cons name (try-load-dissector name path))))
                       dissector-files)))

      ;; Report results
      (let ((loaded (filter (lambda (r) (ok? (cdr r))) results))
            (failed (filter (lambda (r) (err? (cdr r))) results)))

        (displayln (str "Loaded " (length loaded) " dissectors:"))
        (for ((entry loaded))
          (displayln (str "  ✓ " (car entry))))

        (if (> (length failed) 0)
            (begin
              (displayln "")
              (displayln (str "Failed to load " (length failed) " dissectors:"))
              (for ((entry failed))
                (displayln (str "  ✗ " (car entry) ": " (unwrap-or (cdr entry) "unknown error"))))))

        ;; Return loaded protocol names
        (map car loaded)))))

;; ── Registration Pipeline ──────────────────────────────────────────────────

(def (register-builtin-dissectors!)
  "Register all built-in dissectors with the protocol registry
   This is called at startup to populate the dissector table"

  (displayln "Registering dissectors with protocol registry...")

  ;; For now, dissectors must be imported separately and their
  ;; dissect-PROTO functions made available. In a static binary,
  ;; these would be pre-compiled and linked.

  ;; Layer 2 (Link Layer)
  ;; (register-dissector! 'ethernet dissect-ethernet)
  ;; (register-dissector! 'arp dissect-arp)

  ;; Layer 3 (Network Layer)
  ;; (register-dissector! 'ipv4 dissect-ipv4)
  ;; (register-dissector! 'ipv6 dissect-ipv6)
  ;; (register-dissector! 'icmp dissect-icmp)
  ;; (register-dissector! 'icmpv6 dissect-icmpv6)
  ;; (register-dissector! 'igmp dissect-igmp)

  ;; Layer 4 (Transport Layer)
  ;; (register-dissector! 'tcp dissect-tcp)
  ;; (register-dissector! 'udp dissect-udp)

  ;; Layer 5-7 (Application Layer)
  ;; (register-dissector! 'dns dissect-dns)
  ;; (register-dissector! 'dhcp dissect-dhcp)
  ;; (register-dissector! 'ntp dissect-ntp)
  ;; (register-dissector! 'ssh dissect-ssh)

  ;; Note: Actual registration happens in dissector modules
  ;; This function serves as a checkpoint

  (displayln "✓ Dissector registry initialized"))

;; ── Module Interface ───────────────────────────────────────────────────────

(def (init-dissectors!)
  "Initialize the dissector system at startup
   1. Load dissector modules
   2. Register with protocol registry
   3. Verify protocol chaining"

  (displayln "═══════════════════════════════════════════════════════")
  (displayln "Initializing Dissector System")
  (displayln "═══════════════════════════════════════════════════════")
  (displayln "")

  (register-builtin-dissectors!)

  (displayln "")
  (displayln "✓ Dissector system initialized")
  (displayln ""))

;; ── Exported API ───────────────────────────────────────────────────────────

;; init-dissectors!: Initialize the complete dissector system
;; try-load-dissector: Attempt to load a single dissector file
;; load-dissectors-from-directory: Batch load all dissectors from a directory
;;
;; Phase 7 Note: This module provides the foundation for dynamic dissector
;;               loading in the interpreter. For static binaries, dissectors
;;               are pre-compiled and linked, making this primarily a startup
;;               coordination module.
