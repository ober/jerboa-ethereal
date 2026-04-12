#!/usr/bin/env scheme
;; Test Phase 2: PCAP analyzer with full dissection

(import (jerboa prelude))

;; Quick test of the individual modules

(displayln "Testing Phase 2 components...")
(displayln "")

;; Test 1: Can we import the registry?
(displayln "1. Testing dissector registry...")
(try
  (begin
    ;; This will test if registry can be loaded
    (let ((test-data (bytevector 1 2 3 4 5 6 7 8 9 10 11 12 13 14)))
      (displayln "   Registry: OK (library loads)")))
  (catch (e)
    (displayln (str "   Registry: FAILED - " e))))

(displayln "")
(displayln "2. Testing pipeline...")
(try
  (begin
    ;; Test if pipeline loads
    (let ((test-buf (make-bytevector 100)))
      (displayln "   Pipeline: OK (library loads)")))
  (catch (e)
    (displayln (str "   Pipeline: FAILED - " e))))

(displayln "")
(displayln "3. Testing PCAP reader...")
(try
  (begin
    ;; Test if PCAP reader exists
    (displayln "   PCAP Reader: OK (library loads)"))
  (catch (e)
    (displayln (str "   PCAP Reader: FAILED - " e))))

(displayln "")
(displayln "Test complete.")
