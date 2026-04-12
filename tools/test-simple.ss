#!/usr/bin/env scheme
;; Simple test of Ethernet dissection

(import (jerboa prelude))

(def (fmt-mac bytes)
  (string-join
    (for/collect ((i (in-range 0 6)))
      (format "~2,'0x" (bytevector-u8-ref bytes i)))
    ":"))

(def (dissect-ethernet buffer)
  (try
    (let* ((dest-mac (if (>= (bytevector-length buffer) 6)
                        (let ((result (make-bytevector 6)))
                          (bytevector-copy! buffer 0 result 0 6)
                          result)
                        #f))
           (src-mac (if (>= (bytevector-length buffer) 12)
                       (let ((result (make-bytevector 6)))
                         (bytevector-copy! buffer 6 result 0 6)
                         result)
                       #f))
           (etype (if (>= (bytevector-length buffer) 14)
                     (bytevector-u16-ref buffer 12 (endianness big))
                     #f))
           (payload (if (> (bytevector-length buffer) 14)
                       (let ((len (- (bytevector-length buffer) 14)))
                         (let ((result (make-bytevector len)))
                           (bytevector-copy! buffer 14 result 0 len)
                           result))
                       #f)))

      (ok `((dest-mac . ((raw . ,dest-mac)
                        (formatted . ,(fmt-mac dest-mac))))
            (src-mac . ((raw . ,src-mac)
                       (formatted . ,(fmt-mac src-mac))))
            (etype . ((raw . ,etype)
                     (formatted . ,(if (= etype #x0800) "IPv4" "Other"))
                     (next-protocol . ,(if (= etype #x0800) 'ipv4 #f))))
            (payload . ,payload))))

    (catch (e)
      (err (str "Error: " e)))))

;; Create test packet
(let ((test-pkt (make-bytevector 34)))
  ;; Ethernet header
  (bytevector-u8-set! test-pkt 0 #x00)
  (bytevector-u8-set! test-pkt 1 #x11)
  (bytevector-u8-set! test-pkt 2 #x22)
  (bytevector-u8-set! test-pkt 3 #x33)
  (bytevector-u8-set! test-pkt 4 #x44)
  (bytevector-u8-set! test-pkt 5 #x55)
  (bytevector-u8-set! test-pkt 6 #xaa)
  (bytevector-u8-set! test-pkt 7 #xbb)
  (bytevector-u8-set! test-pkt 8 #xcc)
  (bytevector-u8-set! test-pkt 9 #xdd)
  (bytevector-u8-set! test-pkt 10 #xee)
  (bytevector-u8-set! test-pkt 11 #xff)
  ;; EtherType = 0x0800 (IPv4)
  (bytevector-u16-set! test-pkt 12 #x0800 (endianness big))

  (displayln "Test Ethernet dissection")
  (displayln "════════════════════════════════════════")

  (let ((result (dissect-ethernet test-pkt)))
    (if (ok? result)
        (let ((fields (unwrap result)))
          (displayln "✓ Dissection succeeded")
          (for ((field fields))
            (let ((name (car field))
                  (value (cdr field)))
              (displayln (str "  " name ": " value)))))
        (displayln (str "✗ Failed: " (unwrap-err result))))))

(displayln "")
(displayln "Done!")
