;; packet-corosync-totemsrp.c
;; Dissectors for totem single ring protocol implemented in corosync cluster engine
;; Copyright 2007 2009 2010 2014 Masatake YAMATO <yamato@redhat.com>
;; Copyright (c) 2010 2014 Red Hat, Inc.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/corosync-totemsrp.ss
;; Auto-generated from wireshark/epan/dissectors/packet-corosync_totemsrp.c

(import (jerboa prelude))

;; ── Protocol Helpers ─────────────────────────────────────────────────
(def (read-u8 buf offset)
  (if (>= offset (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u8-ref buf offset))))

(def (read-u16be buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u16-ref buf offset (endianness big)))))

(def (read-u24be buf offset)
  (if (> (+ offset 3) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (+ (* (bytevector-u8-ref buf offset) 65536)
             (* (bytevector-u8-ref buf (+ offset 1)) 256)
             (bytevector-u8-ref buf (+ offset 2))))))

(def (read-u32be buf offset)
  (if (> (+ offset 4) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u32-ref buf offset (endianness big)))))

(def (read-u16le buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u16-ref buf offset (endianness little)))))

(def (read-u32le buf offset)
  (if (> (+ offset 4) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u32-ref buf offset (endianness little)))))

(def (read-u64be buf offset)
  (if (> (+ offset 8) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u64-ref buf offset (endianness big)))))

(def (read-u64le buf offset)
  (if (> (+ offset 8) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u64-ref buf offset (endianness little)))))

(def (slice buf offset len)
  (if (> (+ offset len) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (let ((result (make-bytevector len)))
            (bytevector-copy! buf offset result 0 len)
            result))))

(def (extract-bits val mask shift)
  (bitwise-arithmetic-shift-right (bitwise-and val mask) shift))

(def (fmt-ipv4 addr)
  (let ((b0 (bitwise-arithmetic-shift-right addr 24))
        (b1 (bitwise-and (bitwise-arithmetic-shift-right addr 16) 255))
        (b2 (bitwise-and (bitwise-arithmetic-shift-right addr 8) 255))
        (b3 (bitwise-and addr 255)))
    (str b0 "." b1 "." b2 "." b3)))

(def (fmt-mac bytes)
  (string-join
    (map (lambda (b) (string-pad (number->string b 16) 2 #\0))
         (bytevector->list bytes))
    ":"))

(def (fmt-hex val)
  (str "0x" (number->string val 16)))

(def (fmt-oct val)
  (str "0" (number->string val 8)))

(def (fmt-port port)
  (number->string port))

(def (fmt-bytes bv)
  (string-join
    (map (lambda (b) (string-pad (number->string b 16) 2 #\0))
         (bytevector->list bv))
    " "))

(def (fmt-ipv6-address bytes)
  (let loop ((i 0) (parts '()))
    (if (>= i 16)
        (string-join (reverse parts) ":")
        (loop (+ i 2)
              (cons (let ((w (+ (* (bytevector-u8-ref bytes i) 256)
                                (bytevector-u8-ref bytes (+ i 1)))))
                      (number->string w 16))
                    parts)))))

;; ── Dissector ──────────────────────────────────────────────────────
(def (dissect-corosync-totemsrp buffer)
  "Totem Single Ring Protocol implemented in Corosync Cluster Engine"
  (try
    (let* (
           (totemsrp-ip-address-nodeid (unwrap (read-u32be buffer 0)))
           (totemsrp-message-header-endian-detector (unwrap (read-u16be buffer 2)))
           (totemsrp-message-header-nodeid (unwrap (read-u32be buffer 4)))
           (totemsrp-ip-address-addr4 (unwrap (read-u32be buffer 6)))
           (totemsrp-ip-address-addr6 (unwrap (slice buffer 6 16)))
           (totemsrp-ip-address-addr (unwrap (slice buffer 6 1)))
           (totemsrp-ip-address-addr4-padding (unwrap (slice buffer 6 1)))
           (totemsrp-memb-ring-id-seq (unwrap (read-u64be buffer 6)))
           (totemsrp-rtr-item-seq (unwrap (read-u32be buffer 14)))
           (totemsrp-orf-token-seq (unwrap (read-u32be buffer 18)))
           (totemsrp-orf-token-token-seq (unwrap (read-u32be buffer 22)))
           (totemsrp-orf-token-aru (unwrap (read-u32be buffer 26)))
           (totemsrp-orf-token-aru-addr (unwrap (read-u32be buffer 30)))
           (totemsrp-orf-token-backlog (unwrap (read-u32be buffer 34)))
           (totemsrp-orf-token-fcc (unwrap (read-u32be buffer 38)))
           (totemsrp-orf-token-retrnas-flg (unwrap (read-u32be buffer 42)))
           (totemsrp-orf-token-rtr-list-entries (unwrap (read-u32be buffer 46)))
           (totemsrp-mcast-seq (unwrap (read-u32be buffer 50)))
           (totemsrp-mcast-this-seqno (unwrap (read-u32be buffer 54)))
           (totemsrp-mcast-node-id (unwrap (read-u32be buffer 58)))
           (totemsrp-mcast-guarantee (unwrap (read-u32be buffer 62)))
           (totemsrp-memb-join-proc-list-entries (unwrap (read-u32be buffer 66)))
           (totemsrp-memb-join-failed-list-entries (unwrap (read-u32be buffer 70)))
           (totemsrp-memb-join-ring-seq (unwrap (read-u64be buffer 74)))
           (totemsrp-memb-commit-token-memb-entry-aru (unwrap (read-u32be buffer 82)))
           (totemsrp-memb-commit-token-memb-entry-high-delivered (unwrap (read-u32be buffer 86)))
           (totemsrp-memb-commit-token-memb-entry-received-flg (unwrap (read-u32be buffer 90)))
           (totemsrp-memb-commit-token-token-seq (unwrap (read-u32be buffer 94)))
           (totemsrp-memb-commit-token-retrans-flg (unwrap (read-u32be buffer 98)))
           (totemsrp-memb-commit-token-memb-index (unwrap (read-u32be buffer 102)))
           (totemsrp-memb-commit-token-addr-entries (unwrap (read-u32be buffer 106)))
           )

      (ok (list
        (cons 'totemsrp-ip-address-nodeid (list (cons 'raw totemsrp-ip-address-nodeid) (cons 'formatted (number->string totemsrp-ip-address-nodeid))))
        (cons 'totemsrp-message-header-endian-detector (list (cons 'raw totemsrp-message-header-endian-detector) (cons 'formatted (fmt-hex totemsrp-message-header-endian-detector))))
        (cons 'totemsrp-message-header-nodeid (list (cons 'raw totemsrp-message-header-nodeid) (cons 'formatted (number->string totemsrp-message-header-nodeid))))
        (cons 'totemsrp-ip-address-addr4 (list (cons 'raw totemsrp-ip-address-addr4) (cons 'formatted (fmt-ipv4 totemsrp-ip-address-addr4))))
        (cons 'totemsrp-ip-address-addr6 (list (cons 'raw totemsrp-ip-address-addr6) (cons 'formatted (fmt-ipv6-address totemsrp-ip-address-addr6))))
        (cons 'totemsrp-ip-address-addr (list (cons 'raw totemsrp-ip-address-addr) (cons 'formatted (fmt-bytes totemsrp-ip-address-addr))))
        (cons 'totemsrp-ip-address-addr4-padding (list (cons 'raw totemsrp-ip-address-addr4-padding) (cons 'formatted (fmt-bytes totemsrp-ip-address-addr4-padding))))
        (cons 'totemsrp-memb-ring-id-seq (list (cons 'raw totemsrp-memb-ring-id-seq) (cons 'formatted (number->string totemsrp-memb-ring-id-seq))))
        (cons 'totemsrp-rtr-item-seq (list (cons 'raw totemsrp-rtr-item-seq) (cons 'formatted (number->string totemsrp-rtr-item-seq))))
        (cons 'totemsrp-orf-token-seq (list (cons 'raw totemsrp-orf-token-seq) (cons 'formatted (number->string totemsrp-orf-token-seq))))
        (cons 'totemsrp-orf-token-token-seq (list (cons 'raw totemsrp-orf-token-token-seq) (cons 'formatted (number->string totemsrp-orf-token-token-seq))))
        (cons 'totemsrp-orf-token-aru (list (cons 'raw totemsrp-orf-token-aru) (cons 'formatted (number->string totemsrp-orf-token-aru))))
        (cons 'totemsrp-orf-token-aru-addr (list (cons 'raw totemsrp-orf-token-aru-addr) (cons 'formatted (number->string totemsrp-orf-token-aru-addr))))
        (cons 'totemsrp-orf-token-backlog (list (cons 'raw totemsrp-orf-token-backlog) (cons 'formatted (number->string totemsrp-orf-token-backlog))))
        (cons 'totemsrp-orf-token-fcc (list (cons 'raw totemsrp-orf-token-fcc) (cons 'formatted (number->string totemsrp-orf-token-fcc))))
        (cons 'totemsrp-orf-token-retrnas-flg (list (cons 'raw totemsrp-orf-token-retrnas-flg) (cons 'formatted (number->string totemsrp-orf-token-retrnas-flg))))
        (cons 'totemsrp-orf-token-rtr-list-entries (list (cons 'raw totemsrp-orf-token-rtr-list-entries) (cons 'formatted (number->string totemsrp-orf-token-rtr-list-entries))))
        (cons 'totemsrp-mcast-seq (list (cons 'raw totemsrp-mcast-seq) (cons 'formatted (number->string totemsrp-mcast-seq))))
        (cons 'totemsrp-mcast-this-seqno (list (cons 'raw totemsrp-mcast-this-seqno) (cons 'formatted (number->string totemsrp-mcast-this-seqno))))
        (cons 'totemsrp-mcast-node-id (list (cons 'raw totemsrp-mcast-node-id) (cons 'formatted (number->string totemsrp-mcast-node-id))))
        (cons 'totemsrp-mcast-guarantee (list (cons 'raw totemsrp-mcast-guarantee) (cons 'formatted (number->string totemsrp-mcast-guarantee))))
        (cons 'totemsrp-memb-join-proc-list-entries (list (cons 'raw totemsrp-memb-join-proc-list-entries) (cons 'formatted (number->string totemsrp-memb-join-proc-list-entries))))
        (cons 'totemsrp-memb-join-failed-list-entries (list (cons 'raw totemsrp-memb-join-failed-list-entries) (cons 'formatted (number->string totemsrp-memb-join-failed-list-entries))))
        (cons 'totemsrp-memb-join-ring-seq (list (cons 'raw totemsrp-memb-join-ring-seq) (cons 'formatted (number->string totemsrp-memb-join-ring-seq))))
        (cons 'totemsrp-memb-commit-token-memb-entry-aru (list (cons 'raw totemsrp-memb-commit-token-memb-entry-aru) (cons 'formatted (number->string totemsrp-memb-commit-token-memb-entry-aru))))
        (cons 'totemsrp-memb-commit-token-memb-entry-high-delivered (list (cons 'raw totemsrp-memb-commit-token-memb-entry-high-delivered) (cons 'formatted (number->string totemsrp-memb-commit-token-memb-entry-high-delivered))))
        (cons 'totemsrp-memb-commit-token-memb-entry-received-flg (list (cons 'raw totemsrp-memb-commit-token-memb-entry-received-flg) (cons 'formatted (number->string totemsrp-memb-commit-token-memb-entry-received-flg))))
        (cons 'totemsrp-memb-commit-token-token-seq (list (cons 'raw totemsrp-memb-commit-token-token-seq) (cons 'formatted (number->string totemsrp-memb-commit-token-token-seq))))
        (cons 'totemsrp-memb-commit-token-retrans-flg (list (cons 'raw totemsrp-memb-commit-token-retrans-flg) (cons 'formatted (number->string totemsrp-memb-commit-token-retrans-flg))))
        (cons 'totemsrp-memb-commit-token-memb-index (list (cons 'raw totemsrp-memb-commit-token-memb-index) (cons 'formatted (number->string totemsrp-memb-commit-token-memb-index))))
        (cons 'totemsrp-memb-commit-token-addr-entries (list (cons 'raw totemsrp-memb-commit-token-addr-entries) (cons 'formatted (number->string totemsrp-memb-commit-token-addr-entries))))
        )))

    (catch (e)
      (err (str "COROSYNC-TOTEMSRP parse error: " e)))))

;; dissect-corosync-totemsrp: parse COROSYNC-TOTEMSRP from bytevector
;; Returns (ok fields-alist) or (err message)