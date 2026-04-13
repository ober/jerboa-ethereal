;; packet-nstrace.c
;; Routines for nstrace dissection
;; Copyright 2006, Ravi Kondamuru <Ravi.Kondamuru@citrix.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/nstrace.ss
;; Auto-generated from wireshark/epan/dissectors/packet-nstrace.c

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
(def (dissect-nstrace buffer)
  "NetScaler Trace"
  (try
    (let* (
           (tcpdbg-cwnd (unwrap (read-u32be buffer 0)))
           (tcpdbg-rtrtt (unwrap (read-u32be buffer 0)))
           (tcpdbg-tsrecent (unwrap (read-u32be buffer 0)))
           (tcpdbg2-sndCwnd (unwrap (read-u32be buffer 0)))
           (tcpdbg2-ssthresh (unwrap (read-u32be buffer 0)))
           (tcpdbg2-sndbuf (unwrap (read-u32be buffer 0)))
           (tcpdbg2-max-rcvbuf (unwrap (read-u32be buffer 0)))
           (tcpdbg2-bw-estimate (unwrap (read-u32be buffer 0)))
           (tcpdbg2-rtt (unwrap (read-u32be buffer 0)))
           (tcpdbg2-tcpos-pktcnt (unwrap (read-u32be buffer 0)))
           (tcpdbg2-ts-recent (unwrap (read-u32be buffer 0)))
           (tcpdbg2-tcp-cfgsndbuf (unwrap (read-u32be buffer 0)))
           (trcdbg-val15 (unwrap (read-u32be buffer 0)))
           (tcpcc-last-max-cwnd (unwrap (read-u32be buffer 0)))
           (tcpcc-loss-cwnd (unwrap (read-u32be buffer 0)))
           (tcpcc-last-time (unwrap (read-u32be buffer 0)))
           (tcpcc-last-cwnd (unwrap (read-u32be buffer 0)))
           (tcpcc-delay-min (unwrap (read-u32be buffer 0)))
           (tcpcc-ack-cnt (unwrap (read-u32be buffer 0)))
           (tcpcc-alpha (unwrap (read-u32be buffer 0)))
           (tcpcc-beta-val (unwrap (read-u32be buffer 0)))
           (tcpcc-rtt-low (unwrap (read-u32be buffer 0)))
           (tcpcc-rtt-above (unwrap (read-u32be buffer 0)))
           (tcpcc-max-rtt (unwrap (read-u32be buffer 0)))
           (tcpcc-base-rtt (unwrap (read-u32be buffer 0)))
           (tcpcc-rtt-min (unwrap (read-u32be buffer 0)))
           (tcpcc-last-ack (unwrap (read-u32be buffer 0)))
           (tcpcc-round-start (unwrap (read-u32be buffer 0)))
           (tcpcc-end-seq (unwrap (read-u32be buffer 0)))
           (tcpcc-curr-rtt (unwrap (read-u32be buffer 0)))
           (inforec-info (unwrap (slice buffer 0 1)))
           (sslrec-seq (unwrap (read-u32be buffer 0)))
           (mptcprec-subflowid (unwrap (read-u8 buffer 0)))
           (vmnamerec-srcvmname (unwrap (slice buffer 0 1)))
           (clu-snode (unwrap (read-u16be buffer 0)))
           (clu-dnode (unwrap (read-u16be buffer 0)))
           (clu-clflags (unwrap (read-u8 buffer 0)))
           (clu-clflags-fp (extract-bits clu-clflags 0x0 0))
           (clu-clflags-fr (extract-bits clu-clflags 0x0 0))
           (clu-clflags-dfd (extract-bits clu-clflags 0x0 0))
           (clu-clflags-rss (extract-bits clu-clflags 0x0 0))
           (clu-clflags-rssh (extract-bits clu-clflags 0x0 0))
           (clu-clflags-res (extract-bits clu-clflags 0x0 0))
           )

      (ok (list
        (cons 'tcpdbg-cwnd (list (cons 'raw tcpdbg-cwnd) (cons 'formatted (number->string tcpdbg-cwnd))))
        (cons 'tcpdbg-rtrtt (list (cons 'raw tcpdbg-rtrtt) (cons 'formatted (number->string tcpdbg-rtrtt))))
        (cons 'tcpdbg-tsrecent (list (cons 'raw tcpdbg-tsrecent) (cons 'formatted (number->string tcpdbg-tsrecent))))
        (cons 'tcpdbg2-sndCwnd (list (cons 'raw tcpdbg2-sndCwnd) (cons 'formatted (number->string tcpdbg2-sndCwnd))))
        (cons 'tcpdbg2-ssthresh (list (cons 'raw tcpdbg2-ssthresh) (cons 'formatted (number->string tcpdbg2-ssthresh))))
        (cons 'tcpdbg2-sndbuf (list (cons 'raw tcpdbg2-sndbuf) (cons 'formatted (number->string tcpdbg2-sndbuf))))
        (cons 'tcpdbg2-max-rcvbuf (list (cons 'raw tcpdbg2-max-rcvbuf) (cons 'formatted (number->string tcpdbg2-max-rcvbuf))))
        (cons 'tcpdbg2-bw-estimate (list (cons 'raw tcpdbg2-bw-estimate) (cons 'formatted (number->string tcpdbg2-bw-estimate))))
        (cons 'tcpdbg2-rtt (list (cons 'raw tcpdbg2-rtt) (cons 'formatted (number->string tcpdbg2-rtt))))
        (cons 'tcpdbg2-tcpos-pktcnt (list (cons 'raw tcpdbg2-tcpos-pktcnt) (cons 'formatted (number->string tcpdbg2-tcpos-pktcnt))))
        (cons 'tcpdbg2-ts-recent (list (cons 'raw tcpdbg2-ts-recent) (cons 'formatted (number->string tcpdbg2-ts-recent))))
        (cons 'tcpdbg2-tcp-cfgsndbuf (list (cons 'raw tcpdbg2-tcp-cfgsndbuf) (cons 'formatted (number->string tcpdbg2-tcp-cfgsndbuf))))
        (cons 'trcdbg-val15 (list (cons 'raw trcdbg-val15) (cons 'formatted (number->string trcdbg-val15))))
        (cons 'tcpcc-last-max-cwnd (list (cons 'raw tcpcc-last-max-cwnd) (cons 'formatted (number->string tcpcc-last-max-cwnd))))
        (cons 'tcpcc-loss-cwnd (list (cons 'raw tcpcc-loss-cwnd) (cons 'formatted (number->string tcpcc-loss-cwnd))))
        (cons 'tcpcc-last-time (list (cons 'raw tcpcc-last-time) (cons 'formatted (number->string tcpcc-last-time))))
        (cons 'tcpcc-last-cwnd (list (cons 'raw tcpcc-last-cwnd) (cons 'formatted (number->string tcpcc-last-cwnd))))
        (cons 'tcpcc-delay-min (list (cons 'raw tcpcc-delay-min) (cons 'formatted (number->string tcpcc-delay-min))))
        (cons 'tcpcc-ack-cnt (list (cons 'raw tcpcc-ack-cnt) (cons 'formatted (number->string tcpcc-ack-cnt))))
        (cons 'tcpcc-alpha (list (cons 'raw tcpcc-alpha) (cons 'formatted (number->string tcpcc-alpha))))
        (cons 'tcpcc-beta-val (list (cons 'raw tcpcc-beta-val) (cons 'formatted (number->string tcpcc-beta-val))))
        (cons 'tcpcc-rtt-low (list (cons 'raw tcpcc-rtt-low) (cons 'formatted (number->string tcpcc-rtt-low))))
        (cons 'tcpcc-rtt-above (list (cons 'raw tcpcc-rtt-above) (cons 'formatted (number->string tcpcc-rtt-above))))
        (cons 'tcpcc-max-rtt (list (cons 'raw tcpcc-max-rtt) (cons 'formatted (number->string tcpcc-max-rtt))))
        (cons 'tcpcc-base-rtt (list (cons 'raw tcpcc-base-rtt) (cons 'formatted (number->string tcpcc-base-rtt))))
        (cons 'tcpcc-rtt-min (list (cons 'raw tcpcc-rtt-min) (cons 'formatted (number->string tcpcc-rtt-min))))
        (cons 'tcpcc-last-ack (list (cons 'raw tcpcc-last-ack) (cons 'formatted (number->string tcpcc-last-ack))))
        (cons 'tcpcc-round-start (list (cons 'raw tcpcc-round-start) (cons 'formatted (number->string tcpcc-round-start))))
        (cons 'tcpcc-end-seq (list (cons 'raw tcpcc-end-seq) (cons 'formatted (number->string tcpcc-end-seq))))
        (cons 'tcpcc-curr-rtt (list (cons 'raw tcpcc-curr-rtt) (cons 'formatted (number->string tcpcc-curr-rtt))))
        (cons 'inforec-info (list (cons 'raw inforec-info) (cons 'formatted (utf8->string inforec-info))))
        (cons 'sslrec-seq (list (cons 'raw sslrec-seq) (cons 'formatted (fmt-hex sslrec-seq))))
        (cons 'mptcprec-subflowid (list (cons 'raw mptcprec-subflowid) (cons 'formatted (fmt-hex mptcprec-subflowid))))
        (cons 'vmnamerec-srcvmname (list (cons 'raw vmnamerec-srcvmname) (cons 'formatted (utf8->string vmnamerec-srcvmname))))
        (cons 'clu-snode (list (cons 'raw clu-snode) (cons 'formatted (number->string clu-snode))))
        (cons 'clu-dnode (list (cons 'raw clu-dnode) (cons 'formatted (number->string clu-dnode))))
        (cons 'clu-clflags (list (cons 'raw clu-clflags) (cons 'formatted (fmt-hex clu-clflags))))
        (cons 'clu-clflags-fp (list (cons 'raw clu-clflags-fp) (cons 'formatted (if (= clu-clflags-fp 0) "Not set" "Set"))))
        (cons 'clu-clflags-fr (list (cons 'raw clu-clflags-fr) (cons 'formatted (if (= clu-clflags-fr 0) "Not set" "Set"))))
        (cons 'clu-clflags-dfd (list (cons 'raw clu-clflags-dfd) (cons 'formatted (if (= clu-clflags-dfd 0) "Not set" "Set"))))
        (cons 'clu-clflags-rss (list (cons 'raw clu-clflags-rss) (cons 'formatted (if (= clu-clflags-rss 0) "Not set" "Set"))))
        (cons 'clu-clflags-rssh (list (cons 'raw clu-clflags-rssh) (cons 'formatted (if (= clu-clflags-rssh 0) "Not set" "Set"))))
        (cons 'clu-clflags-res (list (cons 'raw clu-clflags-res) (cons 'formatted (if (= clu-clflags-res 0) "Not set" "Set"))))
        )))

    (catch (e)
      (err (str "NSTRACE parse error: " e)))))

;; dissect-nstrace: parse NSTRACE from bytevector
;; Returns (ok fields-alist) or (err message)