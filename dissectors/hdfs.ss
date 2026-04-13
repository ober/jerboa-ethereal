;; packet-hdfs.c
;; HDFS Protocol and dissectors
;;
;; Copyright (c) 2011 by Isilon Systems.
;;
;; Author: Allison Obourn <aobourn@isilon.com>
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1999 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/hdfs.ss
;; Auto-generated from wireshark/epan/dissectors/packet-hdfs.c

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
(def (dissect-hdfs buffer)
  "HDFS Protocol"
  (try
    (let* (
           (paramvalnum (unwrap (read-u64be buffer 2)))
           (success (unwrap (read-u32be buffer 4)))
           (strcall (unwrap (slice buffer 8 1)))
           (params (unwrap (read-u32be buffer 8)))
           (namelentwo (unwrap (read-u16be buffer 10)))
           (objname (unwrap (slice buffer 12 1)))
           (paramtype (unwrap (slice buffer 14 1)))
           (prover (unwrap (read-u64be buffer 14)))
           (paramval (unwrap (slice buffer 14 1)))
           (sequenceno (unwrap (slice buffer 14 1)))
           (pdu-type (unwrap (read-u8 buffer 14)))
           (flags (unwrap (read-u8 buffer 15)))
           (authlen (unwrap (slice buffer 16 4)))
           (auth (unwrap (slice buffer 20 1)))
           (len (unwrap (read-u32be buffer 20)))
           (packetno (unwrap (read-u32be buffer 24)))
           (filename (unwrap (slice buffer 26 1)))
           (endblockloc (unwrap (read-u64be buffer 26)))
           (isdir (unwrap (read-u8 buffer 34)))
           (blockrep (unwrap (read-u16be buffer 35)))
           (modtime (unwrap (read-u64be buffer 45)))
           (accesstime (unwrap (read-u64be buffer 53)))
           (fileperm (unwrap (read-u16be buffer 61)))
           (ownername (unwrap (slice buffer 64 1)))
           (groupname (unwrap (slice buffer 65 1)))
           (identifier (unwrap (slice buffer 66 1)))
           (password (unwrap (slice buffer 67 1)))
           (kind (unwrap (slice buffer 68 1)))
           (service (unwrap (slice buffer 69 1)))
           (corrupt (unwrap (read-u8 buffer 69)))
           (offset (unwrap (read-u64be buffer 70)))
           (blockloc (unwrap (read-u64be buffer 78)))
           (blocksize (unwrap (read-u64be buffer 86)))
           (blockgen (unwrap (read-u64be buffer 94)))
           (locations (unwrap (read-u32be buffer 102)))
           (datanodeid (unwrap (slice buffer 108 1)))
           (storageid (unwrap (slice buffer 110 1)))
           (infoport (unwrap (read-u16be buffer 110)))
           (ipcport (unwrap (read-u16be buffer 112)))
           (capacity (unwrap (read-u64be buffer 114)))
           (dfsused (unwrap (read-u64be buffer 122)))
           (remaining (unwrap (read-u64be buffer 130)))
           (lastupdate (unwrap (read-u64be buffer 138)))
           (activecon (unwrap (read-u32be buffer 146)))
           (rackloc (unwrap (slice buffer 151 1)))
           (hostname (unwrap (slice buffer 152 1)))
           (namelenone (unwrap (read-u8 buffer 152)))
           (adminstate (unwrap (slice buffer 153 1)))
           (filelen (unwrap (read-u64be buffer 153)))
           (construct (unwrap (read-u8 buffer 161)))
           (blockcount (unwrap (read-u32be buffer 162)))
           )

      (ok (list
        (cons 'paramvalnum (list (cons 'raw paramvalnum) (cons 'formatted (number->string paramvalnum))))
        (cons 'success (list (cons 'raw success) (cons 'formatted (number->string success))))
        (cons 'strcall (list (cons 'raw strcall) (cons 'formatted (utf8->string strcall))))
        (cons 'params (list (cons 'raw params) (cons 'formatted (number->string params))))
        (cons 'namelentwo (list (cons 'raw namelentwo) (cons 'formatted (number->string namelentwo))))
        (cons 'objname (list (cons 'raw objname) (cons 'formatted (utf8->string objname))))
        (cons 'paramtype (list (cons 'raw paramtype) (cons 'formatted (utf8->string paramtype))))
        (cons 'prover (list (cons 'raw prover) (cons 'formatted (number->string prover))))
        (cons 'paramval (list (cons 'raw paramval) (cons 'formatted (utf8->string paramval))))
        (cons 'sequenceno (list (cons 'raw sequenceno) (cons 'formatted (utf8->string sequenceno))))
        (cons 'pdu-type (list (cons 'raw pdu-type) (cons 'formatted (number->string pdu-type))))
        (cons 'flags (list (cons 'raw flags) (cons 'formatted (number->string flags))))
        (cons 'authlen (list (cons 'raw authlen) (cons 'formatted (utf8->string authlen))))
        (cons 'auth (list (cons 'raw auth) (cons 'formatted (utf8->string auth))))
        (cons 'len (list (cons 'raw len) (cons 'formatted (number->string len))))
        (cons 'packetno (list (cons 'raw packetno) (cons 'formatted (number->string packetno))))
        (cons 'filename (list (cons 'raw filename) (cons 'formatted (utf8->string filename))))
        (cons 'endblockloc (list (cons 'raw endblockloc) (cons 'formatted (number->string endblockloc))))
        (cons 'isdir (list (cons 'raw isdir) (cons 'formatted (number->string isdir))))
        (cons 'blockrep (list (cons 'raw blockrep) (cons 'formatted (number->string blockrep))))
        (cons 'modtime (list (cons 'raw modtime) (cons 'formatted (number->string modtime))))
        (cons 'accesstime (list (cons 'raw accesstime) (cons 'formatted (number->string accesstime))))
        (cons 'fileperm (list (cons 'raw fileperm) (cons 'formatted (number->string fileperm))))
        (cons 'ownername (list (cons 'raw ownername) (cons 'formatted (utf8->string ownername))))
        (cons 'groupname (list (cons 'raw groupname) (cons 'formatted (utf8->string groupname))))
        (cons 'identifier (list (cons 'raw identifier) (cons 'formatted (utf8->string identifier))))
        (cons 'password (list (cons 'raw password) (cons 'formatted (utf8->string password))))
        (cons 'kind (list (cons 'raw kind) (cons 'formatted (utf8->string kind))))
        (cons 'service (list (cons 'raw service) (cons 'formatted (utf8->string service))))
        (cons 'corrupt (list (cons 'raw corrupt) (cons 'formatted (number->string corrupt))))
        (cons 'offset (list (cons 'raw offset) (cons 'formatted (number->string offset))))
        (cons 'blockloc (list (cons 'raw blockloc) (cons 'formatted (number->string blockloc))))
        (cons 'blocksize (list (cons 'raw blocksize) (cons 'formatted (number->string blocksize))))
        (cons 'blockgen (list (cons 'raw blockgen) (cons 'formatted (number->string blockgen))))
        (cons 'locations (list (cons 'raw locations) (cons 'formatted (number->string locations))))
        (cons 'datanodeid (list (cons 'raw datanodeid) (cons 'formatted (utf8->string datanodeid))))
        (cons 'storageid (list (cons 'raw storageid) (cons 'formatted (utf8->string storageid))))
        (cons 'infoport (list (cons 'raw infoport) (cons 'formatted (number->string infoport))))
        (cons 'ipcport (list (cons 'raw ipcport) (cons 'formatted (number->string ipcport))))
        (cons 'capacity (list (cons 'raw capacity) (cons 'formatted (number->string capacity))))
        (cons 'dfsused (list (cons 'raw dfsused) (cons 'formatted (number->string dfsused))))
        (cons 'remaining (list (cons 'raw remaining) (cons 'formatted (number->string remaining))))
        (cons 'lastupdate (list (cons 'raw lastupdate) (cons 'formatted (number->string lastupdate))))
        (cons 'activecon (list (cons 'raw activecon) (cons 'formatted (number->string activecon))))
        (cons 'rackloc (list (cons 'raw rackloc) (cons 'formatted (utf8->string rackloc))))
        (cons 'hostname (list (cons 'raw hostname) (cons 'formatted (utf8->string hostname))))
        (cons 'namelenone (list (cons 'raw namelenone) (cons 'formatted (number->string namelenone))))
        (cons 'adminstate (list (cons 'raw adminstate) (cons 'formatted (utf8->string adminstate))))
        (cons 'filelen (list (cons 'raw filelen) (cons 'formatted (number->string filelen))))
        (cons 'construct (list (cons 'raw construct) (cons 'formatted (number->string construct))))
        (cons 'blockcount (list (cons 'raw blockcount) (cons 'formatted (number->string blockcount))))
        )))

    (catch (e)
      (err (str "HDFS parse error: " e)))))

;; dissect-hdfs: parse HDFS from bytevector
;; Returns (ok fields-alist) or (err message)