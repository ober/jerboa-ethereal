;; packet-pvfs2.c
;; Routines for pvfs2 packet dissection
;; By Mike Frisch <mfrisch@platform.com>
;; Joint and Several Copyright 2005, Mike Frisch and Platform Computing Inc.
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; Dissector for Parallel Virtual File System (PVFS) version 2.
;; https://web.archive.org/web/20160701052501/http://www.pvfs.org/
;;
;; Copied from packet-smb.c and others
;;
;; TODO
;;
;; - Add filename snooping (match file handles with file names),
;; similar to how packet-rpc.c/packet-nfs.c implements it
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/pvfs2.ss
;; Auto-generated from wireshark/epan/dissectors/packet-pvfs2.c

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
(def (dissect-pvfs2 buffer)
  "Parallel Virtual File System"
  (try
    (let* (
           (magic-nr (unwrap (read-u32be buffer 0)))
           (flow-data (unwrap (slice buffer 8 1)))
           (attrmask (unwrap (read-u32be buffer 12)))
           (opaque-length (unwrap (read-u32be buffer 20)))
           (fill-bytes (unwrap (slice buffer 24 1)))
           (data (unwrap (slice buffer 24 1)))
           (fh-hash (unwrap (read-u32be buffer 24)))
           (fh-length (unwrap (read-u32be buffer 24)))
           (distribution (unwrap (slice buffer 36 1)))
           (dfile-count (unwrap (read-u32be buffer 44)))
           (uid (unwrap (read-u32be buffer 48)))
           (gid (unwrap (read-u32be buffer 52)))
           (permissions (unwrap (read-u32be buffer 56)))
           (target-path-len (unwrap (read-u32be buffer 64)))
           (unused (unwrap (read-u32be buffer 84)))
           (fs-id (unwrap (read-u32be buffer 92)))
           (num-eregs (unwrap (read-u32be buffer 108)))
           (num-blocks (unwrap (read-u32be buffer 112)))
           (stride (unwrap (read-u64be buffer 116)))
           (ub (unwrap (read-u64be buffer 124)))
           (lb (unwrap (read-u64be buffer 132)))
           (aggregate-size (unwrap (read-u64be buffer 140)))
           (num-contig-chunks (unwrap (read-u32be buffer 148)))
           (depth (unwrap (read-u32be buffer 152)))
           (num-nested-req (unwrap (read-u32be buffer 156)))
           (committed (unwrap (read-u32be buffer 160)))
           (refcount (unwrap (read-u32be buffer 164)))
           (ereg (unwrap (read-u32be buffer 172)))
           (sreg (unwrap (read-u32be buffer 176)))
           (server-nr (unwrap (read-u32be buffer 184)))
           (server-count (unwrap (read-u32be buffer 188)))
           (numreq (unwrap (read-u32be buffer 192)))
           (offset (unwrap (read-u64be buffer 200)))
           (size (unwrap (read-u64be buffer 236)))
           (truncate-request-flags (unwrap (read-u32be buffer 244)))
           (dirent-limit (unwrap (read-u32be buffer 260)))
           (flush-request-flags (unwrap (read-u32be buffer 264)))
           (next-id (unwrap (read-u32be buffer 268)))
           (mgmt-perf-mon-request-count (unwrap (read-u32be buffer 272)))
           (mgmt-perf-mon-request-event-count (unwrap (read-u32be buffer 280)))
           (context-id (unwrap (read-u32be buffer 312)))
           (lookup-path-response-handle-count (unwrap (read-u32be buffer 320)))
           (ds-position (unwrap (read-u32be buffer 332)))
           (directory-version (unwrap (read-u64be buffer 340)))
           (dirent-count (unwrap (read-u32be buffer 352)))
           (getconfig-response-total-bytes (unwrap (read-u32be buffer 356)))
           (getconfig-response-lines (unwrap (read-u32be buffer 360)))
           (getconfig-response-config-bytes (unwrap (read-u32be buffer 364)))
           (getconfig-response-entry (unwrap (slice buffer 368 1)))
           (prev-value (unwrap (read-u64be buffer 368)))
           (mgmt-perf-stat-valid-flag (unwrap (read-u32be buffer 380)))
           (mgmt-perf-stat-id (unwrap (read-u32be buffer 384)))
           (mgmt-perf-mon-response-suggested-next-id (unwrap (read-u32be buffer 388)))
           (mgmt-perf-mon-response-perf-array-count (unwrap (read-u32be buffer 400)))
           (mgmt-iterate-handles-response-ds-position (unwrap (read-u32be buffer 404)))
           (mgmt-iterate-handles-response-handle-count (unwrap (read-u32be buffer 408)))
           (mgmt-dspace-info-list-response-dspace-info-count (unwrap (read-u32be buffer 416)))
           (mgmt-event-mon-response-api (unwrap (read-u32be buffer 416)))
           (mgmt-event-mon-response-operation (unwrap (read-u32be buffer 420)))
           (mgmt-event-mon-response-value (unwrap (read-u32be buffer 424)))
           (mgmt-event-mon-response-flags (unwrap (read-u32be buffer 428)))
           (mgmt-event-mon-response-tv-sec (unwrap (read-u32be buffer 432)))
           (mgmt-event-mon-response-tv-usec (unwrap (read-u32be buffer 436)))
           )

      (ok (list
        (cons 'magic-nr (list (cons 'raw magic-nr) (cons 'formatted (fmt-hex magic-nr))))
        (cons 'flow-data (list (cons 'raw flow-data) (cons 'formatted (fmt-bytes flow-data))))
        (cons 'attrmask (list (cons 'raw attrmask) (cons 'formatted (number->string attrmask))))
        (cons 'opaque-length (list (cons 'raw opaque-length) (cons 'formatted (number->string opaque-length))))
        (cons 'fill-bytes (list (cons 'raw fill-bytes) (cons 'formatted (fmt-bytes fill-bytes))))
        (cons 'data (list (cons 'raw data) (cons 'formatted (fmt-bytes data))))
        (cons 'fh-hash (list (cons 'raw fh-hash) (cons 'formatted (fmt-hex fh-hash))))
        (cons 'fh-length (list (cons 'raw fh-length) (cons 'formatted (number->string fh-length))))
        (cons 'distribution (list (cons 'raw distribution) (cons 'formatted (utf8->string distribution))))
        (cons 'dfile-count (list (cons 'raw dfile-count) (cons 'formatted (number->string dfile-count))))
        (cons 'uid (list (cons 'raw uid) (cons 'formatted (number->string uid))))
        (cons 'gid (list (cons 'raw gid) (cons 'formatted (number->string gid))))
        (cons 'permissions (list (cons 'raw permissions) (cons 'formatted (fmt-oct permissions))))
        (cons 'target-path-len (list (cons 'raw target-path-len) (cons 'formatted (number->string target-path-len))))
        (cons 'unused (list (cons 'raw unused) (cons 'formatted (number->string unused))))
        (cons 'fs-id (list (cons 'raw fs-id) (cons 'formatted (fmt-hex fs-id))))
        (cons 'num-eregs (list (cons 'raw num-eregs) (cons 'formatted (number->string num-eregs))))
        (cons 'num-blocks (list (cons 'raw num-blocks) (cons 'formatted (number->string num-blocks))))
        (cons 'stride (list (cons 'raw stride) (cons 'formatted (number->string stride))))
        (cons 'ub (list (cons 'raw ub) (cons 'formatted (number->string ub))))
        (cons 'lb (list (cons 'raw lb) (cons 'formatted (number->string lb))))
        (cons 'aggregate-size (list (cons 'raw aggregate-size) (cons 'formatted (number->string aggregate-size))))
        (cons 'num-contig-chunks (list (cons 'raw num-contig-chunks) (cons 'formatted (number->string num-contig-chunks))))
        (cons 'depth (list (cons 'raw depth) (cons 'formatted (number->string depth))))
        (cons 'num-nested-req (list (cons 'raw num-nested-req) (cons 'formatted (number->string num-nested-req))))
        (cons 'committed (list (cons 'raw committed) (cons 'formatted (number->string committed))))
        (cons 'refcount (list (cons 'raw refcount) (cons 'formatted (number->string refcount))))
        (cons 'ereg (list (cons 'raw ereg) (cons 'formatted (number->string ereg))))
        (cons 'sreg (list (cons 'raw sreg) (cons 'formatted (number->string sreg))))
        (cons 'server-nr (list (cons 'raw server-nr) (cons 'formatted (number->string server-nr))))
        (cons 'server-count (list (cons 'raw server-count) (cons 'formatted (number->string server-count))))
        (cons 'numreq (list (cons 'raw numreq) (cons 'formatted (number->string numreq))))
        (cons 'offset (list (cons 'raw offset) (cons 'formatted (number->string offset))))
        (cons 'size (list (cons 'raw size) (cons 'formatted (number->string size))))
        (cons 'truncate-request-flags (list (cons 'raw truncate-request-flags) (cons 'formatted (number->string truncate-request-flags))))
        (cons 'dirent-limit (list (cons 'raw dirent-limit) (cons 'formatted (number->string dirent-limit))))
        (cons 'flush-request-flags (list (cons 'raw flush-request-flags) (cons 'formatted (number->string flush-request-flags))))
        (cons 'next-id (list (cons 'raw next-id) (cons 'formatted (number->string next-id))))
        (cons 'mgmt-perf-mon-request-count (list (cons 'raw mgmt-perf-mon-request-count) (cons 'formatted (number->string mgmt-perf-mon-request-count))))
        (cons 'mgmt-perf-mon-request-event-count (list (cons 'raw mgmt-perf-mon-request-event-count) (cons 'formatted (number->string mgmt-perf-mon-request-event-count))))
        (cons 'context-id (list (cons 'raw context-id) (cons 'formatted (number->string context-id))))
        (cons 'lookup-path-response-handle-count (list (cons 'raw lookup-path-response-handle-count) (cons 'formatted (number->string lookup-path-response-handle-count))))
        (cons 'ds-position (list (cons 'raw ds-position) (cons 'formatted (number->string ds-position))))
        (cons 'directory-version (list (cons 'raw directory-version) (cons 'formatted (fmt-hex directory-version))))
        (cons 'dirent-count (list (cons 'raw dirent-count) (cons 'formatted (number->string dirent-count))))
        (cons 'getconfig-response-total-bytes (list (cons 'raw getconfig-response-total-bytes) (cons 'formatted (number->string getconfig-response-total-bytes))))
        (cons 'getconfig-response-lines (list (cons 'raw getconfig-response-lines) (cons 'formatted (number->string getconfig-response-lines))))
        (cons 'getconfig-response-config-bytes (list (cons 'raw getconfig-response-config-bytes) (cons 'formatted (number->string getconfig-response-config-bytes))))
        (cons 'getconfig-response-entry (list (cons 'raw getconfig-response-entry) (cons 'formatted (utf8->string getconfig-response-entry))))
        (cons 'prev-value (list (cons 'raw prev-value) (cons 'formatted (number->string prev-value))))
        (cons 'mgmt-perf-stat-valid-flag (list (cons 'raw mgmt-perf-stat-valid-flag) (cons 'formatted (number->string mgmt-perf-stat-valid-flag))))
        (cons 'mgmt-perf-stat-id (list (cons 'raw mgmt-perf-stat-id) (cons 'formatted (number->string mgmt-perf-stat-id))))
        (cons 'mgmt-perf-mon-response-suggested-next-id (list (cons 'raw mgmt-perf-mon-response-suggested-next-id) (cons 'formatted (number->string mgmt-perf-mon-response-suggested-next-id))))
        (cons 'mgmt-perf-mon-response-perf-array-count (list (cons 'raw mgmt-perf-mon-response-perf-array-count) (cons 'formatted (number->string mgmt-perf-mon-response-perf-array-count))))
        (cons 'mgmt-iterate-handles-response-ds-position (list (cons 'raw mgmt-iterate-handles-response-ds-position) (cons 'formatted (number->string mgmt-iterate-handles-response-ds-position))))
        (cons 'mgmt-iterate-handles-response-handle-count (list (cons 'raw mgmt-iterate-handles-response-handle-count) (cons 'formatted (number->string mgmt-iterate-handles-response-handle-count))))
        (cons 'mgmt-dspace-info-list-response-dspace-info-count (list (cons 'raw mgmt-dspace-info-list-response-dspace-info-count) (cons 'formatted (number->string mgmt-dspace-info-list-response-dspace-info-count))))
        (cons 'mgmt-event-mon-response-api (list (cons 'raw mgmt-event-mon-response-api) (cons 'formatted (number->string mgmt-event-mon-response-api))))
        (cons 'mgmt-event-mon-response-operation (list (cons 'raw mgmt-event-mon-response-operation) (cons 'formatted (number->string mgmt-event-mon-response-operation))))
        (cons 'mgmt-event-mon-response-value (list (cons 'raw mgmt-event-mon-response-value) (cons 'formatted (number->string mgmt-event-mon-response-value))))
        (cons 'mgmt-event-mon-response-flags (list (cons 'raw mgmt-event-mon-response-flags) (cons 'formatted (number->string mgmt-event-mon-response-flags))))
        (cons 'mgmt-event-mon-response-tv-sec (list (cons 'raw mgmt-event-mon-response-tv-sec) (cons 'formatted (number->string mgmt-event-mon-response-tv-sec))))
        (cons 'mgmt-event-mon-response-tv-usec (list (cons 'raw mgmt-event-mon-response-tv-usec) (cons 'formatted (number->string mgmt-event-mon-response-tv-usec))))
        )))

    (catch (e)
      (err (str "PVFS2 parse error: " e)))))

;; dissect-pvfs2: parse PVFS2 from bytevector
;; Returns (ok fields-alist) or (err message)