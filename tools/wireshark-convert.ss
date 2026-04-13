;; jerboa-ethereal/tools/wireshark-convert.ss
;; Comprehensive Wireshark C dissector → Jerboa .ss converter
;; Designed for 100% coverage of the 1,688 Wireshark packet-*.c files
;;
;; Handles: all proto_tree_add_item variants, proto_tree_add_bitmask,
;;          TFS() boolean formatters, val64_string, RVALS, FT_UINT24/48/56,
;;          create_dissector_handle function lookup, loop body extraction.
;;
;; Usage:
;;   ;; Single file:
;;   scheme --libdirs .:../jerboa/lib --script tools/wireshark-convert.ss \
;;     ~/mine/wireshark/epan/dissectors/packet-icmp.c --out dissectors/
;;
;;   ;; Entire wireshark dissectors directory:
;;   scheme --libdirs .:../jerboa/lib --script tools/wireshark-convert.ss \
;;     ~/mine/wireshark/epan/dissectors/ --out dissectors/

;; Load native regex library before importing prelude
(let ((native (string-append (or (getenv "JERBOA_HOME")
                                 (string-append (getenv "HOME") "/mine/jerboa"))
                             "/jerboa-native-rs/target/release/libjerboa_native.so")))
  (when (file-exists? native)
    (load-shared-object native)))

(import (jerboa prelude))

;; ── Configuration ────────────────────────────────────────────────────────────

;; Suffixes to try when searching for the primary dissect function by name
(def dissect-fn-suffixes
  '("" "_pdu" "_msg" "_packet" "_common" "_tcp" "_udp" "_body"
    "_data" "_frame" "_request" "_response" "_item" "_info"
    "_header" "_payload" "_record" "_heur"))

;; ── Type Tables ──────────────────────────────────────────────────────────────

(def ft->reader
  (list->hash-table
    '(("FT_UINT8"      . "read-u8")
      ("FT_INT8"       . "read-u8")
      ("FT_UINT16"     . "read-u16be")
      ("FT_INT16"      . "read-u16be")
      ("FT_UINT24"     . "read-u24be")
      ("FT_UINT32"     . "read-u32be")
      ("FT_INT32"      . "read-u32be")
      ("FT_UINT40"     . "read-bytes")
      ("FT_UINT48"     . "read-bytes")
      ("FT_UINT56"     . "read-bytes")
      ("FT_UINT64"     . "read-u64be")
      ("FT_INT64"      . "read-u64be")
      ("FT_FLOAT"      . "read-u32be")
      ("FT_DOUBLE"     . "read-u64be")
      ("FT_IPv4"       . "read-u32be")
      ("FT_IPv6"       . "read-bytes")
      ("FT_ETHER"      . "read-bytes")
      ("FT_BYTES"      . "read-bytes")
      ("FT_UINT_BYTES" . "read-bytes")
      ("FT_STRING"     . "read-bytes")
      ("FT_STRINGZ"    . "read-bytes")
      ("FT_STRINGZPAD" . "read-bytes")
      ("FT_BOOLEAN"    . "read-u8")   ;; size overridden by bitmask parent width
      ("FT_GUID"       . "read-bytes")
      ("FT_OID"        . "read-bytes")
      ("FT_REL_OID"    . "read-bytes")
      ("FT_FRAMENUM"   . "read-u32be")
      ("FT_PROTOCOL"   . "read-bytes"))))

(def ft->size
  (list->hash-table
    '(("FT_UINT8"    . 1)
      ("FT_INT8"     . 1)
      ("FT_BOOLEAN"  . 1)
      ("FT_UINT16"   . 2)
      ("FT_INT16"    . 2)
      ("FT_UINT24"   . 3)
      ("FT_UINT32"   . 4)
      ("FT_INT32"    . 4)
      ("FT_FLOAT"    . 4)
      ("FT_IPv4"     . 4)
      ("FT_UINT40"   . 5)
      ("FT_UINT48"   . 6)
      ("FT_ETHER"    . 6)
      ("FT_UINT56"   . 7)
      ("FT_UINT64"   . 8)
      ("FT_INT64"    . 8)
      ("FT_DOUBLE"   . 8)
      ("FT_IPv6"     . 16)
      ("FT_GUID"     . 16)
      ("FT_FRAMENUM" . 4))))

(def ft-le-override
  (list->hash-table
    '(("FT_UINT16"  . "read-u16le")
      ("FT_INT16"   . "read-u16le")
      ("FT_UINT32"  . "read-u32le")
      ("FT_INT32"   . "read-u32le")
      ("FT_FLOAT"   . "read-u32le")
      ("FT_UINT64"  . "read-u64le")
      ("FT_INT64"   . "read-u64le")
      ("FT_DOUBLE"  . "read-u64le"))))

(def ft-special-formatter
  (list->hash-table
    '(("FT_IPv4"  . "fmt-ipv4")
      ("FT_IPv6"  . "fmt-ipv6-address")
      ("FT_ETHER" . "fmt-mac")
      ("FT_GUID"  . "fmt-bytes"))))

(def base->formatter
  (list->hash-table
    '(("BASE_HEX"      . "fmt-hex")
      ("BASE_HEX_DEC"  . "fmt-hex")
      ("BASE_DEC"      . "number->string")
      ("BASE_DEC_HEX"  . "number->string")
      ("BASE_OCT"      . "fmt-oct")
      ("BASE_PT_TCP"   . "fmt-port")
      ("BASE_PT_UDP"   . "fmt-port")
      ("BASE_PT_SCTP"  . "fmt-port")
      ("BASE_PT_DCCP"  . "fmt-port")
      ("BASE_NONE"     . "number->string")
      ("BASE_CUSTOM"   . "number->string")
      ("0"             . "number->string"))))

;; ── String Utilities ─────────────────────────────────────────────────────────

(def (c-ident->kebab s)
  "hf_icmp_seq_num → seq-num  (strips leading hf_PROTO_ prefix)"
  (let* ((no-hf  (re-replace "^hf_[a-zA-Z0-9]+_" s ""))
         (kebab  (re-replace-all "_" no-hf "-")))
    (if (string=? no-hf s)
        ;; no prefix stripped — just convert underscores
        kebab
        kebab)))

(def (proto-from-filename path)
  "~/wireshark/.../packet-icmp.c → icmp"
  (let* ((base   (path-last path))
         (no-ext (re-replace "\\.c$" base ""))
         (proto  (re-replace "^packet-" no-ext "")))
    (re-replace-all "-" proto "_")))  ;; keep underscores for C lookups

(def (proto-kebab path)
  "~/wireshark/.../packet-icmp.c → icmp"
  (re-replace-all "_" (proto-from-filename path) "-"))

(def (path-last path)
  (let ((parts (string-split path #\/)))
    (if (null? parts) path (last parts))))

(def (last lst)
  (cond ((null? lst) (error 'last "empty list"))
        ((null? (cdr lst)) (car lst))
        (else (last (cdr lst)))))

(def (parse-c-number s)
  "Parse C hex (0x...) or decimal number string to integer."
  (cond
    ((not s) 0)
    ((string=? s "") 0)
    ((string-prefix? "0x" s)
     (or (string->number (substring s 2 (string-length s)) 16) 0))
    ((string-prefix? "0X" s)
     (or (string->number (substring s 2 (string-length s)) 16) 0))
    (else (or (string->number s 10) 0))))

(def (lowest-bit-pos mask)
  "Return index of lowest set bit (0-based)."
  (if (= mask 0) 0
      (let loop ((m mask) (pos 0))
        (if (odd? m)
            pos
            (loop (bitwise-arithmetic-shift-right m 1) (+ pos 1))))))

;; ── Protocol Helpers (emitted into every generated dissector) ────────────────

(def protocol-helpers
  ";; ── Protocol Helpers ─────────────────────────────────────────────────
(def (read-u8 buf offset)
  (if (>= offset (bytevector-length buf))
      (err \"Buffer overrun\")
      (ok (bytevector-u8-ref buf offset))))

(def (read-u16be buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err \"Buffer overrun\")
      (ok (bytevector-u16-ref buf offset (endianness big)))))

(def (read-u24be buf offset)
  (if (> (+ offset 3) (bytevector-length buf))
      (err \"Buffer overrun\")
      (ok (+ (* (bytevector-u8-ref buf offset) 65536)
             (* (bytevector-u8-ref buf (+ offset 1)) 256)
             (bytevector-u8-ref buf (+ offset 2))))))

(def (read-u32be buf offset)
  (if (> (+ offset 4) (bytevector-length buf))
      (err \"Buffer overrun\")
      (ok (bytevector-u32-ref buf offset (endianness big)))))

(def (read-u16le buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err \"Buffer overrun\")
      (ok (bytevector-u16-ref buf offset (endianness little)))))

(def (read-u32le buf offset)
  (if (> (+ offset 4) (bytevector-length buf))
      (err \"Buffer overrun\")
      (ok (bytevector-u32-ref buf offset (endianness little)))))

(def (read-u64be buf offset)
  (if (> (+ offset 8) (bytevector-length buf))
      (err \"Buffer overrun\")
      (ok (bytevector-u64-ref buf offset (endianness big)))))

(def (read-u64le buf offset)
  (if (> (+ offset 8) (bytevector-length buf))
      (err \"Buffer overrun\")
      (ok (bytevector-u64-ref buf offset (endianness little)))))

(def (slice buf offset len)
  (if (> (+ offset len) (bytevector-length buf))
      (err \"Buffer overrun\")
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
    (str b0 \".\" b1 \".\" b2 \".\" b3)))

(def (fmt-mac bytes)
  (string-join
    (map (lambda (b) (string-pad (number->string b 16) 2 #\\0))
         (bytevector->list bytes))
    \":\"))

(def (fmt-hex val)
  (str \"0x\" (number->string val 16)))

(def (fmt-oct val)
  (str \"0\" (number->string val 8)))

(def (fmt-port port)
  (number->string port))

(def (fmt-bytes bv)
  (string-join
    (map (lambda (b) (string-pad (number->string b 16) 2 #\\0))
         (bytevector->list bv))
    \" \"))

(def (fmt-ipv6-address bytes)
  (let loop ((i 0) (parts '()))
    (if (>= i 16)
        (string-join (reverse parts) \":\")
        (loop (+ i 2)
              (cons (let ((w (+ (* (bytevector-u8-ref bytes i) 256)
                                (bytevector-u8-ref bytes (+ i 1)))))
                      (number->string w 16))
                    parts)))))
")

;; ── Data Structures ──────────────────────────────────────────────────────────

;; hf-field: one entry from hf_register_info[]
;; vals-kind: 'vals | 'tfs | 'vals64 | 'rvals | #f
(defstruct hf-field
  (var-name display-name filter-name ft-type base
   vals-name vals-kind bitmask-str
   short-name reader size))

(def (make-hf-field* var display filter ft base vals-name vals-kind mask-str)
  (let* ((short  (c-ident->kebab var))
         (reader (hash-get ft->reader ft))
         (size   (hash-get ft->size ft)))
    (make-hf-field var display filter ft base vals-name vals-kind mask-str short reader size)))

;; val-table: parsed value_string / val64_string table
(defstruct val-table (name entries))  ;; entries: list of (num . label)

;; bitmask-arr: parsed `static int * const NAME[] = { &hf_X, ... }`
(defstruct bitmask-arr (name hf-vars))

;; dissect-field: one field from the dissect function body
;; kind: 'literal | 'tracked | 'bitmask-parent | 'bitmask-bit
(defstruct dissect-field (hf-var offset size encoding kind parent-name))

;; ── Parser: hf_register_info ─────────────────────────────────────────────────

(def (parse-hf-register-info src)
  "Extract all hf_register_info entries. Returns list of hf-field structs."
  ;; Matches: { &hf_VAR, { "Display", "filter", FT_TYPE, BASE/WIDTH, VALS/TFS/NULL, MASK, ..., HFILL } }
  (let* ((pat (re (str
                   ;; outer open + var
                   "\\{\\s*&(hf_\\w+)\\s*,\\s*\\{"
                   ;; display name (1st string)
                   "[^\"]*\"([^\"]+)\"\\s*,"
                   ;; filter name (2nd string)
                   "\\s*\"([^\"]+)\"\\s*,"
                   ;; FT type
                   "\\s*(FT_\\w+)\\s*,"
                   ;; base or bit-width
                   "\\s*(BASE_\\w+|\\d+)\\s*,"
                   ;; VALS/TFS/RVALS/NULL/0
                   "\\s*(VALS64?\\((\\w+)\\)|TFS\\(&?(\\w+)\\)|RVALS\\((\\w+)\\)|NULL|0)"
                   ;; bitmask (may be symbolic like TH_FIN or hex/decimal)
                   "[^,]*,\\s*([x0-9A-Fa-f]+|0[xX][0-9A-Fa-f]+|\\w+)"
                   ;; rest up to HFILL
                   "[^}]*HFILL"))))
    (re-fold pat
      (lambda (i m str acc)
        (let* ((gs        (re-match-groups m))
               (var       (list-ref gs 0))
               (display   (list-ref gs 1))
               (filter    (list-ref gs 2))
               (ft        (list-ref gs 3))
               (base      (list-ref gs 4))
               ;; group 5 = full VALS/TFS match, 6 = VALS name, 7 = TFS name, 8 = RVALS name
               (vals-full (list-ref gs 5))
               (vals-name (let ((v (list-ref gs 6)) (t (list-ref gs 7)) (r (list-ref gs 8)))
                            (cond ((and v (not (string=? v ""))) v)
                                  ((and t (not (string=? t ""))) t)
                                  ((and r (not (string=? r ""))) r)
                                  (else #f))))
               (vals-kind (cond
                            ((string-prefix? "TFS" vals-full) 'tfs)
                            ((string-prefix? "VALS64" vals-full) 'vals64)
                            ((string-prefix? "RVALS" vals-full) 'rvals)
                            ((string-prefix? "VALS" vals-full) 'vals)
                            (else #f)))
               (mask-str  (list-ref gs 9)))
          (cons (make-hf-field* var display filter ft base vals-name vals-kind mask-str)
                acc)))
      '()
      src)))

;; ── Parser: value_string / val64_string tables ───────────────────────────────

(def (parse-value-tables src)
  "Extract value_string and val64_string arrays. Returns hash: name → val-table."
  (let* ((tbl-pat  (re "(?:static\\s+)?const\\s+val(?:64)?_string\\s+(\\w+)\\s*\\[\\]\\s*=\\s*\\{([^;]+)\\}\\s*;"))
         (ent-pat  (re "\\{\\s*(-?\\d+)\\s*,\\s*\"([^\"]+)\"\\s*\\}"))
         (result   (make-hash-table)))
    (re-fold tbl-pat
      (lambda (i m str acc)
        (let* ((gs      (re-match-groups m))
               (name    (list-ref gs 0))
               (block   (list-ref gs 1))
               (entries (re-fold ent-pat
                          (lambda (j em estr eacc)
                            (let ((eg (re-match-groups em)))
                              (cons (cons (string->number (list-ref eg 0))
                                          (list-ref eg 1))
                                    eacc)))
                          '()
                          block)))
          (when (not (null? entries))
            (hash-put! result name (make-val-table name (reverse entries)))))
        acc)
      #f
      src)
    result))

;; ── Parser: TFS true_false_string definitions ─────────────────────────────────

(def (parse-tfs-defs src)
  "Extract true_false_string definitions. Returns hash: name → (true-str . false-str)."
  (let* ((pat    (re "(?:static\\s+)?const\\s+true_false_string\\s+(\\w+)\\s*=\\s*\\{\\s*\"([^\"]+)\"\\s*,\\s*\"([^\"]+)\"\\s*\\}"))
         (result (make-hash-table)))
    (re-fold pat
      (lambda (i m str acc)
        (let* ((gs (re-match-groups m)))
          (hash-put! result (list-ref gs 0)
                     (cons (list-ref gs 1) (list-ref gs 2))))
        acc)
      #f
      src)
    result))

;; ── Parser: bitmask field arrays ──────────────────────────────────────────────

(def (parse-bitmask-arrays src)
  "Extract static int * const NAME[] = { &hf_X, ... } arrays.
   Returns hash: array-name → bitmask-arr."
  (let* ((arr-pat (re "static\\s+int\\s*\\*\\s*const\\s+(\\w+)\\s*\\[\\]\\s*=\\s*\\{([^}]+)\\}"))
         (ref-pat (re "&(hf_\\w+)"))
         (result  (make-hash-table)))
    (re-fold arr-pat
      (lambda (i m str acc)
        (let* ((gs    (re-match-groups m))
               (name  (list-ref gs 0))
               (block (list-ref gs 1))
               (vars  (re-fold ref-pat
                        (lambda (j em estr eacc)
                          (cons (car (re-match-groups em)) eacc))
                        '()
                        block)))
          (when (not (null? vars))
            (hash-put! result name (make-bitmask-arr name (reverse vars)))))
        acc)
      #f
      src)
    result))

;; ── Parser: find primary dissect function ────────────────────────────────────

(def (extract-brace-body src pos)
  "Extract balanced { } body starting at the opening brace at pos."
  (let loop ((i pos) (depth 0) (acc '()))
    (if (>= i (string-length src))
        (list->string (reverse acc))
        (let ((ch (string-ref src i)))
          (cond
            ((char=? ch #\{) (loop (+ i 1) (+ depth 1) (cons ch acc)))
            ((char=? ch #\})
             (if (= depth 1)
                 (list->string (reverse acc))
                 (loop (+ i 1) (- depth 1) (cons ch acc))))
            (else (loop (+ i 1) depth (cons ch acc))))))))

(def (count-add-items body)
  "Count proto_tree_add_item calls in a function body (proxy for complexity)."
  (length (re-find-all "proto_tree_add_item" body)))

(def (find-dissect-fn src proto)
  "Find the best dissect function body for proto (underscore form).
   Returns (values fn-name body) or (values #f \"\").
   Strategy: 1) create_dissector_handle lookup
             2) try name suffixes
             3) any dissect_PROTO_* function
             4) pick function with most add_item calls"
  ;; Strategy 1: find the registered function via create_dissector_handle
  (let* ((handle-pat (re "create_dissector_handle\\s*\\((\\w+)\\s*,"))
         (registered (let ((m (re-search handle-pat src)))
                       (and m (car (re-match-groups m)))))
         (fn-start-pat (lambda (name)
                         (re (str "(?:static\\s+)?(?:int|void|bool|gboolean|gint|guint)\\s+"
                                  name
                                  "\\s*\\([^)]*\\)\\s*\\{"))))
         (try-fn-name  (lambda (name)
                         (let ((m (re-search (fn-start-pat name) src)))
                           (and m (values name (extract-brace-body src (- (re-match-end m) 1)))))))
         (try-names    (append
                         (if registered (list registered) '())
                         (map (lambda (suffix) (str "dissect_" proto suffix))
                              dissect-fn-suffixes))))
    ;; Try each candidate name
    (let loop ((names try-names))
      (if (null? names)
          ;; Strategy 3+4: find any dissect_PROTO_* and pick best
          (let* ((any-pat (re (str "(?:static\\s+)?(?:int|void|bool|gboolean|gint|guint)\\s+"
                                   "(dissect_" proto "\\w*)"
                                   "\\s*\\([^)]*\\)\\s*\\{")))
                 (candidates (re-fold any-pat
                               (lambda (i m str acc)
                                 (let* ((name  (car (re-match-groups m)))
                                        (start (- (re-match-end m) 1))
                                        (body  (extract-brace-body src start)))
                                   (cons (cons name body) acc)))
                               '()
                               src)))
            (if (null? candidates)
                (values #f "")
                ;; Pick the one with the most add_item calls
                (let* ((best (fold-left
                               (lambda (best cand)
                                 (if (> (count-add-items (cdr cand))
                                        (count-add-items (cdr best)))
                                     cand best))
                               (car candidates)
                               (cdr candidates))))
                  (values (car best) (cdr best)))))
          (let ((name (car names)))
            (let ((m (re-search (fn-start-pat name) src)))
              (if m
                  (let* ((body (extract-brace-body src (- (re-match-end m) 1))))
                    (if (> (count-add-items body) 0)
                        (values name body)
                        (loop (cdr names))))  ;; dispatch-only fn, try next
                  (loop (cdr names)))))))))

;; ── Parser: dissect function body → dissect-field list ───────────────────────

(def (parse-body src proto bitmask-arrays)
  "Extract all field reads from a dissect function body.
   Returns sorted list of dissect-field structs."

  ;; ── Pattern 1: proto_tree_add_item* with LITERAL offset ──
  (let* ((lit-pat  (re (str
                        "proto_tree_add_item(?:_ret_\\w+)?\\s*\\([^,]+,\\s*"
                        "(hf_\\w+)\\s*,\\s*tvb\\s*,"
                        "\\s*(\\d+)\\s*,\\s*(-?\\d+|\\w+)\\s*,"
                        "\\s*(ENC_\\w+|ENC_NA|0)\\s*[,)]")))
         ;; ── Pattern 2: proto_tree_add_item* with OFFSET VARIABLE ──
         (var-pat  (re (str
                        "proto_tree_add_item(?:_ret_\\w+)?\\s*\\([^,]+,\\s*"
                        "(hf_\\w+)\\s*,\\s*tvb\\s*,"
                        "\\s*offset(?:\\s*[+\\-]\\s*\\w+)?\\s*,\\s*(-?\\d+|\\w+)\\s*,"
                        "\\s*(ENC_\\w+|ENC_NA|0)\\s*[,)]")))
         ;; ── Pattern 3: proto_tree_add_bitmask* with LITERAL offset ──
         (bm-lit-pat (re (str
                          "proto_tree_add_bitmask(?:_with_flags)?\\s*\\([^,]+,\\s*tvb\\s*,"
                          "\\s*(\\d+)\\s*,\\s*(hf_\\w+)\\s*,"
                          "\\s*\\w+\\s*,\\s*(\\w+)\\s*,\\s*(ENC_\\w+|0)\\s*[,)]")))
         ;; ── Pattern 4: proto_tree_add_bitmask* with OFFSET VARIABLE ──
         (bm-var-pat (re (str
                          "proto_tree_add_bitmask(?:_with_flags)?\\s*\\([^,]+,\\s*tvb\\s*,"
                          "\\s*offset(?:\\s*[+\\-]\\s*\\w+)?\\s*,\\s*(hf_\\w+)\\s*,"
                          "\\s*\\w+\\s*,\\s*(\\w+)\\s*,\\s*(ENC_\\w+|0)\\s*[,)]")))
         ;; ── Pattern 5: offset tracking ──
         ;; Combined: offset = N  |  offset += N  |  proto_tree_add_item(... offset ...)
         (track-pat (re (str
                         "(?:"
                         "(?:int\\s+)?offset\\s*=\\s*(\\d+)"     ;; g0: offset = N
                         "|offset\\s*\\+=\\s*(\\d+)"              ;; g1: offset += N
                         "|proto_tree_add_item(?:_ret_\\w+)?\\s*\\([^,]+,\\s*(hf_\\w+)\\s*,\\s*tvb\\s*,\\s*offset(?:\\s*[+\\-]\\s*\\w+)?\\s*,\\s*(-?\\d+|\\w+)\\s*,\\s*(ENC_\\w+|ENC_NA|0)\\s*[,)]" ;; g2,g3,g4
                         "|proto_tree_add_bitmask(?:_with_flags)?\\s*\\([^,]+,\\s*tvb\\s*,\\s*offset(?:\\s*[+\\-]\\s*\\w+)?\\s*,\\s*(hf_\\w+)\\s*,\\s*\\w+\\s*,\\s*(\\w+)\\s*,\\s*(ENC_\\w+|0)\\s*[,)]" ;; g5,g6,g7
                         ")")))
         ;; Seen hash to dedup by (hf-var . offset)
         (seen    (make-hash-table))
         (results '()))

    ;; Collect literal-offset fields
    (set! results
      (re-fold lit-pat
        (lambda (i m str acc)
          (let* ((gs  (re-match-groups m))
                 (var (list-ref gs 0))
                 (off (string->number (list-ref gs 1)))
                 (sz  (or (string->number (list-ref gs 2)) -1))
                 (enc (list-ref gs 3))
                 (key (cons var off)))
            (if (hash-key? seen key)
                acc
                (begin
                  (hash-put! seen key #t)
                  (cons (make-dissect-field var off sz enc 'literal #f) acc)))))
        '()
        src))

    ;; Collect variable-offset fields (offset or offset±expr)
    (set! results
      (append
        (re-fold var-pat
          (lambda (i m str acc)
            (let* ((gs  (re-match-groups m))
                   (var (list-ref gs 0))
                   (sz  (or (string->number (list-ref gs 1)) -1))
                   (enc (list-ref gs 2))
                   (key (cons var #f)))
              (if (hash-key? seen key)
                  acc
                  (begin
                    (hash-put! seen key #t)
                    (cons (make-dissect-field var #f sz enc 'var #f) acc)))))
          '()
          src)
        results))

    ;; Collect bitmask variable-offset fields
    (set! results
      (append
        (re-fold bm-var-pat
          (lambda (i m str acc)
            (let* ((gs  (re-match-groups m))
                   (var (list-ref gs 0))
                   (arr (list-ref gs 1))
                   (enc (list-ref gs 2))
                   (key (cons var #f)))
              (if (hash-key? seen key)
                  acc
                  (begin
                    (hash-put! seen key #t)
                    (cons (make-dissect-field var #f -1 enc 'bitmask-parent arr) acc)))))
          '()
          src)
        results))

    ;; Collect bitmask literal-offset fields (parent + bits expansion deferred to gen)
    (set! results
      (append
        (re-fold bm-lit-pat
          (lambda (i m str acc)
            (let* ((gs    (re-match-groups m))
                   (off   (string->number (list-ref gs 0)))
                   (var   (list-ref gs 1))
                   (arr   (list-ref gs 2))
                   (enc   (list-ref gs 3))
                   (key   (cons var off)))
              (if (hash-key? seen key)
                  acc
                  (begin
                    (hash-put! seen key #t)
                    ;; One entry per bitmask parent (bits expanded at codegen time)
                    (cons (make-dissect-field var off -1 enc 'bitmask-parent arr) acc)))))
          '()
          src)
        results))

    ;; Run offset tracker to get tracked-offset fields
    (let* ((tracked-and-bm
            (let loop-track ((acc (cons 0 '())) (body src))
              (re-fold track-pat
                (lambda (i m str cur)
                  (let* ((gs      (re-match-groups m))
                         (set-v   (list-ref gs 0))   ;; offset = N
                         (inc-v   (list-ref gs 1))   ;; offset += N
                         (add-var (list-ref gs 2))   ;; hf_var in regular add_item
                         (add-sz  (list-ref gs 3))   ;; size in add_item
                         (add-enc (list-ref gs 4))   ;; enc in add_item
                         (bm-var  (list-ref gs 5))   ;; hf_var in bitmask
                         (bm-arr  (list-ref gs 6))   ;; array name in bitmask
                         (bm-enc  (list-ref gs 7))   ;; enc in bitmask
                         (cur-off (car cur))
                         (cur-flds (cdr cur)))
                    (cond
                      ((and set-v (not (string=? set-v "")))
                       (cons (string->number set-v) cur-flds))
                      ((and inc-v (not (string=? inc-v "")))
                       (cons (+ cur-off (string->number inc-v)) cur-flds))
                      ((and add-var (not (string=? add-var "")))
                       (let ((key (cons add-var cur-off)))
                         (if (hash-key? seen key)
                             cur
                             (begin
                               (hash-put! seen key #t)
                               (cons cur-off
                                     (cons (make-dissect-field
                                             add-var cur-off
                                             (or (string->number add-sz) -1) add-enc
                                             'tracked #f)
                                           cur-flds))))))
                      ((and bm-var (not (string=? bm-var "")))
                       (let ((key (cons bm-var cur-off)))
                         (if (hash-key? seen key)
                             cur
                             (begin
                               (hash-put! seen key #t)
                               (cons cur-off
                                     (cons (make-dissect-field
                                             bm-var cur-off -1 bm-enc
                                             'bitmask-parent bm-arr)
                                           cur-flds))))))
                      (else cur))))
                acc
                body)))
           (tracked (reverse (cdr tracked-and-bm))))
      ;; Merge all, sort by offset
      (let* ((all (append results tracked))
             ;; Deduplicate by name only (pick first occurrence per short-name)
             (name-seen (make-hash-table))
             (deduped   (filter
                          (lambda (f)
                            (let ((key (dissect-field-hf-var f)))
                              (if (hash-key? name-seen key)
                                  #f
                                  (begin (hash-put! name-seen key #t) #t))))
                          all)))
        (sort deduped
              (lambda (a b)
                (< (or (dissect-field-offset a) 9999)
                   (or (dissect-field-offset b) 9999))))))))

;; ── Formatter Helpers ─────────────────────────────────────────────────────────

(def (field-formatter field proto tables tfs-defs)
  "Return a Scheme expression string to format a field's value (with 'val' as placeholder)."
  (let ((ft        (hf-field-ft-type field))
        (base      (hf-field-base field))
        (vals-name (hf-field-vals-name field))
        (vals-kind (hf-field-vals-kind field))
        (short     (hf-field-short-name field)))
    (cond
      ;; TFS boolean: lookup true/false strings
      ((eq? vals-kind 'tfs)
       (let ((tfs (and vals-name (hash-get tfs-defs vals-name))))
         (if tfs
             (str "(if (= val 0) \"" (cdr tfs) "\" \"" (car tfs) "\")")
             "(if (= val 0) \"False\" \"True\")")))
      ;; VALS table → custom formatter function call
      ((and vals-name (or (eq? vals-kind 'vals) (eq? vals-kind 'vals64)))
       (str "(format-" (re-replace-all "_" proto "-") "-" short " val)"))
      ;; RVALS: no table gen, just hex
      ((eq? vals-kind 'rvals)
       "(fmt-hex val)")
      ;; Special type formatters (IPv4, MAC, IPv6, GUID)
      ((hash-get ft-special-formatter ft)
       => (lambda (f) (str "(" f " val)")))
      ;; String types → decode as UTF-8
      ((or (string=? ft "FT_STRING") (string=? ft "FT_STRINGZ") (string=? ft "FT_STRINGZPAD"))
       "(utf8->string val)")
      ;; Raw byte types
      ((or (string=? ft "FT_BYTES") (string=? ft "FT_UINT_BYTES")
           (string=? ft "FT_OID") (string=? ft "FT_REL_OID") (string=? ft "FT_PROTOCOL"))
       "(fmt-bytes val)")
      ;; Base display for numeric types
      ((hash-get base->formatter base)
       => (lambda (f)
            (if (string=? f "number->string")
                "(number->string val)"
                (str "(" f " val)"))))
      (else
       "(number->string val)"))))

(def (bitmask-bit-formatter field tfs-defs)
  "Formatter for an FT_BOOLEAN bitmask bit field."
  (let* ((vals-name (hf-field-vals-name field))
         (vals-kind (hf-field-vals-kind field)))
    (if (and vals-name (eq? vals-kind 'tfs))
        (let ((tfs (hash-get tfs-defs vals-name)))
          (if tfs
              (str "(if (= val 0) \"" (cdr tfs) "\" \"" (car tfs) "\")")
              "(if (= val 0) \"Not set\" \"Set\")"))
        "(if (= val 0) \"Not set\" \"Set\")")))

(def (generate-vals-formatter proto field table)
  "Generate (def (format-PROTO-FIELD val) (case val ...)) from a val-table."
  (let* ((fn-name (str "format-" (re-replace-all "_" proto "-") "-"
                       (hf-field-short-name field)))
         (entries (val-table-entries table))
         (cases   (map (lambda (e)
                         (str "    ((" (car e) ") \""
                              (re-replace-all "\"" (cdr e) "\\\\\"")
                              "\")"))
                       entries)))
    (str "(def (" fn-name " val)\n"
         "  (case val\n"
         (string-join cases "\n")
         "\n    (else (str \"Unknown (\" val \")\"))))")))

;; ── Code Generator ───────────────────────────────────────────────────────────

(def (generate-dissector proto fields-by-var dissect-fields tables tfs-defs bitmask-arrays rfc description)
  "Build the complete .ss file as a string."
  (let* ((proto-kebab (re-replace-all "_" proto "-"))
         (lines       '()))

    (def (emit! s) (set! lines (cons s lines)))

    ;; Header
    (emit! (str ";; jerboa-ethereal/dissectors/" proto-kebab ".ss"))
    (emit! (str ";; Auto-generated from wireshark/epan/dissectors/packet-" proto ".c"))
    (when (not (string=? rfc "")) (emit! (str ";; " rfc)))
    (emit! "")
    (emit! "(import (jerboa prelude))")
    (emit! "")
    (emit! protocol-helpers)

    ;; Emit VALS formatters for fields in dissect-fields
    (let ((emitted-vals (make-hash-table)))
      (for ((df dissect-fields))
        (let* ((field (hash-get fields-by-var (dissect-field-hf-var df))))
          (when (and field
                     (hf-field-vals-name field)
                     (or (eq? (hf-field-vals-kind field) 'vals)
                         (eq? (hf-field-vals-kind field) 'vals64)))
            (let ((vname (hf-field-vals-name field)))
              (unless (hash-key? emitted-vals vname)
                (hash-put! emitted-vals vname #t)
                (let ((table (hash-get tables vname)))
                  (when table
                    (emit! (str ";; ── " (hf-field-display-name field) " formatter ──"))
                    (emit! (generate-vals-formatter proto field table))
                    (emit! "")))))))))

    ;; Also emit VALS formatters for bitmask bit fields
    (for ((df dissect-fields))
      (when (eq? (dissect-field-kind df) 'bitmask-parent)
        (let* ((arr-name (dissect-field-parent-name df))
               (arr      (and arr-name (hash-get bitmask-arrays arr-name))))
          (when arr
            (for ((hf-var (bitmask-arr-hf-vars arr)))
              (let ((bit-field (hash-get fields-by-var hf-var)))
                (when (and bit-field
                           (hf-field-vals-name bit-field)
                           (or (eq? (hf-field-vals-kind bit-field) 'vals)
                               (eq? (hf-field-vals-kind bit-field) 'vals64)))
                  (let ((vname (hf-field-vals-name bit-field))
                        (emitted-vals (make-hash-table)))
                    (unless (hash-key? emitted-vals vname)
                      (hash-put! emitted-vals vname #t)
                      (let ((table (hash-get tables vname)))
                        (when table
                          (emit! (str ";; ── " (hf-field-display-name bit-field) " formatter ──"))
                          (emit! (generate-vals-formatter proto bit-field table))
                          (emit! ""))))))))))))
    ;; Dissector function
    (emit! ";; ── Dissector ──────────────────────────────────────────────────────")
    (emit! (str "(def (dissect-" proto-kebab " buffer)"))
    (emit! (str "  \"" (if (string=? description "") (str proto-kebab " dissector") description) "\""))
    (emit! "  (try")

    ;; Build the readable-fields list, expanding bitmask parents to include bit fields
    (let* (;; First pass: filter to fields with known readers
           (base-fields
            (filter (lambda (df)
                      (let ((f (hash-get fields-by-var (dissect-field-hf-var df))))
                        (and f (hf-field-reader f))))
                    dissect-fields))
           ;; Expand bitmask parents: insert bit fields after parent
           (expanded
            (append-map
              (lambda (df)
                (if (not (eq? (dissect-field-kind df) 'bitmask-parent))
                    (list df)
                    ;; Expand: parent + bit entries
                    (let* ((arr-name (dissect-field-parent-name df))
                           (arr      (and arr-name (hash-get bitmask-arrays arr-name))))
                      (if (not arr)
                          (list df)
                          (cons df
                                (map (lambda (hf-var)
                                       (make-dissect-field
                                         hf-var
                                         (dissect-field-offset df)
                                         -1
                                         (dissect-field-encoding df)
                                         'bitmask-bit
                                         (dissect-field-hf-var df)))
                                     (bitmask-arr-hf-vars arr)))))))
              base-fields))
           ;; Deduplicate by short-name (keep first occurrence)
           (name-seen (make-hash-table))
           (readable  (filter
                        (lambda (df)
                          (let* ((field (hash-get fields-by-var (dissect-field-hf-var df)))
                                 (name  (and field (hf-field-short-name field))))
                            (if (or (not name) (hash-key? name-seen name))
                                #f
                                (begin (hash-put! name-seen name #t) #t))))
                        expanded)))

      (if (null? readable)
          (begin
            (emit! (str "    ;; TODO: no extractable fields found for " proto-kebab))
            (emit! "    (ok '())"))
          (begin
            ;; Emit let* bindings
            (emit! "    (let* (")
            (for ((df readable))
              (let* ((field    (hash-get fields-by-var (dissect-field-hf-var df)))
                     (name     (hf-field-short-name field))
                     (ft       (hf-field-ft-type field))
                     (kind     (dissect-field-kind df))
                     (offset   (dissect-field-offset df))
                     (size     (dissect-field-size df))
                     (enc      (dissect-field-encoding df))
                     (reader   (let ((r (hf-field-reader field)))
                                 (if (and (not (eq? kind 'bitmask-bit))
                                          (string-contains enc "LITTLE_ENDIAN"))
                                     (or (hash-get ft-le-override ft) r)
                                     r))))
                (cond
                  ;; Bitmask bit: extract from parent field value
                  ((eq? kind 'bitmask-bit)
                   (let* ((parent-field (hash-get fields-by-var (dissect-field-parent-name df)))
                          (parent-name  (and parent-field (hf-field-short-name parent-field)))
                          (mask-str     (hf-field-bitmask-str field))
                          (mask-val     (parse-c-number mask-str))
                          (shift        (lowest-bit-pos mask-val)))
                     (if parent-name
                         (emit! (str "           (" name
                                     " (extract-bits " parent-name
                                     " " (fmt-hex mask-val)
                                     " " shift "))"))
                         (emit! (str "           (" name " 0) ;; bitmask parent not found")))))
                  ;; Byte slice (read-bytes → slice)
                  ((string=? reader "read-bytes")
                   (let* ((actual-size (if (> size 0) size
                                          (or (hash-get ft->size ft) 1)))
                          (off (or offset 0)))
                     (emit! (str "           (" name " (unwrap (slice buffer " off " " actual-size ")))"))))
                  ;; Numeric read
                  (else
                   (let ((off (or offset 0)))
                     (emit! (str "           (" name " (unwrap (" reader " buffer " off ")))")))))))  
            (emit! "           )")
            (emit! "")

            ;; Emit result list
            (emit! "      (ok (list")
            (for ((df readable))
              (let* ((field (hash-get fields-by-var (dissect-field-hf-var df)))
                     (name  (hf-field-short-name field))
                     (kind  (dissect-field-kind df))
                     (fmt   (if (eq? kind 'bitmask-bit)
                                (re-replace "\\bval\\b"
                                  (bitmask-bit-formatter field tfs-defs)
                                  name)
                                (re-replace "\\bval\\b"
                                  (field-formatter field proto tables tfs-defs)
                                  name))))
                (emit! (str "        (cons '" name
                            " (list (cons 'raw " name
                            ") (cons 'formatted " fmt ")))"))))
            (emit! "        )))"))))

    (emit! "")
    (emit! "    (catch (e)")
    (emit! (str "      (err (str \"" (string-upcase proto-kebab) " parse error: \" e)))))"))
    (emit! "")
    (emit! (str ";; dissect-" proto-kebab ": parse " (string-upcase proto-kebab) " from bytevector"))
    (emit! ";; Returns (ok fields-alist) or (err message)")

    (string-join (reverse lines) "\n")))

;; ── Metadata Helpers ─────────────────────────────────────────────────────────

(def (find-rfc src)
  (let ((m (re-search "RFC\\s*(\\d+)" (substring src 0 (min 3000 (string-length src))))))
    (if m (str "RFC " (car (re-match-groups m))) "")))

(def (find-description src)
  (let ((m (re-search "proto_register_protocol\\s*\\(\\s*\"([^\"]+)\"" src)))
    (if m (car (re-match-groups m)) "")))

;; ── File Conversion ───────────────────────────────────────────────────────────

(def (convert-file c-path out-dir verbose?)
  (let* ((src            (read-file-string c-path))
         (proto          (proto-from-filename c-path))
         (proto-kebab    (re-replace-all "_" proto "-"))
         (fields         (parse-hf-register-info src))
         (tables         (parse-value-tables src))
         (tfs-defs       (parse-tfs-defs src))
         (bitmask-arrs   (parse-bitmask-arrays src))
         (fields-by-var  (list->hash-table
                           (map (lambda (f) (cons (hf-field-var-name f) f))
                                fields)))
         (rfc            (find-rfc src))
         (description    (find-description src)))
    ;; Find primary dissect function
    (let-values (((fn-name body) (find-dissect-fn src proto)))
      (let* ((dissect-flds   (if fn-name
                                 (parse-body body proto bitmask-arrs)
                                 '()))
             (field-count    (length fields))
             (detected-count (length dissect-flds))
             (code           (generate-dissector proto fields-by-var dissect-flds
                                                 tables tfs-defs bitmask-arrs
                                                 rfc description))
             (out-path       (and out-dir
                                  (path-join out-dir (str proto-kebab ".ss")))))
        (when verbose?
          (displayln (str "  " proto-kebab
                          "  hf:" field-count
                          "  fields:" detected-count
                          (if fn-name (str "  fn:" fn-name) "  fn:none"))))
        (if out-path
            (begin
              (write-file-string out-path code)
              out-path)
            code)))))

;; ── Main ─────────────────────────────────────────────────────────────────────

(def (collect-c-files path)
  "Return list of .c files to process. Path may be a file or directory."
  (cond
    ((and (file-exists? path) (not (file-directory? path)))
     (list path))
    ((file-directory? path)
     (let* ((entries (directory-list path))
            (c-files (filter (lambda (f) (string-suffix? ".c" f)) entries)))
       (map (lambda (f) (path-join path f)) c-files)))
    (else '())))

(def (parse-args args)
  "Returns (values files out-dir verbose?)."
  (let loop ((a args) (files '()) (out-dir #f) (verbose? #f))
    (cond
      ((null? a)
       (values (reverse files) out-dir verbose?))
      ((string=? (car a) "--out")
       (if (pair? (cdr a))
           (loop (cddr a) files (cadr a) verbose?)
           (loop (cdr a) files out-dir verbose?)))
      ((string=? (car a) "--verbose")
       (loop (cdr a) files out-dir #t))
      (else
       (loop (cdr a)
             (append files (collect-c-files (car a)))
             out-dir verbose?)))))

(def (main)
  (let-values (((files out-dir verbose?) (parse-args (command-line-arguments))))
    (if (null? files)
        (begin
          (displayln "Usage: wireshark-convert.ss <packet-PROTO.c|dir/> ... [--out dir/] [--verbose]")
          (displayln "")
          (displayln "Examples:")
          (displayln "  scheme --libdirs .:../jerboa/lib --script tools/wireshark-convert.ss \\")
          (displayln "    ~/mine/wireshark/epan/dissectors/packet-icmp.c --out dissectors/")
          (displayln "  scheme --libdirs .:../jerboa/lib --script tools/wireshark-convert.ss \\")
          (displayln "    ~/mine/wireshark/epan/dissectors/ --out dissectors/ --verbose"))
        (begin
          (when out-dir
            (displayln (str "Output: " out-dir "  Files: " (length files))))
          (let ((ok-count 0) (fail-count 0) (total (length files)))
            (for ((f files))
              (try
                (convert-file f out-dir verbose?)
                (set! ok-count (+ ok-count 1))
                (when (and (not verbose?) (= (modulo ok-count 100) 0))
                  (displayln (str "  " ok-count "/" total " converted...")))
                (catch (e)
                  (displayln (str "FAIL " f ": "
                                  (with-output-to-string (lambda () (display-condition e)))))
                  (set! fail-count (+ fail-count 1)))))
            (displayln (str "\nDone: " ok-count " converted, " fail-count " failed")))))))

(main)
