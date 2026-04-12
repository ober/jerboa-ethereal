;; jerboa-ethereal/lib/dsl/parser.ss
;; DSL parser: parse protocol definitions from s-expressions
;;
;; Converts DSL definitions like:
;;   (defprotocol ethernet :description "..." :fields [...])
;; into executable protocol-t records.

(import (jerboa prelude))

;; Protocol structure: use alists for flexibility
;; Protocol: (name . (description fields link-type next-protocol-field))
;; Field-spec: (name . (type size mask shift formatter values conditional description))

(def (make-protocol name description fields link-type next-protocol-field)
  "Create protocol record as nested alist"
  (cons name (list description fields link-type next-protocol-field)))

(def (protocol? x)
  "Check if x is a protocol"
  (and (pair? x) (symbol? (car x))))

(def (protocol-name proto)
  "Get protocol name"
  (car proto))

(def (protocol-description proto)
  "Get protocol description"
  (cadr (cdr proto)))

(def (protocol-field-specs proto)
  "Get protocol field specs list"
  (caddr (cdr proto)))

(def (protocol-link-type proto)
  "Get optional parent protocol"
  (cadddr (cdr proto)))

(def (protocol-next-protocol-field proto)
  "Get field that determines payload protocol"
  (car (cddddr (cdr proto))))

(def (make-field-spec name type size mask shift formatter values conditional description)
  "Create field-spec record as nested alist"
  (cons name (list type size mask shift formatter values conditional description)))

(def (field-spec? x)
  "Check if x is a field-spec"
  (and (pair? x) (symbol? (car x))))

(def (field-spec-name fs)
  "Get field name"
  (car fs))

(def (field-spec-type fs)
  "Get field type"
  (cadr (cdr fs)))

(def (field-spec-size fs)
  "Get field size (static or #f)"
  (caddr (cdr fs)))

(def (field-spec-mask fs)
  "Get bitfield mask"
  (cadddr (cdr fs)))

(def (field-spec-shift fs)
  "Get bit shift amount"
  (car (cddddr (cdr fs))))

(def (field-spec-formatter fs)
  "Get formatter function name"
  (cadr (cddddr (cdr fs))))

(def (field-spec-values fs)
  "Get value name mapping"
  (caddr (cddddr (cdr fs))))

(def (field-spec-conditional fs)
  "Get conditional predicate"
  (cadddr (cddddr (cdr fs))))

(def (field-spec-description fs)
  "Get field description"
  (car (cdddddr (cdr fs))))

;; ── Parser ──────────────────────────────────────────────────────────────────

(def (parse-protocol-def sexp)
  "Parse a protocol definition s-expression
   Input: (defprotocol name :key value ...)
   Output: protocol-t record"
  (unless (and (list? sexp) (> (length sexp) 1))
    (error 'parse-protocol-def "Invalid protocol definition"))

  (match sexp
    [('defprotocol name . rest)
     (let* ([opts (parse-keyword-args rest)]
            [description (get-opt opts :description "Undocumented")]
            [field-specs (get-opt opts "field-specs" '())]
            [link-type (get-opt opts :link-type #f)]
            [next-field (get-opt opts :next-protocol-field #f)])
       (make-protocol
         name
         description
         (map parse-field-spec (ensure-list field-specs))
         link-type
         next-field))]
    [_ (error 'parse-protocol-def (str "Invalid protocol definition: " sexp))]))

(def (parse-field-spec sexp)
  "Parse a single field specification
   Input: (name type :mask ... :formatter ... :description ...)
   Output: field-spec record"
  (unless (and (list? sexp) (>= (length sexp) 2))
    (error 'parse-field-spec "Field spec must have at least name and type"))

  (let* ([name (car sexp)]
         [type (cadr sexp)]
         [opts (parse-keyword-args (cddr sexp))]
         [size (get-opt opts :size #f)]
         [mask (get-opt opts :mask #f)]
         [shift (get-opt opts :shift #f)]
         [formatter (get-opt opts :formatter #f)]
         [values-map (get-opt opts :values #f)]
         [conditional (get-opt opts :conditional #f)]
         [description (get-opt opts :desc "")])
    (unless (symbol? name)
      (error 'parse-field-spec (str "Field name must be symbol, got: " name)))
    (unless (symbol? type)
      (error 'parse-field-spec (str "Field type must be symbol, got: " type)))
    (make-field-spec
      name type size mask shift formatter values-map conditional description)))

;; ── Helper Functions ───────────────────────────────────────────────────────

(def (parse-keyword-args args)
  "Parse keyword arguments into alist
   Input: (:key1 val1 :key2 val2 ...)
   Output: ((key1 . val1) (key2 . val2) ...)"
  (let loop ([args args] [acc '()])
    (cond
      [(null? args) (reverse acc)]
      [(null? (cdr args)) (error 'parse-keyword-args "Odd number of keyword args")]
      [else
       (let ([key (car args)]
             [val (cadr args)]
             [rest (cddr args)])
         (if (keyword? key)
             (loop rest (cons (cons (keyword->string key) val) acc))
             (error 'parse-keyword-args (str "Expected keyword, got: " key))))])))

(def (get-opt alist key default)
  "Get optional keyword from alist
   Input: alist (from parse-keyword-args), key (string), default value
   Output: value or default"
  (let ([pair (assoc key alist)])
    (if pair (cdr pair) default)))

(def (ensure-list x)
  "Ensure x is a list; wrap in list if not"
  (if (list? x) x (list x)))

;; ── Validation ──────────────────────────────────────────────────────────────

(def (validate-protocol proto)
  "Validate protocol definition for correctness
   Checks: field types exist, sizes are valid, etc."
  (unless (protocol? proto)
    (error 'validate-protocol "Not a protocol"))

  ;; TODO: Check field types are registered
  ;; TODO: Check size expressions are valid
  ;; TODO: Check formatter names exist

  #t)

;; ── Protocol Definition Utilities ───────────────────────────────────────────

(def (protocol-field-names proto)
  "Get list of field names in protocol
   Input: protocol-t
   Output: (field-name1 field-name2 ...)"
  (map field-spec-name (protocol-fields proto)))

(def (protocol-field proto field-name)
  "Look up field spec by name
   Input: protocol-t, symbol
   Output: field-spec or #f"
  (let ([field (assoc field-name
                      (map (lambda (f) (cons (field-spec-name f) f))
                           (protocol-fields proto)))])
    (if field (cdr field) #f)))

(def (protocol-static-size proto)
  "Calculate static size of protocol (if all fields are fixed-size)
   Input: protocol-t
   Output: integer or #f (if any field is variable)"
  (for/fold ([total 0]) ([field (protocol-fields proto)])
    (let ([size (field-spec-size field)])
      (if (and (integer? size) (positive? size))
          (+ total size)
          (begin (return #f) total)))))

;; Public API: protocol parsing and utilities
;; parse-protocol-def, parse-field-spec, validate-protocol,
;; protocol, protocol-field, protocol-field-names, protocol-static-size,
;; field-spec, make-field-spec
