;; jerboa-ethereal/lib/dissector/evaluator.ss
;; Expression evaluation for conditional fields and dynamic sizing

(import (jerboa prelude))

;; ── Conditional Evaluation ─────────────────────────────────────────────────

(def (eval-conditional expr proto-context)
  "Evaluate a conditional expression
   proto-context: alist of (field-name . raw-value)"

  (cond
    ((eq? expr #t) #t)
    ((eq? expr #f) #f)
    ((symbol? expr)
     (let ((val (assoc-in proto-context expr)))
       (and val (not (= (cdr val) 0)))))
    ((pair? expr)
     (eval-compound-condition expr proto-context))
    (#t #f)))

(def (eval-compound-condition expr proto-context)
  "Evaluate compound condition expressions like (= field val) or (> field 5)"
  (let ((op (car expr))
        (args (cdr expr)))
    (case op
      ((=)
       (let ((fld (assoc-in proto-context (car args))))
         (and fld (= (cdr fld) (cadr args)))))
      ((>)
       (let ((fld (assoc-in proto-context (car args))))
         (and fld (> (cdr fld) (cadr args)))))
      ((<)
       (let ((fld (assoc-in proto-context (car args))))
         (and fld (< (cdr fld) (cadr args)))))
      ((>=)
       (let ((fld (assoc-in proto-context (car args))))
         (and fld (>= (cdr fld) (cadr args)))))
      ((<=)
       (let ((fld (assoc-in proto-context (car args))))
         (and fld (<= (cdr fld) (cadr args)))))
      ((and)
       (let loop ((exprs args))
         (cond
           ((null? exprs) #t)
           ((eval-conditional (car exprs) proto-context)
            (loop (cdr exprs)))
           (#t #f))))
      ((or)
       (let loop ((exprs args))
         (cond
           ((null? exprs) #f)
           ((eval-conditional (car exprs) proto-context) #t)
           (#t (loop (cdr exprs))))))
      ((not)
       (not (eval-conditional (car args) proto-context)))
      (else #f))))

;; ── Size Expression Evaluation ─────────────────────────────────────────────

(def (eval-size-expr expr proto-context)
  "Evaluate a size expression (integer, field ref, or arithmetic)"

  (cond
    ((integer? expr) expr)
    ((symbol? expr)
     (let ((val (assoc-in proto-context expr)))
       (if val (cdr val) 0)))
    ((pair? expr)
     (eval-arithmetic-expr expr proto-context))
    (#t 0)))

(def (eval-arithmetic-expr expr proto-context)
  "Evaluate arithmetic: (+ a b), (- a b), (* a b), (/ a b), (% a b)"
  (let ((op (car expr))
        (args (cdr expr)))
    (let ((values (map (lambda (arg) (eval-size-expr arg proto-context)) args)))
      (case op
        ((+) (if (null? values) 0 (apply + values)))
        ((-) (cond
               ((null? values) 0)
               ((= (length values) 1) (- (car values)))
               (#t (apply - values))))
        ((*) (if (null? values) 1 (apply * values)))
        ((/) (if (>= (length values) 2)
                 (let loop ((result (car values)) (rest (cdr values)))
                   (if (null? rest) result
                       (loop (quotient result (car rest)) (cdr rest))))
                 0))
        ((%) (if (>= (length values) 2)
                 (mod (car values) (cadr values))
                 0))
        (else 0)))))