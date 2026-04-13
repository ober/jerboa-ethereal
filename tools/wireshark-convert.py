#!/usr/bin/env python3
"""
wireshark-convert.py — Convert Wireshark C dissectors to Jerboa .ss dissectors

Usage:
  python3 tools/wireshark-convert.py ~/mine/wireshark/epan/dissectors/packet-icmp.c
  python3 tools/wireshark-convert.py ~/mine/wireshark/epan/dissectors/packet-*.c --out dissectors/

Reads:
  - hf_register_info[]   → field names, types, display bases, VALS tables
  - value_string[]        → enum formatters
  - dissect_PROTO()       → field ordering via proto_tree_add_item calls

Emits:
  - dissectors/PROTO.ss   → Jerboa dissector in the same pattern as existing ones
"""

import re
import sys
import os
import argparse
from pathlib import Path
from typing import Optional

# ── Type mapping: Wireshark FT_* → Jerboa reader + size ─────────────────────

FT_TO_JERBOA = {
    'FT_UINT8':    ('read-u8',    1),
    'FT_INT8':     ('read-u8',    1),
    'FT_UINT16':   ('read-u16be', 2),
    'FT_INT16':    ('read-u16be', 2),
    'FT_UINT24':   ('read-u24be', 3),
    'FT_INT24':    ('read-u24be', 3),
    'FT_UINT32':   ('read-u32be', 4),
    'FT_INT32':    ('read-u32be', 4),
    'FT_UINT48':   ('read-u48be', 6),
    'FT_UINT64':   ('read-u64be', 8),
    'FT_INT64':    ('read-u64be', 8),
    'FT_IPv4':     ('read-u32be', 4),
    'FT_IPv6':     ('read-bytes', 16),
    'FT_ETHER':    ('read-bytes', 6),
    'FT_BOOLEAN':  ('read-u8',    1),
    'FT_BYTES':    ('read-bytes', None),   # variable
    'FT_STRING':   ('read-bytes', None),   # variable
    'FT_STRINGZ':  ('read-bytes', None),   # variable
    'FT_NONE':     (None,         0),
    'FT_FRAMENUM': (None,         0),      # metadata only
    'FT_RELATIVE_TIME': (None,    0),
    'FT_ABSOLUTE_TIME': (None,    0),
}

# When ENC_LITTLE_ENDIAN: override reader
FT_LE_OVERRIDE = {
    'FT_UINT16':  'read-u16le',
    'FT_INT16':   'read-u16le',
    'FT_UINT32':  'read-u32le',
    'FT_INT32':   'read-u32le',
    'FT_UINT64':  'read-u64le',
    'FT_INT64':   'read-u64le',
}

# Base display → formatter
BASE_TO_FMT = {
    'BASE_HEX':         'fmt-hex',
    'BASE_HEX_DEC':     'fmt-hex',
    'BASE_DEC':         'number->string',
    'BASE_DEC_HEX':     'number->string',
    'BASE_OCT':         '(lambda (v) (number->string v 8))',
    'BASE_NONE':        'number->string',
    'BASE_PT_TCP':      'fmt-port',
    'BASE_PT_UDP':      'fmt-port',
}

# Special type formatters
TYPE_FMT_OVERRIDE = {
    'FT_IPv4':  'fmt-ipv4',
    'FT_ETHER': 'fmt-mac',
    'FT_IPv6':  'fmt-ipv6-address',
}

# Protocol helper preamble (same as in all existing dissectors)
PROTOCOL_HELPERS = '''\
;; ── Protocol Helpers ─────────────────────────────────────────────────
(def (read-u8 buf offset)
  (if (>= offset (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u8-ref buf offset))))

(def (read-u16be buf offset)
  (if (> (+ offset 2) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (bytevector-u16-ref buf offset (endianness big)))))

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

(def (slice buf offset len)
  (if (> (+ offset len) (bytevector-length buf))
      (err "Buffer overrun")
      (ok (let ((result (make-bytevector len)))
            (bytevector-copy! buf offset result 0 len)
            result))))

(def (extract-bits val mask shift)
  (bitwise-arithmetic-shift-right (bitwise-and val mask) shift))

(def (validate pred msg)
  (if pred (ok #t) (err msg)))

(def (fmt-ipv4 addr)
  (let ((b0 (bitwise-arithmetic-shift-right addr 24))
        (b1 (bitwise-and (bitwise-arithmetic-shift-right addr 16) 255))
        (b2 (bitwise-and (bitwise-arithmetic-shift-right addr 8) 255))
        (b3 (bitwise-and addr 255)))
    (str b0 "." b1 "." b2 "." b3)))

(def (fmt-mac bytes)
  (string-join
    (map (lambda (b) (string-pad (number->string b 16) 2 #\\0))
         (bytevector->list bytes))
    ":"))

(def (fmt-hex val)
  (str "0x" (number->string val 16)))

(def (fmt-port port)
  (number->string port))
'''


# ── Parser ────────────────────────────────────────────────────────────────────

class Field:
    def __init__(self, var_name, display_name, filter_name, ft_type,
                 base, vals_name, bitmask, description):
        self.var_name    = var_name       # hf_icmp_type
        self.display_name = display_name  # "Type"
        self.filter_name = filter_name    # "icmp.type"
        self.ft_type     = ft_type        # FT_UINT8
        self.base        = base           # BASE_DEC
        self.vals_name   = vals_name      # "icmp_type_str" or None
        self.bitmask     = bitmask        # "0x0" or mask
        self.description = description    # tooltip text

        # Derived
        self.short_name  = self._derive_short(var_name)
        reader, size     = FT_TO_JERBOA.get(ft_type, (None, 0))
        self.reader      = reader
        self.size        = size

    def _derive_short(self, var_name):
        """hf_icmp_type → type, hf_ntp_flags_li → flags-li"""
        # Strip common prefix hf_ and protocol name
        name = re.sub(r'^hf_\w+?_', '', var_name)
        # Convert underscores to hyphens
        return name.replace('_', '-')

    def jerboa_name(self):
        return self.short_name

    def formatter(self, proto):
        """Return the formatter expression for this field."""
        if self.vals_name:
            return f'(format-{proto}-{self.short_name} {{val}})'
        override = TYPE_FMT_OVERRIDE.get(self.ft_type)
        if override:
            return f'({override} {{val}})'
        fmt = BASE_TO_FMT.get(self.base, 'number->string')
        if fmt == 'number->string':
            return f'(number->string {{val}})'
        if fmt.startswith('(lambda'):
            return f'({fmt} {{val}})'
        return f'({fmt} {{val}})'


class ValueTable:
    def __init__(self, name, entries):
        self.name    = name     # "icmp_type_str"
        self.entries = entries  # [(value, label), ...]


def parse_hf_register_info(src: str) -> list[Field]:
    """Extract field definitions from hf_register_info hf[] = { ... }"""
    fields = []

    # Find the hf_register_info block
    m = re.search(r'hf_register_info hf\[\]\s*=\s*\{(.*?)^\s*\};',
                  src, re.DOTALL | re.MULTILINE)
    if not m:
        return fields

    block = m.group(1)

    # Each entry: { &hf_VAR, { "Name", "filter", FT_TYPE, BASE, VALS/NULL, mask, desc, HFILL }}
    # Pattern is flexible - can be multi-line with various formatting
    entry_pat = re.compile(
        r'\{\s*&(hf_\w+)\s*,\s*'           # &hf_variable
        r'\{[^"]*"([^"]+)"\s*,\s*'          # "Display Name"
        r'"([^"]+)"\s*,\s*'                 # "filter.name"
        r'(FT_\w+)\s*,\s*'                  # FT_TYPE
        r'(BASE_\w+|0)\s*,\s*'             # BASE_xxx
        r'(VALS\((\w+)\)|FRAMENUM_TYPE\([^)]+\)|NULL|0)\s*,\s*'  # VALS or NULL
        r'([x0-9A-Fa-f]+|0)\s*,\s*'        # bitmask
        r'(?:"([^"]*)")?\s*,?\s*HFILL',     # description
        re.DOTALL
    )

    for m in entry_pat.finditer(block):
        var_name     = m.group(1)
        display_name = m.group(2)
        filter_name  = m.group(3)
        ft_type      = m.group(4)
        base         = m.group(5)
        vals_expr    = m.group(6)
        vals_name    = m.group(7)  # inner name from VALS(name)
        bitmask      = m.group(8)
        description  = m.group(9) or ''

        fields.append(Field(var_name, display_name, filter_name,
                            ft_type, base, vals_name, bitmask, description))

    return fields


def parse_value_tables(src: str) -> dict[str, ValueTable]:
    """Extract value_string tables: static const value_string NAME[] = { ... }"""
    tables = {}

    # Match: static const value_string NAME[] = { {val, "str"}, ... {0, NULL} };
    tbl_pat = re.compile(
        r'(?:static\s+)?const\s+value_string\s+(\w+)\s*\[\]\s*=\s*\{(.*?)\};',
        re.DOTALL
    )

    entry_pat = re.compile(r'\{(\s*[A-Z_a-z0-9]+\s*),\s*"([^"]+)"\s*\}')
    # Also handle numeric constants
    num_entry_pat = re.compile(r'\{\s*(-?\d+)\s*,\s*"([^"]+)"\s*\}')

    for m in tbl_pat.finditer(src):
        name  = m.group(1)
        block = m.group(2)

        entries = []
        for em in num_entry_pat.finditer(block):
            val   = int(em.group(1))
            label = em.group(2)
            entries.append((val, label))

        if entries:
            tables[name] = ValueTable(name, entries)

    return tables


def parse_dissect_fields(src: str, proto: str) -> list[tuple[str, int, int, str]]:
    """
    Extract proto_tree_add_item calls from the main dissect function.
    Returns list of (hf_var, offset, size, encoding).
    Only captures calls where offset/size are integer literals.
    """
    # Find the main dissect function
    fn_pat = re.compile(
        rf'(?:static\s+)?(?:int|void)\s+dissect_{proto}\s*\([^)]*\)\s*\{{',
        re.IGNORECASE
    )
    m = fn_pat.search(src)
    if not m:
        return []

    # Extract function body (find matching brace)
    start = m.end() - 1
    depth = 0
    i = start
    while i < len(src):
        if src[i] == '{':
            depth += 1
        elif src[i] == '}':
            depth -= 1
            if depth == 0:
                break
        i += 1
    body = src[start:i+1]

    # Find proto_tree_add_item(tree, hf_var, tvb, offset, size, encoding)
    add_pat = re.compile(
        r'proto_tree_add_item\s*\(\s*\w+\s*,\s*'
        r'(hf_\w+)\s*,\s*tvb\s*,\s*'
        r'(\d+)\s*,\s*(\d+)\s*,\s*'
        r'(ENC_\w+|0)\s*\)'
    )

    results = []
    seen_offsets = set()
    for m in add_pat.finditer(body):
        hf_var   = m.group(1)
        offset   = int(m.group(2))
        size     = int(m.group(3))
        encoding = m.group(4)
        key = (hf_var, offset)
        if key not in seen_offsets:
            seen_offsets.add(key)
            results.append((hf_var, offset, size, encoding))

    return sorted(results, key=lambda x: x[1])


# ── Code Generator ───────────────────────────────────────────────────────────

def c_name_to_jerboa(name: str) -> str:
    """Convert C identifier to Jerboa kebab-case."""
    return name.replace('_', '-')


def generate_vals_formatter(proto: str, field: Field, table: ValueTable) -> str:
    """Generate a format-PROTO-FIELD function from a value_string table."""
    fn_name = f'format-{proto}-{field.short_name}'
    lines = [f'(def ({fn_name} val)']
    lines.append(f'  (case val')
    for val, label in table.entries:
        escaped = label.replace('"', '\\"')
        lines.append(f'    (({val}) "{escaped}")')
    lines.append(f'    (else (str "Unknown (" val ")"))))')
    return '\n'.join(lines)


def generate_dissector(proto: str,
                       fields_by_var: dict,
                       dissect_fields: list,
                       tables: dict,
                       rfc: str = '',
                       description: str = '') -> str:
    """Generate a complete .ss dissector file."""

    proto_upper = proto.upper()
    proto_kebab = c_name_to_jerboa(proto)
    doc_line = description or f'{proto_upper} dissector'
    rfc_comment = f';; {rfc}' if rfc else ''

    out = []
    out.append(f';; jerboa-ethereal/dissectors/{proto_kebab}.ss')
    out.append(f';; Auto-generated from wireshark/epan/dissectors/packet-{proto}.c')
    if rfc_comment:
        out.append(rfc_comment)
    out.append('')
    out.append('(import (jerboa prelude))')
    out.append('')
    out.append(PROTOCOL_HELPERS)

    # Emit formatter functions for VALS tables referenced by extracted fields
    emitted_fmts = set()
    for hf_var, offset, size, encoding in dissect_fields:
        field = fields_by_var.get(hf_var)
        if not field or not field.vals_name:
            continue
        table = tables.get(field.vals_name)
        if not table or field.vals_name in emitted_fmts:
            continue
        emitted_fmts.add(field.vals_name)
        out.append(f';; ── {field.display_name} formatter ──')
        out.append(generate_vals_formatter(proto, field, table))
        out.append('')

    # Main dissect function
    out.append(f';; ── Dissector ──────────────────────────────────────────────────────')
    out.append(f'(def (dissect-{proto_kebab} buffer)')
    out.append(f'  "{doc_line}"')
    out.append(f'  (try')

    if not dissect_fields:
        out.append(f'    ;; TODO: field extraction not auto-detected; fill in manually')
        out.append(f'    (ok (list))')
    else:
        out.append(f'    (let* (')
        bindings = []
        for hf_var, offset, size, encoding in dissect_fields:
            field = fields_by_var.get(hf_var)
            if not field:
                continue
            if field.reader is None:
                continue  # skip metadata-only fields

            # Determine reader (LE vs BE)
            reader = field.reader
            if 'ENC_LITTLE_ENDIAN' in encoding and field.ft_type in FT_LE_OVERRIDE:
                reader = FT_LE_OVERRIDE[field.ft_type]

            name = field.jerboa_name()
            if reader in ('read-u8', 'read-u16be', 'read-u32be', 'read-u16le', 'read-u32le', 'read-u64be'):
                bindings.append(f'           ({name} (unwrap ({reader} buffer {offset})))')
            elif reader == 'read-bytes':
                bindings.append(f'           ({name} (unwrap (slice buffer {offset} {size})))')
            else:
                bindings.append(f'           ;; TODO: {name} ({reader} at {offset}, size {size})')

        out.append('\n'.join(bindings))
        out.append('           )')

        # Build result alist
        out.append('')
        out.append(f'      (ok (list')
        for hf_var, offset, size, encoding in dissect_fields:
            field = fields_by_var.get(hf_var)
            if not field or field.reader is None:
                continue
            name = field.jerboa_name()
            fmt_expr = field.formatter(proto).replace('{val}', name)
            out.append(f'        (cons \'{name} (list (cons \'raw {name}) (cons \'formatted {fmt_expr})))')
        out.append('        )))')

    out.append('')
    out.append(f'    (catch (e)')
    out.append(f'      (err (str "{proto_upper} parse error: " e)))))')
    out.append('')

    # Footer comment
    out.append(f';; ── Exported API ────────────────────────────────────────────────────────')
    out.append(f';; dissect-{proto_kebab}: parse {proto_upper} from bytevector')
    out.append(f';; Returns (ok fields-alist) or (err message)')

    return '\n'.join(out) + '\n'


# ── Main ──────────────────────────────────────────────────────────────────────

def convert_file(c_path: str, out_dir: Optional[str] = None) -> str:
    """Convert a single packet-PROTO.c file. Returns generated Scheme code."""

    src = Path(c_path).read_text(errors='replace')
    filename = os.path.basename(c_path)

    # Extract protocol name from filename: packet-icmp.c → icmp
    proto = re.sub(r'^packet-', '', filename)
    proto = re.sub(r'\.c$', '', proto)

    fields = parse_hf_register_info(src)
    tables = parse_value_tables(src)
    dissect_order = parse_dissect_fields(src, proto)

    fields_by_var = {f.var_name: f for f in fields}

    # Try to find RFC reference in comments
    rfc_match = re.search(r'RFC\s*(\d+)', src[:2000])
    rfc = f'RFC {rfc_match.group(1)}' if rfc_match else ''

    # Try to find protocol description
    desc_match = re.search(r'proto_register_protocol\s*\(\s*"([^"]+)"', src)
    description = desc_match.group(1) if desc_match else ''

    code = generate_dissector(proto, fields_by_var, dissect_order, tables,
                              rfc=rfc, description=description)

    if out_dir:
        proto_kebab = c_name_to_jerboa(proto)
        out_path = Path(out_dir) / f'{proto_kebab}.ss'
        out_path.write_text(code)
        print(f'  → {out_path}  ({len(fields)} fields, {len(dissect_order)} detected)')
    else:
        print(code)

    return code


def main():
    parser = argparse.ArgumentParser(description='Convert Wireshark dissectors to Jerboa .ss')
    parser.add_argument('files', nargs='+', help='packet-PROTO.c files to convert')
    parser.add_argument('--out', '-o', help='Output directory (default: print to stdout)')
    args = parser.parse_args()

    if args.out:
        Path(args.out).mkdir(parents=True, exist_ok=True)

    ok = fail = 0
    for f in args.files:
        try:
            convert_file(f, args.out)
            ok += 1
        except Exception as e:
            print(f'FAIL {f}: {e}', file=sys.stderr)
            fail += 1

    if len(args.files) > 1:
        print(f'\n{ok} converted, {fail} failed', file=sys.stderr)


if __name__ == '__main__':
    main()
