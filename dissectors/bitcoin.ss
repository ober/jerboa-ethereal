;; packet-bitcoin.c
;; Routines for bitcoin dissection
;; Copyright 2011, Christian Svensson <blue@cmd.nu>
;; Bitcoin address: 15Y2EN5mLnsTt3CZBfgpnZR5SeLwu7WEHz
;;
;; See https://en.bitcoin.it/wiki/Protocol_specification
;;
;; Updated 2015, Laurenz Kamp <laurenz.kamp@gmx.de>
;; Changes made:
;; Updated dissectors:
;; -> ping: ping packets now have a nonce.
;; -> version: If version >= 70002, version messages have a relay flag.
;; -> Messages with no payload: Added mempool and filterclear messages.
;; Added dissectors:
;; -> pong message
;; -> notfound message
;; -> reject message
;; -> filterload
;; -> filteradd
;; -> merkleblock
;; -> headers
;;
;; Wireshark - Network traffic analyzer
;; By Gerald Combs <gerald@wireshark.org>
;; Copyright 1998 Gerald Combs
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;

;; jerboa-ethereal/dissectors/bitcoin.ss
;; Auto-generated from wireshark/epan/dissectors/packet-bitcoin.c

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
(def (dissect-bitcoin buffer)
  "Bitcoin protocol"
  (try
    (let* (
           (magic (unwrap (read-u32be buffer 0)))
           (services (unwrap (read-u64le buffer 0)))
           (version-version (unwrap (read-u32be buffer 0)))
           (addr-address (unwrap (slice buffer 0 30)))
           (headers-version (unwrap (read-u32be buffer 0)))
           (block-version (unwrap (read-u32be buffer 0)))
           (ping-nonce (unwrap (read-u64be buffer 0)))
           (pong-nonce (unwrap (read-u64be buffer 0)))
           (filterload-nhashfunc (unwrap (read-u32be buffer 0)))
           (merkleblock-version (unwrap (read-u32be buffer 0)))
           (sendcmpct-announce (unwrap (read-u8 buffer 0)))
           (reject-data (unwrap (slice buffer 1 1)))
           (sendcmpct-version (unwrap (read-u64be buffer 1)))
           (command (unwrap (slice buffer 4 12)))
           (version-services (unwrap (read-u64le buffer 4)))
           (network (extract-bits version-services 0x1 0))
           (getutxo (extract-bits version-services 0x2 1))
           (bloom (extract-bits version-services 0x4 2))
           (witness (extract-bits version-services 0x8 3))
           (xthin (extract-bits version-services 0x10 4))
           (compactfilters (extract-bits version-services 0x40 6))
           (networklimited (extract-bits version-services 0x400 10))
           (p2pv2 (extract-bits version-services 0x800 11))
           (inv-hash (unwrap (slice buffer 4 32)))
           (getdata-hash (unwrap (slice buffer 4 32)))
           (notfound-hash (unwrap (slice buffer 4 32)))
           (getblocks-start (unwrap (slice buffer 4 32)))
           (getheaders-start (unwrap (slice buffer 4 32)))
           (block-prev-block (unwrap (slice buffer 4 32)))
           (headers-prev-block (unwrap (slice buffer 4 32)))
           (filterload-ntweak (unwrap (read-u32be buffer 4)))
           (merkleblock-prev-block (unwrap (slice buffer 4 32)))
           (addrv2-port (unwrap (read-u16be buffer 5)))
           (address (unwrap (slice buffer 8 16)))
           (length (unwrap (read-u32be buffer 16)))
           (port (unwrap (read-u16be buffer 24)))
           (getblocks-stop (unwrap (slice buffer 36 32)))
           (getheaders-stop (unwrap (slice buffer 36 32)))
           (block-merkle-root (unwrap (slice buffer 36 32)))
           (headers-merkle-root (unwrap (slice buffer 36 32)))
           (merkleblock-merkle-root (unwrap (slice buffer 36 32)))
           (tx-version (unwrap (read-u32be buffer 68)))
           (version-nonce (unwrap (read-u64be buffer 72)))
           (tx-flag (unwrap (slice buffer 72 2)))
           (block-bits (unwrap (read-u32be buffer 72)))
           (headers-bits (unwrap (read-u32be buffer 72)))
           (merkleblock-bits (unwrap (read-u32be buffer 72)))
           (tx-in-prev-outp-hash (unwrap (slice buffer 74 32)))
           (block-nonce (unwrap (read-u32be buffer 76)))
           (headers-nonce (unwrap (read-u32be buffer 76)))
           (merkleblock-nonce (unwrap (read-u32be buffer 76)))
           (version-start-height (unwrap (read-u32be buffer 80)))
           (merkleblock-transactions (unwrap (read-u32be buffer 80)))
           (version-relay (unwrap (read-u8 buffer 84)))
           (merkleblock-hashes-hash (unwrap (slice buffer 84 32)))
           (tx-in-prev-outp-index (unwrap (read-u32be buffer 106)))
           (tx-in-seq (unwrap (read-u32be buffer 110)))
           (tx-out-value (unwrap (read-u64be buffer 114)))
           (tx-lock-time (unwrap (read-u32be buffer 122)))
           )

      (ok (list
        (cons 'magic (list (cons 'raw magic) (cons 'formatted (fmt-hex magic))))
        (cons 'services (list (cons 'raw services) (cons 'formatted (fmt-hex services))))
        (cons 'version-version (list (cons 'raw version-version) (cons 'formatted (number->string version-version))))
        (cons 'addr-address (list (cons 'raw addr-address) (cons 'formatted (fmt-bytes addr-address))))
        (cons 'headers-version (list (cons 'raw headers-version) (cons 'formatted (number->string headers-version))))
        (cons 'block-version (list (cons 'raw block-version) (cons 'formatted (number->string block-version))))
        (cons 'ping-nonce (list (cons 'raw ping-nonce) (cons 'formatted (fmt-hex ping-nonce))))
        (cons 'pong-nonce (list (cons 'raw pong-nonce) (cons 'formatted (fmt-hex pong-nonce))))
        (cons 'filterload-nhashfunc (list (cons 'raw filterload-nhashfunc) (cons 'formatted (number->string filterload-nhashfunc))))
        (cons 'merkleblock-version (list (cons 'raw merkleblock-version) (cons 'formatted (number->string merkleblock-version))))
        (cons 'sendcmpct-announce (list (cons 'raw sendcmpct-announce) (cons 'formatted (number->string sendcmpct-announce))))
        (cons 'reject-data (list (cons 'raw reject-data) (cons 'formatted (fmt-bytes reject-data))))
        (cons 'sendcmpct-version (list (cons 'raw sendcmpct-version) (cons 'formatted (number->string sendcmpct-version))))
        (cons 'command (list (cons 'raw command) (cons 'formatted (utf8->string command))))
        (cons 'version-services (list (cons 'raw version-services) (cons 'formatted (fmt-hex version-services))))
        (cons 'network (list (cons 'raw network) (cons 'formatted (if (= network 0) "Not set" "Set"))))
        (cons 'getutxo (list (cons 'raw getutxo) (cons 'formatted (if (= getutxo 0) "Not set" "Set"))))
        (cons 'bloom (list (cons 'raw bloom) (cons 'formatted (if (= bloom 0) "Not set" "Set"))))
        (cons 'witness (list (cons 'raw witness) (cons 'formatted (if (= witness 0) "Not set" "Set"))))
        (cons 'xthin (list (cons 'raw xthin) (cons 'formatted (if (= xthin 0) "Not set" "Set"))))
        (cons 'compactfilters (list (cons 'raw compactfilters) (cons 'formatted (if (= compactfilters 0) "Not set" "Set"))))
        (cons 'networklimited (list (cons 'raw networklimited) (cons 'formatted (if (= networklimited 0) "Not set" "Set"))))
        (cons 'p2pv2 (list (cons 'raw p2pv2) (cons 'formatted (if (= p2pv2 0) "Not set" "Set"))))
        (cons 'inv-hash (list (cons 'raw inv-hash) (cons 'formatted (fmt-bytes inv-hash))))
        (cons 'getdata-hash (list (cons 'raw getdata-hash) (cons 'formatted (fmt-bytes getdata-hash))))
        (cons 'notfound-hash (list (cons 'raw notfound-hash) (cons 'formatted (fmt-bytes notfound-hash))))
        (cons 'getblocks-start (list (cons 'raw getblocks-start) (cons 'formatted (fmt-bytes getblocks-start))))
        (cons 'getheaders-start (list (cons 'raw getheaders-start) (cons 'formatted (fmt-bytes getheaders-start))))
        (cons 'block-prev-block (list (cons 'raw block-prev-block) (cons 'formatted (fmt-bytes block-prev-block))))
        (cons 'headers-prev-block (list (cons 'raw headers-prev-block) (cons 'formatted (fmt-bytes headers-prev-block))))
        (cons 'filterload-ntweak (list (cons 'raw filterload-ntweak) (cons 'formatted (fmt-hex filterload-ntweak))))
        (cons 'merkleblock-prev-block (list (cons 'raw merkleblock-prev-block) (cons 'formatted (fmt-bytes merkleblock-prev-block))))
        (cons 'addrv2-port (list (cons 'raw addrv2-port) (cons 'formatted (fmt-port addrv2-port))))
        (cons 'address (list (cons 'raw address) (cons 'formatted (fmt-ipv6-address address))))
        (cons 'length (list (cons 'raw length) (cons 'formatted (number->string length))))
        (cons 'port (list (cons 'raw port) (cons 'formatted (fmt-port port))))
        (cons 'getblocks-stop (list (cons 'raw getblocks-stop) (cons 'formatted (fmt-bytes getblocks-stop))))
        (cons 'getheaders-stop (list (cons 'raw getheaders-stop) (cons 'formatted (fmt-bytes getheaders-stop))))
        (cons 'block-merkle-root (list (cons 'raw block-merkle-root) (cons 'formatted (fmt-bytes block-merkle-root))))
        (cons 'headers-merkle-root (list (cons 'raw headers-merkle-root) (cons 'formatted (fmt-bytes headers-merkle-root))))
        (cons 'merkleblock-merkle-root (list (cons 'raw merkleblock-merkle-root) (cons 'formatted (fmt-bytes merkleblock-merkle-root))))
        (cons 'tx-version (list (cons 'raw tx-version) (cons 'formatted (number->string tx-version))))
        (cons 'version-nonce (list (cons 'raw version-nonce) (cons 'formatted (fmt-hex version-nonce))))
        (cons 'tx-flag (list (cons 'raw tx-flag) (cons 'formatted (fmt-bytes tx-flag))))
        (cons 'block-bits (list (cons 'raw block-bits) (cons 'formatted (fmt-hex block-bits))))
        (cons 'headers-bits (list (cons 'raw headers-bits) (cons 'formatted (fmt-hex headers-bits))))
        (cons 'merkleblock-bits (list (cons 'raw merkleblock-bits) (cons 'formatted (fmt-hex merkleblock-bits))))
        (cons 'tx-in-prev-outp-hash (list (cons 'raw tx-in-prev-outp-hash) (cons 'formatted (fmt-bytes tx-in-prev-outp-hash))))
        (cons 'block-nonce (list (cons 'raw block-nonce) (cons 'formatted (fmt-hex block-nonce))))
        (cons 'headers-nonce (list (cons 'raw headers-nonce) (cons 'formatted (fmt-hex headers-nonce))))
        (cons 'merkleblock-nonce (list (cons 'raw merkleblock-nonce) (cons 'formatted (fmt-hex merkleblock-nonce))))
        (cons 'version-start-height (list (cons 'raw version-start-height) (cons 'formatted (number->string version-start-height))))
        (cons 'merkleblock-transactions (list (cons 'raw merkleblock-transactions) (cons 'formatted (number->string merkleblock-transactions))))
        (cons 'version-relay (list (cons 'raw version-relay) (cons 'formatted (number->string version-relay))))
        (cons 'merkleblock-hashes-hash (list (cons 'raw merkleblock-hashes-hash) (cons 'formatted (fmt-bytes merkleblock-hashes-hash))))
        (cons 'tx-in-prev-outp-index (list (cons 'raw tx-in-prev-outp-index) (cons 'formatted (number->string tx-in-prev-outp-index))))
        (cons 'tx-in-seq (list (cons 'raw tx-in-seq) (cons 'formatted (number->string tx-in-seq))))
        (cons 'tx-out-value (list (cons 'raw tx-out-value) (cons 'formatted (number->string tx-out-value))))
        (cons 'tx-lock-time (list (cons 'raw tx-lock-time) (cons 'formatted (number->string tx-lock-time))))
        )))

    (catch (e)
      (err (str "BITCOIN parse error: " e)))))

;; dissect-bitcoin: parse BITCOIN from bytevector
;; Returns (ok fields-alist) or (err message)