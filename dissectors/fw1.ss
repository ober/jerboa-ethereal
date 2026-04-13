;; packet-fw1.c
;; Routines for Ethernet header disassembly of FW1 "monitor" files
;; Copyright 2002,2003, Alfred Koebler <ako@icon.de>
;; Copyright 2018, Alfred Koebler <Alfred.Koebler2002ATgmx.de>
;;
;; Wireshark - Network traffic analyzer
;; By Alfred Koebler <ako@icon.de>
;; By Alfred Koebler <Alfred.Koebler2002ATgmx.de>
;; Copyright 2002,2003,2018 Alfred Koebler
;;
;; To use this dissector use the command line option
;; -o eth.interpret_as_fw1_monitor:true
;;
;; At the moment the way with the option is the best one.
;; A automatic way is not possible, because the file format isn't different
;; to the snoop file.
;;
;; With "fw monitor" it is possible to collect packets on several places.
;; The additional information:
;; - is it a incoming or outgoing packet
;; - is it before or after the firewall
;; i  incoming before the firewall
;; I  incoming after the firewall
;; o  outcoming before the firewall
;; O  outcoming after the firewall
;; e  before VPN encryption
;; E  after VPN encryption
;; - the name of the interface
;;
;; What's the problem ?
;; Think about one packet traveling across the firewall.
;; With wireshark you will see 4 lines in the Top Pane.
;; To analyze a problem it is helpful to see the additional information
;; in the protocol tree of the Middle Pane.
;;
;; The presentation of the summary line is designed in the following way:
;; Every time the next selected packet in the Top Pane includes a
;; "new" interface name the name is added to the list in the summary line.
;; The interface names are listed one after the other.
;; The position of the interface names didn't change.
;;
;; And who are the 4 places represented ?
;; The interface name represents the firewall module of the interface.
;; On the left side of the interface name is the interface module.
;; On the right side of the interface name is the "IP" module.
;;
;; Example for a ping from the firewall to another host:
;; For the four lines in the Top Pane you will see the according lines
;; in the Middle Pane:
;; El90x1 o
;; O El90x1
;; i El90x1
;; El90x1 I
;;
;; Example for a packet traversing through the Firewall, first through
;; the inner side firewall module then through the outer side firewall module:
;; i  El90x1        El90x2
;; El90x1 I      El90x2
;; El90x1      o E190x2
;; El90x1        E190x2 O
;;
;; 9.12.2002
;; Add new column with summary of FW-1 interface/direction
;;
;; 11.8.2003
;; Additional interpretation of field Chain Position.
;; Show the chain position in the interface list.
;; Support for new format of fw monitor file
;; written by option -u | -s for UUID/SUUID.
;; NOTICE: First paket will have UUID == 0 !
;;
;; SPDX-License-Identifier: GPL-2.0-or-later
;;
;; 30.5.2018
;; added inspection points "e" and "E"
;;

;; jerboa-ethereal/dissectors/fw1.ss
;; Auto-generated from wireshark/epan/dissectors/packet-fw1.c

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
(def (dissect-fw1 buffer)
  "Checkpoint FW-1"
  (try
    (let* (
           (direction (unwrap (slice buffer 0 1)))
           (chain (unwrap (slice buffer 1 1)))
           (interface (unwrap (slice buffer 2 1)))
           (uuid (unwrap (read-u32be buffer 8)))
           )

      (ok (list
        (cons 'direction (list (cons 'raw direction) (cons 'formatted (utf8->string direction))))
        (cons 'chain (list (cons 'raw chain) (cons 'formatted (utf8->string chain))))
        (cons 'interface (list (cons 'raw interface) (cons 'formatted (utf8->string interface))))
        (cons 'uuid (list (cons 'raw uuid) (cons 'formatted (number->string uuid))))
        )))

    (catch (e)
      (err (str "FW1 parse error: " e)))))

;; dissect-fw1: parse FW1 from bytevector
;; Returns (ok fields-alist) or (err message)