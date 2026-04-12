# Wireshark Protocols Index
## Quick Reference for Conversion

Location: `~/mine/wireshark/epan/dissectors/`

### Tier 1: Core Infrastructure (Highest Priority)
**Status**: ICMPv4 ✓ in progress, IPv4 ✓ done

| Protocol | File | RFC | Size | Status | Notes |
|----------|------|-----|------|--------|-------|
| Ethernet | packet-eth.c | IEEE 802.3 | ~300 lines | ✓ Done | L2 foundation |
| IPv4 | packet-ip.c | RFC 791 | ~800 lines | ✓ Done | L3 foundation |
| IPv6 | packet-ipv6.c | RFC 2460 | ~500 lines | 📋 Next | Extension headers |
| ICMP | packet-icmp.c | RFC 792 | ~400 lines | ⏳ In Progress | Basic messages |
| ICMPv6 | packet-icmpv6.c | RFC 4443 | ~300 lines | 📋 High | Echo, Neighbor Disc |
| IGMP | packet-igmp.c | RFC 3376 | ~200 lines | 📋 High | Group membership |
| ARP | packet-arp.c | RFC 826 | ~250 lines | 📋 High | Address resolution |
| UDP | packet-udp.c | RFC 768 | ~150 lines | ✓ Done | L4 transport |
| TCP | packet-tcp.c | RFC 793 | ~1000 lines | ✓ Done | L4 transport |

**Total Tier 1**: ~4.5K lines → ~250 lines Jerboa (95% reduction through code generation)

---

### Tier 2: Application/Transport Protocols

| Protocol | File | RFC | Size | Priority | Notes |
|----------|------|-----|------|----------|-------|
| DNS | packet-dns.c | RFC 1035, 1349 | ~2000 lines | **CRITICAL** | Compressed names, RR types |
| DHCP | packet-dhcp.c | RFC 2131 | ~400 lines | **HIGH** | Bootstrap options |
| NTP | packet-ntp.c | RFC 5905 | ~200 lines | **HIGH** | Time synchronization |
| SNMP | packet-snmp.c | RFC 3416 | ~800 lines | MEDIUM | Management protocol |
| SYSLOG | packet-syslog.c | RFC 3164, 5424 | ~200 lines | MEDIUM | Event logging |
| SIP | packet-sip.c | RFC 3261 | ~1000 lines | MEDIUM | VoIP signaling |
| SMTP | packet-smtp.c | RFC 5321 | ~300 lines | LOW | Email submission |
| POP | packet-pop.c | RFC 1939 | ~150 lines | LOW | Email retrieval |
| IMAP | packet-imap.c | RFC 3501 | ~300 lines | LOW | Email access |
| FTP | packet-ftp.c | RFC 959 | ~200 lines | LOW | File transfer |

**Total Tier 2**: ~6K lines → ~350 lines Jerboa

---

### Tier 3: Security Protocols

| Protocol | File | RFC | Size | Priority | Notes |
|----------|------|-----|------|----------|-------|
| TLS/SSL | packet-tls.c | RFC 5246, 8446 | ~5000 lines | **CRITICAL** | Handshake, records, alerts |
| SSH | packet-ssh.c | RFC 4251-4254 | ~400 lines | **HIGH** | Key exchange, packets |
| HTTPS | packet-http.c | RFC 7230-7235 | ~1000 lines | **HIGH** | HTTP/2, HTTPS |
| HTTP/2 | packet-http2.c | RFC 7540 | ~600 lines | HIGH | Framing, headers |
| RADIUS | packet-radius.c | RFC 2865 | ~600 lines | MEDIUM | Authentication |
| KERBEROS | packet-krb5.c | RFC 4120 | ~800 lines | MEDIUM | Authentication |
| TLS Extensions | packet-tls-utils.c | Various | ~1000 lines | MEDIUM | Certificates, extensions |

**Total Tier 3**: ~9K lines → ~600 lines Jerboa

---

### Tier 4: Infrastructure/Utility Protocols

| Protocol | File | RFC | Size | Priority | Notes |
|----------|------|-----|------|----------|-------|
| LLMNR | packet-llmnr.c | RFC 4795 | ~200 lines | LOW | Link-local multicast |
| mDNS | packet-mdns.c | RFC 6762 | ~400 lines | LOW | Multicast DNS |
| Netbios | packet-netbios.c | RFC 1001, 1002 | ~500 lines | LOW | Legacy Windows |
| NBNS | packet-nbns.c | RFC 1002 | ~300 lines | LOW | Netbios name service |
| WINS | packet-wins.c | Proprietary | ~200 lines | LOW | Windows name service |
| LDAP | packet-ldap.c | RFC 4511 | ~600 lines | LOW | Directory service |
| HTTP Proxy | packet-http.c | - | Part of HTTP | LOW | Proxy protocol |

**Total Tier 4**: ~2.3K lines → ~200 lines Jerboa

---

### Tier 5: Optional/Advanced Protocols

| Category | Protocols | Files | Count | Notes |
|----------|-----------|-------|-------|-------|
| Real-time Media | RTP, RTCP, SCTP | packet-rtp.c, packet-rtcp.c, packet-sctp.c | 1000+ | Streaming |
| Tunneling | GRE, IPSec, OpenVPN, WireGuard | packet-gre.c, packet-ipsec.c, etc. | 2000+ | VPN protocols |
| Quality of Service | RSVP, DiffServ | packet-rsvp.c | 800+ | QoS signaling |
| Multicast | PIM, MSDP, IGMP | packet-pim.c, packet-msdp.c | 500+ | Group routing |
| Routing | OSPF, BGP, RIP, EIGRP | packet-ospf.c, packet-bgp.c, etc. | 2000+ | Dynamic routing |
| Link Control | PPP, HDLC, Frame Relay | packet-ppp.c, packet-hdlc.c | 1000+ | WAN protocols |
| VoIP | H.323, IAX, MGCP | packet-h323.c, packet-iax.c | 1000+ | Voice protocols |
| Industrial | MODBUS, OPC-UA, Profinet | packet-modbus.c, packet-opcua.c | 1500+ | Industrial IoT |
| Cloud/Containers | Docker, Kubernetes, etcd | Various | 500+ | Modern infrastructure |

**Total Tier 5**: ~10K+ lines (huge, implement selectively)

---

## Extraction Commands by Tier

### Tier 1 Core (Low Complexity)
```bash
# Get ICMPv6 dissector
head -500 ~/mine/wireshark/epan/dissectors/packet-icmpv6.c

# Get IGMP dissector
head -400 ~/mine/wireshark/epan/dissectors/packet-igmp.c

# Get ARP dissector
head -350 ~/mine/wireshark/epan/dissectors/packet-arp.c
```

### Tier 2 Application (Medium Complexity)
```bash
# Get DNS field structure
grep -A 200 "hf_register_info" ~/mine/wireshark/epan/dissectors/packet-dns.c | head -150

# Get DHCP options
grep "^#define" ~/mine/wireshark/epan/dissectors/packet-dhcp.c | head -50

# Get NTP dissector (simpler)
head -300 ~/mine/wireshark/epan/dissectors/packet-ntp.c
```

### Tier 3 Security (High Complexity)
```bash
# TLS record types (complex - 5000+ lines)
wc -l ~/mine/wireshark/epan/dissectors/packet-tls.c

# HTTP methods (simpler subset)
grep "GET\|POST\|HEAD\|PUT\|DELETE" ~/mine/wireshark/epan/dissectors/packet-http.c | head -10

# SSH packet types
grep "^#define.*SSH.*0x" ~/mine/wireshark/epan/dissectors/packet-ssh.c | head -30
```

---

## Field Extraction Patterns

### Pattern 1: Simple Integer Fields
**Wireshark**:
```c
proto_tree_add_item(tree, hf_field_name, tvb, offset, 2, ENC_BIG_ENDIAN);
```

**Extract**:
```bash
grep -n "proto_tree_add_item.*hf_" ~/mine/wireshark/epan/dissectors/packet-icmp.c | head -20
```

**Result**: List of all fields with offsets and sizes

### Pattern 2: Bitfield/Masked Fields
**Wireshark**:
```c
proto_tree_add_uint_bits_format_value(tree, hf_flags, tvb, 0, 8, flags, "%d");
```

**Extract**:
```bash
grep "proto_tree_add_uint_bits\|proto_tree_add_bits_item" ~/mine/wireshark/epan/dissectors/packet-dns.c
```

### Pattern 3: Variable-Length Fields
**Wireshark**:
```c
int name_len = dissect_dns_name(tvb, offset, tree);
offset += name_len;
```

**Extract**:
```bash
grep -B 2 -A 2 "dissect_dns_name\|tvb_get_string" ~/mine/wireshark/epan/dissectors/packet-dns.c | head -30
```

### Pattern 4: Conditional Fields (Type-Dependent)
**Wireshark**:
```c
if (type == ECHO || type == ECHO_REPLY) {
  proto_tree_add_item(tree, hf_identifier, tvb, 4, 2, ENC_BIG_ENDIAN);
}
```

**Extract**:
```bash
grep -n "if.*type\|switch.*type" ~/mine/wireshark/epan/dissectors/packet-icmp.c
```

---

## Most Important Dissectors (Strategic Priority)

### If you only convert 5 protocols, choose these:
1. **DNS** - Used by everything, appears in 50% of traffic
2. **TLS/SSL** - HTTPS dominates modern internet
3. **HTTP** - Web traffic analysis
4. **DHCP** - Network bootstrap, very visible
5. **SSH** - Remote access, security baseline

### If you have 2 weeks, add:
6. **ICMPv6** - IPv6 is growing
7. **NTP** - Time synchronization
8. **SNMP** - Network management
9. **SIP** - VoIP
10. **RADIUS** - Authentication

---

## Integration Checklist

For each protocol converted:

- [ ] Extract from Wireshark `packet-PROTO.c`
- [ ] Map fields to Jerboa types
- [ ] Create `dissectors/PROTO.ss` with safe dissector
- [ ] Create formatters for special fields (IPs, ports, names)
- [ ] Register with pipeline via `register-protocol!`
- [ ] Test with sample packet from live capture
- [ ] Add to DSL_EXAMPLES.md
- [ ] Update docs with protocol notes
- [ ] Commit with RFC reference

---

## File Size Reference

Wireshark dissectors range from:
- **Tiny** (50-200 lines): Simple fixed-structure protocols
  - NTP, LLMNR, simple options
- **Small** (200-500 lines): Most transport/app protocols
  - DNS, DHCP, SSH basics
- **Medium** (500-2000 lines): Complex protocols with options
  - HTTP, SIP, SNMP
- **Large** (2000-5000 lines): TLS, ASN.1-heavy, many packet types
  - TLS, Kerberos, LDAP
- **Huge** (5000+ lines): Industrial, complex, many variants
  - BGP, H.323, proprietary protocols

Our dissectors average 10-15% of Wireshark's due to code generation and not handling every edge case.

---

## Next Steps

**Recommended starting point**: **ICMPv6 + IGMP** (Tier 1)
- Small, well-structured
- Easy to extract from Wireshark
- Essential for full IPv4/IPv6 coverage
- ~4 hours work total

**Then move to**: **DNS** (Tier 2)
- Most useful for traffic analysis
- Slightly more complex (compressed names)
- ~6 hours work

See `WIRESHARK_CONVERSION_STRATEGY.md` for detailed workflow.
