/*
 * TLS Snoop - eBPF program for capturing TLS handshakes
 * Filters TCP traffic on port 443 and captures TLS handshake packets
 * Supports both IPv4 and IPv6
 * Uses per-CPU array map to avoid 512-byte stack limit
 * Attaches to TC (traffic control) for both ingress and egress visibility
 */

#include <uapi/linux/ptrace.h>
#include <uapi/linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>

// TLS Content Types
#define TLS_CONTENT_HANDSHAKE 0x16

// TLS Handshake Types
#define TLS_HANDSHAKE_CLIENT_HELLO 0x01
#define TLS_HANDSHAKE_SERVER_HELLO 0x02

// TLS Versions (record layer)
// Note: TLS 1.3 uses 0x0301 (TLS 1.0) in record layer for compatibility
#define SSL_3_0_MAJOR 0x03

// Maximum TLS record size per spec (2^14 = 16384 bytes)
#define MAX_TLS_PAYLOAD 16384

// Structure to send packet info to userland
struct tls_event {
    u32 src_ip;
    u32 dst_ip;
    u8  src_ip6[16];
    u8  dst_ip6[16];
    u16 src_port;
    u16 dst_port;
    u16 payload_len;
    u8  is_ipv6;
    u8  payload[MAX_TLS_PAYLOAD];
};

// Per-CPU array to hold event data (avoids 512-byte stack limit)
BPF_PERCPU_ARRAY(event_storage, struct tls_event, 1);

BPF_PERF_OUTPUT(tls_events);

int tls_filter(struct __sk_buff *skb) {
    // Get event storage from per-CPU map
    int zero = 0;
    struct tls_event *event = event_storage.lookup(&zero);
    if (!event)
        return TC_ACT_OK;

    u8 buf[6];  // Small buffer for header reads

    // Read Ethernet header ethertype (at offset 12, 2 bytes)
    u16 eth_proto;
    if (bpf_skb_load_bytes(skb, 12, &eth_proto, 2) < 0)
        return TC_ACT_OK;

    // DEBUG: trace IPv6 packets
    if (eth_proto == htons(ETH_P_IPV6)) {
        bpf_trace_printk("IPv6 packet, skb->len=%d\\n", skb->len);
    }

    u32 tcp_offset;
    u8 ip_proto;

    // Handle IPv4
    if (eth_proto == htons(ETH_P_IP)) {
        event->is_ipv6 = 0;

        // Read IP header (starts at offset 14)
        u8 ip_ver_ihl;
        if (bpf_skb_load_bytes(skb, 14, &ip_ver_ihl, 1) < 0)
            return TC_ACT_OK;

        u32 ip_hdr_len = (ip_ver_ihl & 0x0F) * 4;
        if (ip_hdr_len < 20)
            return TC_ACT_OK;

        // Read IP protocol
        if (bpf_skb_load_bytes(skb, 14 + 9, &ip_proto, 1) < 0)
            return TC_ACT_OK;

        // Only process TCP
        if (ip_proto != IPPROTO_TCP)
            return TC_ACT_OK;

        // Read source and destination IPs
        if (bpf_skb_load_bytes(skb, 14 + 12, &event->src_ip, 4) < 0)
            return TC_ACT_OK;
        if (bpf_skb_load_bytes(skb, 14 + 16, &event->dst_ip, 4) < 0)
            return TC_ACT_OK;

        tcp_offset = 14 + ip_hdr_len;

    // Handle IPv6
    } else if (eth_proto == htons(ETH_P_IPV6)) {
        event->is_ipv6 = 1;

        // Read source IPv6 (offset 8, 16 bytes)
        if (bpf_skb_load_bytes(skb, 14 + 8, event->src_ip6, 16) < 0)
            return TC_ACT_OK;
        // Read destination IPv6 (offset 24, 16 bytes)
        if (bpf_skb_load_bytes(skb, 14 + 24, event->dst_ip6, 16) < 0)
            return TC_ACT_OK;

        // IPv6 header is fixed 40 bytes, next header at offset 6
        if (bpf_skb_load_bytes(skb, 14 + 6, &ip_proto, 1) < 0)
            return TC_ACT_OK;

        tcp_offset = 14 + 40;  // Start after IPv6 header

        // Skip extension headers if present (max 6 iterations to satisfy verifier)
        #pragma unroll
        for (int i = 0; i < 6; i++) {
            if (ip_proto == IPPROTO_TCP) {
                break;
            }

            // Check for known extension headers
            // 0=Hop-by-Hop, 43=Routing, 44=Fragment, 60=Destination Options
            if (ip_proto == 0 || ip_proto == 43 || ip_proto == 60) {
                // Extension header: next_header(1) + length(1) + data
                u8 ext_hdr[2];
                if (bpf_skb_load_bytes(skb, tcp_offset, ext_hdr, 2) < 0)
                    return TC_ACT_OK;
                ip_proto = ext_hdr[0];
                // Length is in 8-byte units, not including first 8 bytes
                tcp_offset += 8 + (ext_hdr[1] * 8);
            } else if (ip_proto == 44) {
                // Fragment header is fixed 8 bytes
                u8 next_hdr;
                if (bpf_skb_load_bytes(skb, tcp_offset, &next_hdr, 1) < 0)
                    return TC_ACT_OK;
                ip_proto = next_hdr;
                tcp_offset += 8;
            } else {
                // Unknown header or not TCP, bail out
                return TC_ACT_OK;
            }
        }

        if (ip_proto != IPPROTO_TCP) {
            bpf_trace_printk("IPv6: not TCP, proto=%d\\n", ip_proto);
            return TC_ACT_OK;
        }
        bpf_trace_printk("IPv6: TCP found at offset %d\\n", tcp_offset);

    } else {
        return TC_ACT_OK;
    }

    // Read TCP source port, dest port
    u16 src_port, dst_port;
    if (bpf_skb_load_bytes(skb, tcp_offset, &src_port, 2) < 0)
        return TC_ACT_OK;
    if (bpf_skb_load_bytes(skb, tcp_offset + 2, &dst_port, 2) < 0)
        return TC_ACT_OK;

    src_port = ntohs(src_port);
    dst_port = ntohs(dst_port);

    // Filter for TLS ports (either direction)
    // PORT_FILTER_CONDITION is replaced at load time with actual port checks
    if (!(PORT_FILTER_CONDITION))
        return TC_ACT_OK;

    bpf_trace_printk("TLS port match: %d -> %d\\n", src_port, dst_port);

    // Read TCP data offset (upper 4 bits of byte 12)
    u8 tcp_doff_byte;
    if (bpf_skb_load_bytes(skb, tcp_offset + 12, &tcp_doff_byte, 1) < 0)
        return TC_ACT_OK;

    u32 tcp_hdr_len = ((tcp_doff_byte >> 4) & 0x0F) * 4;
    if (tcp_hdr_len < 20)
        return TC_ACT_OK;

    // TLS payload starts after TCP header
    u32 payload_offset = tcp_offset + tcp_hdr_len;

    // Read first 6 bytes of TLS record to check if it's a handshake
    if (bpf_skb_load_bytes(skb, payload_offset, buf, 6) < 0)
        return TC_ACT_OK;

    u8 content_type = buf[0];
    u8 version_major = buf[1];
    u8 version_minor = buf[2];
    u16 record_len = (buf[3] << 8) | buf[4];
    u8 handshake_type = buf[5];

    // Check content type is handshake (0x16)
    if (content_type != TLS_CONTENT_HANDSHAKE)
        return TC_ACT_OK;

    // Check version: major must be 0x03 (SSL 3.0 / TLS)
    // Minor version not checked - TLS 1.3 uses 0x01 (TLS 1.0) for compatibility
    if (version_major != SSL_3_0_MAJOR)
        return TC_ACT_OK;

    // Check handshake type is Client Hello (0x01) or Server Hello (0x02)
    if (handshake_type != TLS_HANDSHAKE_CLIENT_HELLO &&
        handshake_type != TLS_HANDSHAKE_SERVER_HELLO) {
        bpf_trace_printk("TLS: not hello, type=0x%x\\n", handshake_type);
        return TC_ACT_OK;
    }
    bpf_trace_printk("TLS Hello: type=0x%x ver=0x%x%x\\n", handshake_type, version_major, version_minor);

    // Calculate payload length to capture (TLS record header + content)
    u32 tls_total_len = 5 + record_len;
    u32 payload_len = tls_total_len;

    if (payload_len > MAX_TLS_PAYLOAD)
        payload_len = MAX_TLS_PAYLOAD;

    // Fill event struct
    event->src_port = src_port;
    event->dst_port = dst_port;
    event->payload_len = payload_len;

    // Copy TLS payload
    if (bpf_skb_load_bytes(skb, payload_offset, event->payload, payload_len) < 0)
        return TC_ACT_OK;

    tls_events.perf_submit(skb, event, sizeof(*event));
    return TC_ACT_OK;
}
