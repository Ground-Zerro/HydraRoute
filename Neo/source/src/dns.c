#include "../include/dns.h"
#include "../include/util.h"
#include <string.h>

const uint8_t *extract_dns_payload(const uint8_t *pkt, int pkt_len, int *dns_len) {
    if (pkt_len < 20) return NULL;

    int version = (pkt[0] >> 4) & 0x0F;
    int ip_hdr_len, transport_offset;

    if (version == 4) {
        ip_hdr_len = (pkt[0] & 0x0F) * 4;
        if (ip_hdr_len < 20 || pkt_len < ip_hdr_len + 8) return NULL;
        transport_offset = ip_hdr_len;
    } else if (version == 6) {
        if (pkt_len < 48) return NULL;
        ip_hdr_len = 40;
        transport_offset = 40;
    } else {
        return NULL;
    }

    if (pkt_len < transport_offset + 8) return NULL;

    uint16_t src_port = ((uint16_t)pkt[transport_offset] << 8) | pkt[transport_offset + 1];
    if (src_port != 53) return NULL;

    uint8_t protocol;
    if (version == 4) {
        protocol = pkt[9];
    } else {
        protocol = pkt[6];
    }

    int dns_offset;
    if (protocol == 6) {
        int tcp_hdr_len = ((pkt[transport_offset + 12] >> 4) & 0x0F) * 4;
        if (tcp_hdr_len < 20) return NULL;
        dns_offset = transport_offset + tcp_hdr_len;
        if (pkt_len < dns_offset + 2) return NULL;
        uint16_t tcp_dns_len = ((uint16_t)pkt[dns_offset] << 8) | pkt[dns_offset + 1];
        dns_offset += 2;
        if (pkt_len < dns_offset + 12) return NULL;
        *dns_len = tcp_dns_len;
        if (dns_offset + *dns_len > pkt_len)
            *dns_len = pkt_len - dns_offset;
    } else {
        dns_offset = transport_offset + 8;
        if (pkt_len <= dns_offset) return NULL;
        *dns_len = pkt_len - dns_offset;
    }

    if (*dns_len < 12) return NULL;
    return pkt + dns_offset;
}

static int dns_decode_name(const uint8_t *dns_data, int dns_len, int offset, char *out_name, int max_len) {
    int name_len = 0;
    int jumped = 0;
    int bytes_read = 0;
    int ptr_count = 0;
    int orig_offset = offset;

    while (offset < dns_len) {
        uint8_t label_len = dns_data[offset];

        if (label_len == 0) {
            if (!jumped) bytes_read = offset - orig_offset + 1;
            break;
        }

        if ((label_len & 0xC0) == 0xC0) {
            if (offset + 1 >= dns_len) return -1;
            if (!jumped) bytes_read = offset - orig_offset + 2;
            offset = ((label_len & 0x3F) << 8) | dns_data[offset + 1];
            jumped = 1;
            if (++ptr_count > 128) return -1;
            continue;
        }

        offset++;
        if (offset + label_len > dns_len) return -1;

        if (name_len > 0 && name_len < max_len - 1) {
            out_name[name_len++] = '.';
        }

        int copy_len = label_len;
        if (name_len + copy_len >= max_len) copy_len = max_len - name_len - 1;
        memcpy(out_name + name_len, dns_data + offset, copy_len);
        name_len += copy_len;
        offset += label_len;
    }

    out_name[name_len] = '\0';
    to_lower_inplace(out_name, name_len);
    return bytes_read ? bytes_read : (offset - orig_offset + 1);
}

int dns_parse_response(const uint8_t *dns_data, int dns_len, dns_result_t *result) {
    if (dns_len < 12) return -1;

    uint16_t flags = ((uint16_t)dns_data[2] << 8) | dns_data[3];
    if (!(flags & DNS_FLAG_QR)) return -1;

    uint16_t qdcount = ((uint16_t)dns_data[4] << 8) | dns_data[5];
    uint16_t ancount = ((uint16_t)dns_data[6] << 8) | dns_data[7];

    result->answer_count = 0;
    result->cname_count = 0;

    int offset = 12;

    for (int i = 0; i < qdcount && offset < dns_len; i++) {
        while (offset < dns_len) {
            uint8_t len = dns_data[offset];
            if (len == 0) { offset++; break; }
            if ((len & 0xC0) == 0xC0) { offset += 2; break; }
            offset += 1 + len;
        }
        offset += 4;
    }

    for (int i = 0; i < ancount && offset < dns_len; i++) {
        char name[256];
        int name_bytes = dns_decode_name(dns_data, dns_len, offset, name, sizeof(name));
        if (name_bytes < 0) break;
        offset += name_bytes;

        if (offset + 10 > dns_len) break;

        uint16_t rtype = ((uint16_t)dns_data[offset] << 8) | dns_data[offset + 1];
        uint16_t rdlength = ((uint16_t)dns_data[offset + 8] << 8) | dns_data[offset + 9];
        offset += 10;

        if (offset + rdlength > dns_len) break;

        switch (rtype) {
        case DNS_TYPE_A:
            if (rdlength == 4 && result->answer_count < DNS_MAX_ANSWERS) {
                dns_answer_t *a = &result->answers[result->answer_count++];
                strncpy(a->domain, name, 255);
                a->domain[255] = '\0';
                memset(a->ip, 0, 16);
                memcpy(a->ip, dns_data + offset, 4);
                a->family = AF_INET;
            }
            break;

        case DNS_TYPE_AAAA:
            if (rdlength == 16 && result->answer_count < DNS_MAX_ANSWERS) {
                dns_answer_t *a = &result->answers[result->answer_count++];
                strncpy(a->domain, name, 255);
                a->domain[255] = '\0';
                memcpy(a->ip, dns_data + offset, 16);
                a->family = AF_INET6;
            }
            break;

        case DNS_TYPE_CNAME:
            if (result->cname_count < DNS_MAX_CNAMES) {
                dns_cname_t *c = &result->cnames[result->cname_count];
                strncpy(c->source, name, 255);
                c->source[255] = '\0';
                if (dns_decode_name(dns_data, dns_len, offset, c->target, sizeof(c->target)) > 0)
                    result->cname_count++;
            }
            break;

        default:
            break;
        }

        offset += rdlength;
    }

    return 0;
}
