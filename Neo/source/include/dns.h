#ifndef DNS_H
#define DNS_H

#include "hrneo.h"
#include <stdint.h>
#include <netinet/in.h>

#define DNS_FLAG_QR    0x8000
#define DNS_TYPE_A     1
#define DNS_TYPE_CNAME 5
#define DNS_TYPE_AAAA  28

#define DNS_MAX_ANSWERS 128
#define DNS_MAX_CNAMES  32

typedef struct {
    char domain[256];
    uint8_t ip[16];
    uint8_t family;
} dns_answer_t;

typedef struct {
    char source[256];
    char target[256];
} dns_cname_t;

typedef struct {
    dns_answer_t answers[DNS_MAX_ANSWERS];
    int answer_count;
    dns_cname_t cnames[DNS_MAX_CNAMES];
    int cname_count;
} dns_result_t;

const uint8_t *extract_dns_payload(const uint8_t *pkt, int pkt_len, int *dns_len);
int dns_parse_response(const uint8_t *dns_data, int dns_len, dns_result_t *result);

#endif
