#ifndef PROBE_QUIC_H
#define PROBE_QUIC_H

#include <stdint.h>
#include "crypto_asm.h"

int quic_walk_initial(const uint8_t *quic_pkt, int pkt_len, crypto_asm_t *a);

#endif
