PROJECT = hrneo
VERSION = 3.24.0-1

CC_MIPSEL   = mipsel-linux-muslsf-gcc
CC_MIPS     = mips-linux-muslsf-gcc
CC_AARCH64  = aarch64-linux-musl-gcc
CC_NATIVE   = gcc

COMMON_CFLAGS = -Os -Wall -Wextra -Wno-unused-parameter \
                -ffunction-sections -fdata-sections \
                -fno-unwind-tables -fno-asynchronous-unwind-tables \
                -fomit-frame-pointer \
                -fno-strict-aliasing \
                -DVERSION=\"$(VERSION)\" \
                -Iinclude

COMMON_LDFLAGS = -Wl,--gc-sections -Wl,--build-id=sha1 -s

CFLAGS_MIPSEL  = $(COMMON_CFLAGS) -march=mips32r2 -mtune=1004kc -EL -msoft-float \
                 -mno-check-zero-division -mno-shared -mno-plt
CFLAGS_MIPS    = $(COMMON_CFLAGS) -march=mips32r2 -mtune=1004kc -msoft-float \
                 -mno-check-zero-division -mno-shared -mno-plt
CFLAGS_AARCH64 = $(COMMON_CFLAGS) -march=armv8-a \
                 -mno-outline-atomics -fno-exceptions
CFLAGS_NATIVE  = $(COMMON_CFLAGS)

LDFLAGS_STATIC  = $(COMMON_LDFLAGS) -static -static-libgcc
LDFLAGS_MIPS    = $(LDFLAGS_STATIC) -no-pie
LDFLAGS_AARCH64 = $(LDFLAGS_STATIC) -no-pie -Wl,-z,norelro
LDFLAGS_DYNAMIC = $(COMMON_LDFLAGS)

LIBS =

FUZZ_SRCS = tests/fuzz.c src/l7_dispatch.c src/probe_quic.c src/probe_tls.c src/probe_http.c \
            src/quic_crypto.c src/tcp_reasm.c src/bogon.c src/dns.c src/util.c src/log.c
FUZZ_ITERS      ?= 200000
FUZZ_QEMU_ITERS ?= 30000
FUZZ_SEED       ?= 1

SRCS = src/main.c src/util.c src/log.c src/config.c src/args.c src/params.c src/watchlist.c src/ipset_nl.c src/dns.c src/packet_capture.c src/iptables.c src/signal_handler.c src/rci.c src/conntrack.c src/geodat.c src/routing.c src/probe_tls.c src/probe_http.c src/probe_quic.c src/quic_crypto.c src/bogon.c src/nflog_capture.c src/l7_dispatch.c src/l7_firewall.c src/tcp_reasm.c src/watchlist_api.c

.PHONY: all clean mipsel mips aarch64 native check fuzz

all: mipsel mips aarch64

mipsel: CC = $(CC_MIPSEL)
mipsel: CFLAGS = $(CFLAGS_MIPSEL)
mipsel: LDFLAGS = $(LDFLAGS_MIPS)
mipsel: build/$(PROJECT)-mipsel

mips: CC = $(CC_MIPS)
mips: CFLAGS = $(CFLAGS_MIPS)
mips: LDFLAGS = $(LDFLAGS_MIPS)
mips: build/$(PROJECT)-mips

aarch64: CC = $(CC_AARCH64)
aarch64: CFLAGS = $(CFLAGS_AARCH64)
aarch64: LDFLAGS = $(LDFLAGS_AARCH64)
aarch64: build/$(PROJECT)-aarch64

native: CC = $(CC_NATIVE)
native: CFLAGS = $(CFLAGS_NATIVE)
native: LDFLAGS = $(LDFLAGS_DYNAMIC)
native: build/$(PROJECT)

build/$(PROJECT): $(SRCS) Makefile
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS) $(LIBS)

build/$(PROJECT)-mipsel: $(SRCS) Makefile
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS) $(LIBS)

build/$(PROJECT)-mips: $(SRCS) Makefile
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS) $(LIBS)

build/$(PROJECT)-aarch64: $(SRCS) Makefile
	@mkdir -p build
	$(CC) $(CFLAGS) $(SRCS) -o $@ $(LDFLAGS) $(LIBS)

check:
	@mkdir -p build
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_nf.c src/l7_firewall.c src/util.c src/log.c -o build/check_nf
	./build/check_nf
	$(CC_NATIVE) $(CFLAGS_NATIVE) -Wl,--wrap=run_command_output,--wrap=run_command_stdin,--wrap=load_kmod tests/check_connmark.c src/iptables.c src/l7_firewall.c src/util.c src/log.c -o build/check_connmark
	./build/check_connmark
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_rci.c src/util.c src/log.c src/config.c src/params.c -o build/check_rci
	./build/check_rci
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_config.c src/config.c src/params.c src/util.c src/log.c -o build/check_config
	./build/check_config
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_watchlist.c src/watchlist.c src/util.c src/log.c -o build/check_watchlist
	./build/check_watchlist
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_wlapi.c src/watchlist_api.c src/watchlist.c src/util.c src/log.c -o build/check_wlapi
	./build/check_wlapi
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_routing.c src/routing.c src/watchlist.c src/util.c src/log.c -o build/check_routing
	./build/check_routing
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_geodat.c src/geodat.c src/ipset_nl.c src/watchlist.c src/util.c src/log.c -o build/check_geodat
	./build/check_geodat
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_l7.c src/l7_dispatch.c src/probe_quic.c src/probe_tls.c src/probe_http.c src/quic_crypto.c src/tcp_reasm.c src/bogon.c -o build/check_l7
	./build/check_l7
	$(CC_NATIVE) $(CFLAGS_NATIVE) -Wl,--wrap=send,--wrap=recv,--wrap=clock_gettime tests/check_ipset.c src/ipset_nl.c src/util.c src/log.c -o build/check_ipset
	./build/check_ipset
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_dns.c src/dns.c src/util.c src/log.c -o build/check_dns
	./build/check_dns
	$(CC_NATIVE) $(CFLAGS_NATIVE) -Wl,--wrap=send,--wrap=recv tests/check_conntrack.c src/conntrack.c src/util.c src/log.c -o build/check_conntrack
	./build/check_conntrack
	$(CC_NATIVE) $(CFLAGS_NATIVE) -Wl,--wrap=socket,--wrap=bind,--wrap=sendto,--wrap=recv tests/check_nflog.c src/nflog_capture.c src/util.c src/log.c -o build/check_nflog
	./build/check_nflog
	$(CC_NATIVE) $(CFLAGS_NATIVE) -DCHILD_DEADLINE_MS=300 tests/check_spawn.c src/util.c src/log.c -o build/check_spawn
	./build/check_spawn

fuzz:
	@mkdir -p build
	$(CC_NATIVE) -O1 -g -Wall -Wextra -Wno-unused-parameter -Iinclude -fsanitize=address,undefined -fno-sanitize-recover=all $(FUZZ_SRCS) -o build/fuzz-asan
	./build/fuzz-asan $(FUZZ_ITERS) $(FUZZ_SEED)
	$(CC_MIPSEL) $(CFLAGS_MIPSEL) $(FUZZ_SRCS) -o build/fuzz-mipsel $(LDFLAGS_MIPS)
	qemu-mipsel-static build/fuzz-mipsel $(FUZZ_QEMU_ITERS) $(FUZZ_SEED)
	$(CC_MIPS) $(CFLAGS_MIPS) $(FUZZ_SRCS) -o build/fuzz-mips $(LDFLAGS_MIPS)
	qemu-mips-static build/fuzz-mips $(FUZZ_QEMU_ITERS) $(FUZZ_SEED)
	$(CC_AARCH64) $(CFLAGS_AARCH64) $(FUZZ_SRCS) -o build/fuzz-aarch64 $(LDFLAGS_AARCH64)
	qemu-aarch64-static build/fuzz-aarch64 $(FUZZ_QEMU_ITERS) $(FUZZ_SEED)

clean:
	rm -rf build/
