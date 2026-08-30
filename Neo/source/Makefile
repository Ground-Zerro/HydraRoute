PROJECT = hrneo
VERSION = 3.18.3-1

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

SRCS = src/main.c src/util.c src/log.c src/config.c src/args.c src/params.c src/watchlist.c src/ipset_nl.c src/dns.c src/packet_capture.c src/iptables.c src/signal_handler.c src/rci.c src/conntrack.c src/geodat.c src/routing.c src/probe_tls.c src/probe_http.c src/probe_quic.c src/quic_crypto.c src/bogon.c src/nflog_capture.c src/l7_dispatch.c src/l7_firewall.c src/tcp_reasm.c

.PHONY: all clean mipsel mips aarch64 native check

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
	$(CC_NATIVE) $(CFLAGS_NATIVE) tests/check_rci.c src/util.c src/log.c src/config.c src/params.c -o build/check_rci
	./build/check_rci

clean:
	rm -rf build/
