# SPDX-License-Identifier: GPL-3.0-only
# Copyright(c) 2022 P Quentin Armitage <quentin@armitage.org.uk>

# binary name
APP = tcpoptim

# all source are stored in SRCS-y
SRCS-y := tcpoptim.c tcp_process.c tfo_worker.c \
	  tcp_process.h tfo.h tfo_worker.h \
	  linux_jhash.h linux_list.h \
	  util.h

PKGCONF ?= pkg-config

# Build using pkg-config variables if possible
ifneq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
$(error "no installation of DPDK found")
endif

all: shared
.PHONY: shared static
shared: build/$(APP)-shared
	ln -sf $(APP)-shared build/$(APP)
static: build/$(APP)-static
	ln -sf $(APP)-static build/$(APP)

PC_FILE := $(shell $(PKGCONF) --path libdpdk 2>/dev/null)
WARNINGS = -Wall -Wextra -Wunused -Wstrict-prototypes -Wabsolute-value -Waddress-of-packed-member -Walloca \
	   -Walloc-zero -Warith-conversion -Warray-bounds=2 -Wattribute-alias=2 -Wbad-function-cast \
	   -Wc11-c2x-compat -Wcast-align -Wcast-qual -Wdate-time -Wdisabled-optimization -Wdouble-promotion \
	   -Wduplicated-branches -Wduplicated-cond -Wfloat-conversion -Wfloat-equal -Wformat-overflow \
	   -Wformat-signedness -Wformat-truncation -Wframe-larger-than=5120 -Wimplicit-fallthrough=3 \
	   -Winit-self -Winline -Winvalid-pch -Wjump-misses-init -Wlogical-op -Wmissing-declarations \
	   -Wmissing-field-initializers -Wmissing-include-dirs -Wmissing-prototypes -Wnested-externs \
	   -Wnormalized -Wnull-dereference -Wold-style-definition -Woverlength-strings -Wpointer-arith \
	   -Wredundant-decls -Wshadow -Wshift-overflow=2 -Wstack-protector -Wstrict-overflow=4 \
	   -Wstringop-overflow=2 -Wstringop-truncation -Wsuggest-attribute=cold -Wsuggest-attribute=const \
	   -Wsuggest-attribute=format -Wsuggest-attribute=malloc -Wsuggest-attribute=noreturn \
	   -Wsuggest-attribute=pure -Wsync-nand -Wtrampolines -Wundef -Wuninitialized -Wunknown-pragmas \
	   -Wunsafe-loop-optimizations -Wunsuffixed-float-constants -Wunused-const-variable=2 \
	   -Wvariadic-macros -Wwrite-strings -fPIE -Wformat -Werror=format-security
CFLAGS += -O0 -g $(shell $(PKGCONF) --cflags libdpdk) -Wunused -Wstrict-prototypes -Wall -Wextra # $(WARNINGS)
LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk) -lev
LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk) -lev

ifeq ($(MAKECMDGOALS),static)
# check for broken pkg-config
ifeq ($(shell echo $(LDFLAGS_STATIC) | grep 'whole-archive.*l:lib.*no-whole-archive'),)
$(warning "pkg-config output list does not contain drivers between 'whole-archive'/'no-whole-archive' flags.")
$(error "Cannot generate statically-linked binaries with this version of pkg-config")
endif
endif

CFLAGS += -DALLOW_EXPERIMENTAL_API

build/$(APP)-shared: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_SHARED)

build/$(APP)-static: $(SRCS-y) Makefile $(PC_FILE) | build
	$(CC) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS) $(LDFLAGS_STATIC)

build:
	@mkdir -p $@

.PHONY: clean
clean:
	rm -f build/$(APP) build/$(APP)-static build/$(APP)-shared
	test -d build && rmdir -p build || true
