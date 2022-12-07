include $(top_srcdir)/Make_global.am

noinst_PROGRAMS = tcpoptim

# Until we build tfo_wrapper
EXTRA_DIST	= tfo_wrapper.c

# TESTS = $(check_PROGRAMS)

tcpoptim_SOURCES = tcpoptim.c
# tcpoptim_LDADD = ../lib/.libs/libtfo.a
# tcpoptim_CPPFLAGS = -I.
tcpoptim_LDFLAGS = ../lib/.libs/libtfo.a $(dpdk_LIBS) -lev -pthread

# LDFLAGS_SHARED = $(shell $(PKGCONF) --libs libdpdk) -lev -pthread
# LDFLAGS_STATIC = $(shell $(PKGCONF) --static --libs libdpdk) -lev -pthread

clean-local:
	@rm -rf .deps
