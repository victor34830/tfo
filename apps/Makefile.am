include $(top_srcdir)/Make_global.am

noinst_PROGRAMS = tcpoptim tcpoptim_static

# Until we build tfo_wrapper
EXTRA_DIST	= tfo_wrapper.c

tcpoptim_SOURCES = tcpoptim.c
tcpoptim_LDFLAGS = -L../lib/.libs -ltfo $(dpdk_LIBS) -lev -pthread

tcpoptim_static_SOURCES = tcpoptim.c
tcpoptim_static_LDFLAGS = ../lib/.libs/libtfo.a $(dpdk_STATIC_LIBS) -lev -pthread

clean-local:
	@rm -rf .deps
