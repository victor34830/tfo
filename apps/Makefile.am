include $(top_srcdir)/Make_global.am

noinst_PROGRAMS = tcpoptim tcpoptim_static

# Until we build tfo_wrapper
EXTRA_DIST	= tfo_wrapper.c

tcpoptim_SOURCES = tcpoptim.c
tcpoptim_LDFLAGS = -L../lib/.libs -ltfo $(dpdk_LIBS) -lev -pthread -lnuma

tcpoptim_static_SOURCES = tcpoptim.c
tcpoptim_static_LDFLAGS = ../lib/.libs/libtfo.a $(dpdk_STATIC_LIBS) -lev -pthread -lnuma

EXTRA_tcpoptim_DEPENDENCIES = ../lib/.libs/libtfo.so.0.0.0

EXTRA_tcpoptim_static_DEPENDENCIES = ../lib/.libs/libtfo.a

clean-local:
	@rm -rf .deps
