include $(top_srcdir)/Make_global.am

lib_LTLIBRARIES = libtfo.la

# libtfo_la_LIBADD = ${LIBMNL_LIBS}
libtfo_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libtfo.map	\
		      -version-info $(LIBVERSION)

libtfo_la_SOURCES = linux_rbtree.c \
		      tcp_process.c \
		      tfo_printf.c \
		      tfo_worker.c \
		      win_minmax.c \
		      libtfo.map

clean-local:
	@rm -rf .deps
