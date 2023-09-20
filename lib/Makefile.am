include $(top_srcdir)/Make_global.am

lib_LTLIBRARIES = libtfo.la

libtfo_la_LDFLAGS = -Wl,--version-script=$(srcdir)/libtfo.map	\
		      -version-info $(LIBVERSION)

libtfo_la_SOURCES =	linux_rbtree.c \
			tcp_process.c \
			tfo_debug.c \
			tfo_worker.c \
			win_minmax.c \
			libtfo.map.in

libtfo_la_LIBADD	=
EXTRA_libtfo_la_SOURCES =

if TFO_PRINTF
  libtfo_la_LIBADD	  += tfo_printf.lo
  EXTRA_libtfo_la_SOURCES += tfo_printf.c
endif

libtfo.map:	libtfo.map.in

clean-local:
	@rm -rf .deps
