/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright(c) 2022 P Quentin Armitage <quentin@armitage.org.uk>
 */

/*
** configure.ac for tcp flow optimizer
**
** Author: P Quentin Armitage <quentin@armitage.org.uk>
**
*/

dnl Process this file with autoconf to create configure.

AC_DEFUN([add_to_var], [$1="$$1 $2"])
AC_DEFUN([add_to_var_ind], [eval $1=\"\$$1 $2\"]) dnl "

AC_DEFUN([add_config_opt], [add_to_var([CONFIG_OPTIONS], [$1])])

AC_DEFUN([add_system_opt], [add_to_var([SYSTEM_OPTIONS], [$1])])

AC_PREREQ[2.63])
AC_INIT([libtfo], [1.0.0], [quentin@armitage.org.uk], [], [https://github.com/pqarmitage/tfo])
AC_CONFIG_AUX_DIR([build-aux])
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([include/tfo_config.h include/tfo_options.h apps/tfo_app_config.h])
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_CONFIG_FILES([lib/libtfo.map])

AM_INIT_AUTOMAKE([-Wall -Werror -Woverride foreign tar-pax no-dist-gzip dist-bzip2
	1.6 subdir-objects])

AH_TOP(
  [
#ifndef TFO_CONFIG_H_
#define TFO_CONFIG_H_
  ])
AH_BOTTOM(
  [

#endif])

dnl kernel style compile messages
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl Dependencies
AC_PROG_CC
AM_PROG_CC_C_O
AC_EXEEXT
PKG_PROG_PKG_CONFIG
# AC_DISABLE_STATIC
LT_INIT
# CHECK_GCC_FVISIBILITY
case "$host" in
*-*-linux* | *-*-uclinux*) ;;
*) AC_MSG_ERROR([Linux only]);;
esac

MAINTAINERCLEANFILES="*~ *.orig *.rej core core.*"
AC_SUBST(MAINTAINERCLEANFILES)
CONFIG_OPTIONS=
SYSTEM_OPTIONS=
CONFIG_DEFAULTS_FILE=tfo_options.default
CC_OPTIMIZATION=-O2

regular_CPPFLAGS="-D_FILE_OFFSET_BITS=64 -D_REENTRANT"

regular_CFLAGS="-Wall -Waggregate-return -Wmissing-declarations \
	-Wmissing-prototypes -Wshadow -Wstrict-prototypes \
	-Wformat=2 -Wwrite-strings -pipe -fvisibility=hidden"
WARNINGS=" \
	-Wall -Wextra -Wunused -Wstrict-prototypes -Wabsolute-value -Waddress-of-packed-member -Walloca \
	-Walloc-zero -Warith-conversion -Warray-bounds=2 -Wattribute-alias=2 -Wbad-function-cast \
	-Wc11-c2x-compat -Wcast-align -Wcast-qual -Wdate-time -Wdisabled-optimization -Wdouble-promotion \
	-Wduplicated-branches -Wduplicated-cond -Wfloat-conversion -Wfloat-equal -Wformat-overflow \
	-Wformat-signedness -Wformat-truncation -Wframe-larger-than=12000 -Wimplicit-fallthrough=3 \
	-Winit-self -Winvalid-pch -Wjump-misses-init -Wlogical-op -Wmissing-declarations \
	-Wmissing-field-initializers -Wmissing-include-dirs -Wmissing-prototypes -Wnested-externs \
	-Wnormalized -Wnull-dereference -Wold-style-definition -Woverlength-strings -Wpointer-arith \
	-Wredundant-decls -Wshadow -Wshift-overflow=2 -Wstack-protector -Wstrict-overflow=4 \
	-Wstringop-overflow=2 -Wstringop-truncation -Wsuggest-attribute=cold -Wsuggest-attribute=const \
	-Wsuggest-attribute=format -Wsuggest-attribute=malloc -Wsuggest-attribute=noreturn \
	-Wsuggest-attribute=pure -Wsync-nand -Wtrampolines -Wundef -Wuninitialized -Wunknown-pragmas \
	-Wunsafe-loop-optimizations -Wunsuffixed-float-constants -Wunused-const-variable=1 \
	-Wvariadic-macros -Wwrite-strings -fPIE -Wformat -Werror=format-security"

# The DPDK headers produce a large number of the following warnings"
#EXTRA_WARNINGS="-Winline -Wunused-const-variable=2 -Wframe-larger-than=5120"
INLINE_ALLOWANCE="-finline-limit=1000 --param large-stack-frame-growth=1500 --param inline-unit-growth=100"
#DEBUG_CPPFLAGS="-DNO_DEBUG"

regular_LDFLAGS=
regular_CPPFLAGS="$regular_CPPFLAGS -DALLOW_EXPERIMENTAL_API -DPQA"
regular_CFLAGS="$regular_CFLAGS ${DEBUG_CPPFLAGS} ${INLINE_ALLOWANCE} -fno-strict-aliasing ${WARNINGS} ${EXTRA_WARNINGS} ${CLAGS_EXTRA}"

regular_CPPFLAGS="-I\${top_srcdir}/include ${regular_CPPFLAGS} ${DEBUG_CPPFLAGS}"

regular_LIBS="-lev -lpthread"

# Get the library flags needed for DPDK
DPDK_PATH=$(grep -v "#" /etc/ld.so.conf.d/dpdk.conf | sed -e "s:/$::")
PATH_NO_DPDK=$(echo $PATH | sed -e "s/:[^:]%dpdk[^:]*:/:/" -e "s/:[^:]*dpdk[^:]*$//")

export PKG_CONFIG_PATH=$DPDK_PATH/pkgconfig
export PATH=$PATH_NO_DPDK:${DPDK_PATH%/lib64}/bin

dpdk_LDFLAGS=
dpdk_LIBS=$($PKG_CONFIG --libs libdpdk)
dpdk_STATIC_LIBS=$($PKG_CONFIG --static --libs libdpdk)
dpdk_CPPFLAGS=$($PKG_CONFIG --cflags-only-I libdpdk | sed -e "s:-I/usr/usr/include::")
dpdk_CFLAGS=$($PKG_CONFIG --cflags-only-other libdpdk)

AC_SUBST([dpdk_CPPFLAGS])
AC_SUBST([dpdk_CFLAGS])
AC_SUBST([dpdk_LIBS])
AC_SUBST([dpdk_STATIC_LIBS])

AC_SUBST([regular_CPPFLAGS])
AC_SUBST([regular_CFLAGS])
AC_SUBST([regular_LIBS])

# AC_CONFIG_FILES([Makefile lib/Makefile include/Makefile include/libnftnl/Makefile include/linux/Makefile include/linux/netfilter/Makefile examples/Makefile apps/Makefile libnftnl.pc doxygen.cfg])
AC_CONFIG_FILES([Makefile lib/Makefile include/Makefile apps/Makefile libtfo.pc])

# Set up help for configurable options

# Specify the file for configuration defaults
AC_ARG_WITH(config-file,
	      [AS_HELP_STRING([--with-config-file], [file containing configuration defaults (default tfo_options.default)])])

# Compiler and linker options
AC_ARG_ENABLE(lto,
	      [AS_HELP_STRING([--enable-lto], [enable link time optimisation])],
	      [regular_CFLAGS="${regular_CFLAGS} -flto=auto -ffat-lto-objects"])
AC_ARG_ENABLE(debug-symbols,
	      [AS_HELP_STRING([--enable-debug-symbols], [include gcc -g -Og flags])],
	      [CC_OPTIMIZATION="-Og -g"])
AC_ARG_WITH(optimization,
	      [AS_HELP_STRING([--with-optimization=n], [specify gcc -On optimizaation level (default O2)])],
	      [CC_OPTIMIZATION="-O${withval}"])

# App and library
AC_ARG_ENABLE(debug-print-to-buf,
	      [AS_HELP_STRING([--enable-debug-print-to-buf], [enable print to buf debug])])
AC_ARG_ENABLE(debug-check-pkts,
	      [AS_HELP_STRING([--enable-debug-check-pkts], [check queued packets before and after each send and receive])])

# Library only functionality
AC_ARG_ENABLE(calc-ts-clock,
	      [AS_HELP_STRING([--disable-calc-ts-clock], [dont calculate timestamp clock rate])])
AC_ARG_ENABLE(cwnd-alternate,
	      [AS_HELP_STRING([--enable-cwnd-alternate], [alternative CWND calculation])])
AC_ARG_ENABLE(detect-loss-min,
	      [AS_HELP_STRING([--enable-detect-loss-min], [enable detect loss min])])
AC_ARG_ENABLE(eflow-dump,
	      [AS_HELP_STRING([--enable-eflow-dump], [enable writing eflow state to stream])])
AC_ARG_ENABLE(do-quickack,
	      [AS_HELP_STRING([--enable-do-quickack], [enable do quickack])])
AC_ARG_ENABLE(have-duplicate-mbuf-bug,
	      [AS_HELP_STRING([--enable-have-duplicate-mbuf-bug], [enable have duplicate mbuf bug])])
AC_ARG_ENABLE(receive-window-allow-max,
	      [AS_HELP_STRING([--enable-receive-window-allow-max], [enable receive window allow max])])
AC_ARG_ENABLE(receive-window-mss-mult,
	      [AS_HELP_STRING([--enable-receive-window-mss-mult=nn], [set receive window mss mult = nn])])
AC_ARG_ENABLE(release-sacked-packets,
	      [AS_HELP_STRING([--enable-release-sacked-packets], [enable release sacked packets])])
AC_ARG_ENABLE(write-pcap,
	      [AS_HELP_STRING([--enable-write-pcap], [enable write pcap])])

# Library debug options
AC_ARG_ENABLE(debug-ack,
	      [AS_HELP_STRING([--enable-debug-ack], [enable ack debug])])
AC_ARG_ENABLE(debug-ack-mempool,
	      [AS_HELP_STRING([--enable-debug-ack-mempool], [enable ack mempool debug])])
AC_ARG_ENABLE(debug-ack-mempool-init,
	      [AS_HELP_STRING([--enable-debug-ack-mempool-init], [enable ack mempool init debug])])
AC_ARG_ENABLE(debug-ack-pkt-list,
	      [AS_HELP_STRING([--enable-debug-ack-pkt-list], [enable ack pkt list debug])])
AC_ARG_ENABLE(debug-burst,
	      [AS_HELP_STRING([--enable-debug-burst], [enable burst debug])])
AC_ARG_ENABLE(debug-check-addr,
	      [AS_HELP_STRING([--enable-debug-check-addr], [enable check addr debug])])
AC_ARG_ENABLE(debug-checksum,
	      [AS_HELP_STRING([--enable-debug-checksum], [enable checksum debug])])
AC_ARG_ENABLE(debug-checksum-detail,
	      [AS_HELP_STRING([--enable-debug-checksum-detail], [enable checksum detail debug])])
AC_ARG_ENABLE(debug-config,
	      [AS_HELP_STRING([--enable-debug-config], [enable config debug])])
AC_ARG_ENABLE(debug-delayed-ack,
	      [AS_HELP_STRING([--enable-debug-delayed-ack], [enable delayed ack debug])])
AC_ARG_ENABLE(debug-disable-sack,
	      [AS_HELP_STRING([--enable-debug-disable-sack], [enable disable sack debug])])
AC_ARG_ENABLE(debug-disable-ts,
	      [AS_HELP_STRING([--enable-debug-disable-ts], [enable disable ts debug])])
AC_ARG_ENABLE(debug-dlspeed,
	      [AS_HELP_STRING([--enable-debug-dlspeed], [enable dlspeed debug])])
AC_ARG_ENABLE(debug-dlspeed-debug,
	      [AS_HELP_STRING([--enable-debug-dlspeed-debug], [enable dlspeed debug debug])])
AC_ARG_ENABLE(debug-duplicate-mbufs,
	      [AS_HELP_STRING([--enable-debug-duplicate-mbufs], [enable duplicate mbufs debug])])
AC_ARG_ENABLE(debug-dup-sack-send,
	      [AS_HELP_STRING([--enable-debug-dup-sack-send], [enable dup sack send debug])])
AC_ARG_ENABLE(debug-empty-packets,
	      [AS_HELP_STRING([--enable-debug-empty-packets], [enable empty packets debug])])
AC_ARG_ENABLE(debug-ethdev,
	      [AS_HELP_STRING([--enable-debug-ethdev], [enable ethdev debug])])
AC_ARG_ENABLE(debug-fin,
	      [AS_HELP_STRING([--enable-debug-fin], [enable fin debug])])
AC_ARG_ENABLE(debug-flow,
	      [AS_HELP_STRING([--enable-debug-flow], [enable flow debug])])
AC_ARG_ENABLE(debug-fwd-freed-pkt,
	      [AS_HELP_STRING([--enable-debug-fwd-freed-pkt], [enable fwd freed pkt debug])])
AC_ARG_ENABLE(debug-in-flight,
	      [AS_HELP_STRING([--enable-debug-in-flight], [enable in flight debug])])
AC_ARG_ENABLE(debug-keepalives,
	      [AS_HELP_STRING([--enable-debug-keepalives], [enable keepalives debug])])
AC_ARG_ENABLE(debug-last-sent,
	      [AS_HELP_STRING([--enable-debug-last-sent], [enable last sent debug])])
AC_ARG_ENABLE(debug-mbuf-cookies,
	      [AS_HELP_STRING([--enable-debug-mbuf-cookies], [enable mbuf cookies debug])])
AC_ARG_ENABLE(debug-mem,
	      [AS_HELP_STRING([--enable-debug-mem], [enable mem debug])])
AC_ARG_ENABLE(debug-mempool,
	      [AS_HELP_STRING([--enable-debug-mempool], [enable mempool debug])])
AC_ARG_ENABLE(debug-mempool-init,
	      [AS_HELP_STRING([--enable-debug-mempool-init], [enable mempool init debug])])
AC_ARG_ENABLE(debug-no-mbuf,
	      [AS_HELP_STRING([--enable-debug-no-mbuf], [enable no mbuf debug])])
AC_ARG_ENABLE(debug-optimize,
	      [AS_HELP_STRING([--enable-debug-optimize], [enable optimize debug])])
AC_ARG_ENABLE(debug-packet-overlap,
	      [AS_HELP_STRING([--enable-debug-packet-overlap], [enable packet overlap debug])])
AC_ARG_ENABLE(debug-packet-pool,
	      [AS_HELP_STRING([--enable-debug-packet-pool], [enable packet pool debug])])
AC_ARG_ENABLE(debug-pcap-mempool,
	      [AS_HELP_STRING([--enable-debug-pcap-mempool], [enable pcap mempool debug])])
AC_ARG_ENABLE(debug-pkt-delays,
	      [AS_HELP_STRING([--enable-debug-pkt-delays], [enable pkt delays debug])])
AC_ARG_ENABLE(debug-pkt-num,
	      [AS_HELP_STRING([--enable-debug-pkt-num], [enable pkt num debug])])
AC_ARG_ENABLE(debug-pkt-ptrs,
	      [AS_HELP_STRING([--enable-debug-pkt-ptrs], [enable pkt ptrs debug])])
AC_ARG_ENABLE(debug-pkt-refcnt,
	      [AS_HELP_STRING([--enable-debug-pkt-refcnt], [enable pkt refcnt debug])])
AC_ARG_ENABLE(debug-pkt-rx,
	      [AS_HELP_STRING([--enable-debug-pkt-rx], [enable pkt rx debug])])
AC_ARG_ENABLE(debug-pkts,
	      [AS_HELP_STRING([--enable-debug-pkts], [enable pkts debug])])
AC_ARG_ENABLE(debug-pkt-sanity,
	      [AS_HELP_STRING([--enable-debug-pkt-sanity], [enable pkt sanity debug])])
AC_ARG_ENABLE(debug-pkt-types,
	      [AS_HELP_STRING([--enable-debug-pkt-types], [enable pkt types debug])])
AC_ARG_ENABLE(debug-pkt-valid,
	      [AS_HELP_STRING([--enable-debug-pkt-valid], [enable pkt valid debug])])
AC_ARG_ENABLE(debug-postprocess,
	      [AS_HELP_STRING([--enable-debug-postprocess], [enable postprocess debug])])
AC_ARG_ENABLE(debug-process-pkt-info,
	      [AS_HELP_STRING([--enable-debug-process-pkt-info], [enable process pkt info debug])])
AC_ARG_ENABLE(debug-queued,
	      [AS_HELP_STRING([--enable-debug-queued], [enable queued debug])])
AC_ARG_ENABLE(debug-queue-pkts,
	      [AS_HELP_STRING([--enable-debug-queue-pkts], [enable queue pkts debug])])
AC_ARG_ENABLE(debug-rack,
	      [AS_HELP_STRING([--enable-debug-rack], [enable rack debug])])
AC_ARG_ENABLE(debug-rack-loss,
	      [AS_HELP_STRING([--enable-debug-rack-loss], [enable rack loss debug])])
AC_ARG_ENABLE(debug-rack-sacked,
	      [AS_HELP_STRING([--enable-debug-rack-sacked], [enable rack sacked debug])])
AC_ARG_ENABLE(debug-rcv-win,
	      [AS_HELP_STRING([--enable-debug-rcv-win], [enable rcv win debug])])
AC_ARG_ENABLE(debug-recovery,
	      [AS_HELP_STRING([--enable-debug-recovery], [enable recovery debug])])
AC_ARG_ENABLE(debug-relative-seq,
	      [AS_HELP_STRING([--enable-debug-relative-seq], [enable relative seq debug])])
AC_ARG_ENABLE(debug-remove-tx-pkt,
	      [AS_HELP_STRING([--enable-debug-remove-tx-pkt], [enable remove tx pkt debug])])
AC_ARG_ENABLE(debug-resend-failed-packets,
	      [AS_HELP_STRING([--enable-debug-resend-failed-packets], [enable resend failed packets debug])])
AC_ARG_ENABLE(debug-rfc5681,
	      [AS_HELP_STRING([--enable-debug-rfc5681], [enable rfc5681 debug])])
AC_ARG_ENABLE(debug-rst,
	      [AS_HELP_STRING([--enable-debug-rst], [enable rst debug])])
AC_ARG_ENABLE(debug-rto,
	      [AS_HELP_STRING([--enable-debug-rto], [enable rto debug])])
AC_ARG_ENABLE(debug-rtt-min,
	      [AS_HELP_STRING([--enable-debug-rtt-min], [enable rtt min debug])])
AC_ARG_ENABLE(debug-rx-pkts,
	      [AS_HELP_STRING([--enable-debug-rx-pkts], [enable rx pkts debug])])
AC_ARG_ENABLE(debug-sack-rx,
	      [AS_HELP_STRING([--enable-debug-sack-rx], [enable sack rx debug])])
AC_ARG_ENABLE(debug-sack-send,
	      [AS_HELP_STRING([--enable-debug-sack-send], [enable sack send debug])])
AC_ARG_ENABLE(debug-sack-verify,
	      [AS_HELP_STRING([--enable-debug-sack-verify], [enable sack verify debug])])
AC_ARG_ENABLE(debug-send-burst,
	      [AS_HELP_STRING([--enable-debug-send-burst], [enable send burst debug])])
AC_ARG_ENABLE(debug-send-burst-errors,
	      [AS_HELP_STRING([--enable-debug-send-burst-errors], [enable send burst errors debug])])
AC_ARG_ENABLE(debug-send-burst-not-sent,
	      [AS_HELP_STRING([--enable-debug-send-burst-not-sent], [enable send burst not sent debug])])
AC_ARG_ENABLE(debug-send-dsack-check,
	      [AS_HELP_STRING([--enable-debug-send-dsack-check], [enable send dsack check debug])])
AC_ARG_ENABLE(debug-send-pkt,
	      [AS_HELP_STRING([--enable-debug-send-pkt], [enable send pkt debug])])
AC_ARG_ENABLE(debug-send-pkt-location,
	      [AS_HELP_STRING([--enable-debug-send-pkt-location], [enable send pkt location debug])])
AC_ARG_ENABLE(debug-send-probe,
	      [AS_HELP_STRING([--enable-debug-send-probe], [enable send probe debug])])
AC_ARG_ENABLE(debug-sm,
	      [AS_HELP_STRING([--enable-debug-sm], [enable sm debug])])
AC_ARG_ENABLE(debug-snd-nxt,
	      [AS_HELP_STRING([--enable-debug-snd-nxt], [enable snd nxt debug])])
AC_ARG_ENABLE(debug-structures,
	      [AS_HELP_STRING([--enable-debug-structures], [enable structures debug])])
AC_ARG_ENABLE(debug-supported-pkt-types,
	      [AS_HELP_STRING([--enable-debug-supported-pkt-types], [enable supported pkt types debug])])
AC_ARG_ENABLE(debug-tcp-opt,
	      [AS_HELP_STRING([--enable-debug-tcp-opt], [enable tcp opt debug])])
AC_ARG_ENABLE(debug-tcp-window,
	      [AS_HELP_STRING([--enable-debug-tcp-window], [enable tcp window debug])])
AC_ARG_ENABLE(debug-timers,
	      [AS_HELP_STRING([--enable-debug-timers], [enable timers debug])])
AC_ARG_ENABLE(debug-ts-speed,
	      [AS_HELP_STRING([--enable-debug-ts-speed], [enable ts speed debug])])
AC_ARG_ENABLE(debug-tx-bufs,
	      [AS_HELP_STRING([--enable-debug-tx-bufs], [enable tx bufs debug])])
AC_ARG_ENABLE(debug-users-tx-clock,
	      [AS_HELP_STRING([--enable-debug-users-tx-clock], [enable users tx clock debug])])
AC_ARG_ENABLE(debug-valid-options,
	      [AS_HELP_STRING([--enable-debug-valid-options], [enable valid options debug])])
AC_ARG_ENABLE(debug-vlan,
	      [AS_HELP_STRING([--enable-debug-vlan], [enable vlan debug])])
AC_ARG_ENABLE(debug-vlan1,
	      [AS_HELP_STRING([--enable-debug-vlan1], [enable vlan1 debug])])
AC_ARG_ENABLE(debug-vlan-tci,
	      [AS_HELP_STRING([--enable-debug-vlan-tci], [enable vlan tci debug])])
AC_ARG_ENABLE(debug-xmit-list,
	      [AS_HELP_STRING([--enable-debug-xmit-list], [enable xmit list debug])])
AC_ARG_ENABLE(debug-zero-window,
	      [AS_HELP_STRING([--enable-debug-zero-window], [enable zero window debug])])

# App functionality
AC_ARG_ENABLE(app-sends-pkts,
	      [AS_HELP_STRING([--enable-app-sends-pkts], [enable app sends pkts])])
AC_ARG_ENABLE(app-updates-mac-addr,
	      [AS_HELP_STRING([--enable-app-updates-mac-addr], [enable app updates MAC addr])])
AC_ARG_ENABLE(app-updates-vlan,
	      [AS_HELP_STRING([--enable-app-updates-vlan], [enable app updates Vlan])])
AC_ARG_ENABLE(app-vlan-swap,
	      [AS_HELP_STRING([--enable-app-vlan-swap], [enable app Vlan swap])])
AC_ARG_WITH(app-rx-ring-size,
	      [AS_HELP_STRING([--with-app-rx-ring-size=nn], [specify app receive ring size (default 1024)])])
AC_ARG_WITH(app-tx-ring-size,
	      [AS_HELP_STRING([--with-app-tx-ring-size=nn], [specify app transmit ring size (default 1024)])])
AC_ARG_WITH(app-num-mbufs,
	      [AS_HELP_STRING([--with-app-num-mbufs=nn], [specify app number of mbufs (default 8191)])])
AC_ARG_WITH(app-mbuf-cache-size,
	      [AS_HELP_STRING([--with-app-mbuf-cache-size=nn], [specify app size of mbuf cache (default 250)])])
AC_ARG_WITH(app-mbuf-default-burst-size,
	      [AS_HELP_STRING([--with-app-default-burst-size=nn], [specify app default burst size (default 1024)])])
AC_ARG_WITH(app-max-if,
	      [AS_HELP_STRING([--with-app-max-if=nn], [specify app maximum number of interfaces (default 2)])])

# App debug options
AC_ARG_ENABLE(app-clear-rx-bufs,
	      [AS_HELP_STRING([--enable-app-clear-rx-bufs], [enable app clear rx bufs])])
AC_ARG_ENABLE(app-debug-duplicate-mbufs,
	      [AS_HELP_STRING([--enable-app-debug-duplicate-mbufs], [enable app debug duplicate mbufs])])
AC_ARG_ENABLE(app-debug-pkt-details,
	      [AS_HELP_STRING([--enable-app-debug-pkt-details], [enable app debug pkt details])])
AC_ARG_ENABLE(app-debug-pkt-type-unknown,
	      [AS_HELP_STRING([--enable-app-debug-pkt-type-unknown], [enable app debug pkt type unknown])])
AC_ARG_ENABLE(app-fix-duplicate-mbufs,
	      [AS_HELP_STRING([--enable-app-fix-duplicate-mbufs], [enable app fix duplicate mbufs])])
AC_ARG_ENABLE(app-log-actions,
	      [AS_HELP_STRING([--enable-app-log-actions], [enable app log actions])])
AC_ARG_ENABLE(app-log-shutdown,
	      [AS_HELP_STRING([--enable-app-log-shutdown], [enable app log shutdown])])
AC_ARG_ENABLE(app-log-timer-secs,
	      [AS_HELP_STRING([--enable-app-log-timer-secs], [enable app log timer secs])])
AC_ARG_ENABLE(app-log-tx-timer,
	      [AS_HELP_STRING([--enable-app-log-tx-timer], [enable app log tx timer])])

AS_IF([test .$with_config_file != .],
  [
    AS_IF([test -r $with_config_file],
      [CONFIG_DEFAULTS_FILE=$with_config_file],
      [AC_MSG_ERROR([specified config defaults file "$with_config_file" does not exist])])
  ])

# Read and set any default configuration options not specified
opts=$(echo $ac_user_opts)	# convert NL to space
AS_IF([test -f $CONFIG_DEFAULTS_FILE],
  [
    exec 3< $CONFIG_DEFAULTS_FILE
    while read config rest <&3; do
      config=${config###*}
      [[ -z $config ]] && continue

      var=${config%=*}
      val=${config#*=}

      [[[ " $opts " =~ " with_$var " ]]] && conf_var=with_$var || conf_var=enable_$var
      [[[ .${!conf_var} = . ]]] && eval $conf_var=$val
    done

    exec 3<&-
  ])

AS_IF([test .$enable_calc_ts_clock != .no],
  [
    CALC_TS_CLOCK=Yes
    AC_DEFINE([CALC_TS_CLOCK], [ 1 ], [Define to 1 if calculate timestamp clock])
  ],
  [
    CALC_TS_CLOCK=No
    add_config_opt([DISABLE_CALC_TS_CLOCK])
  ])

AS_IF([test .${enable_cwnd_alternate} = .yes],
  [
    CWND_USE_ALTERNATE=Yes
    AC_DEFINE([CWND_USE_ALTERNATE], [ 1 ], [Define to 1 to use alternate CWND calculation])
    add_config_opt([CWND_USE_ALTERNATE])
  ],
  [
    CWND_USE_ALTERNATE=No
  ])

AS_IF([test .${enable_detect_loss_min} = .yes],
  [
    DETECT_LOSS_MIN=Yes
    AC_DEFINE([DETECT_LOSS_MIN], [ 1 ], [Define to 1 to enable detect loss min])
    add_config_opt([DETECT_LOSS_MIN])
  ],
  [DETECT_LOSS_MIN=No])

AS_IF([test .${enable_do_quickack} = .yes],
  [
    DO_QUICKACK=Yes
    AC_DEFINE([DO_QUICKACK], [ 1 ], [Define to 1 to enable do quickack])
    add_config_opt([DO_QUICKACK])
  ],
  [DO_QUICKACK=No])

AS_IF([test .${enable_eflow_dump} = .yes],
  [
    EFLOW_DUMP=Yes
    AC_DEFINE([EXPOSE_EFLOW_DUMP], [ 1 ], [Define to 1 to include make tfo_eflow_dump()])
    add_config_opt([EFLOW_DUMP])
  ],
  [EFLOW_DUMP=No])
AM_CONDITIONAL([EFLOW_DUMP], [test $EFLOW_DUMP = Yes])

AS_IF([test .${enable_have_duplicate_mbuf_bug} = .yes],
  [
    HAVE_DUPLICATE_MBUF_BUG=Yes
    AC_DEFINE([HAVE_DUPLICATE_MBUF_BUG], [ 1 ], [Define to 1 to enable have duplicate mbuf bug])
    add_config_opt([HAVE_DUPLICATE_MBUF_BUG])
  ],
  [HAVE_DUPLICATE_MBUF_BUG=No])

AS_IF([test .${enable_receive_window_allow_max} = .yes],
  [
    RECEIVE_WINDOW_ALLOW_MAX=Yes
    AC_DEFINE([RECEIVE_WINDOW_ALLOW_MAX], [ 1 ], [Define to 1 to enable receive window allow max])
    add_config_opt([RECEIVE_WINDOW_ALLOW_MAX])
  ],
  [RECEIVE_WINDOW_ALLOW_MAX=No])

AS_IF([test .${enable_receive_window_mss_mult} != .],
  [
    RECEIVE_WINDOW_MSS_MULT=Yes
    AC_DEFINE_UNQUOTED([RECEIVE_WINDOW_MSS_MULT], [ ${enable_receive_window_mss_mult} ], [Define to set receive window mss multiplier])
    add_config_opt([RECEIVE_WINDOW_MSS_MULT])
  ],
  [RECEIVE_WINDOW_MSS_MULT=No])

AS_IF([test .${enable_release_sacked_packets} = .yes],
  [
    RELEASE_SACKED_PACKETS=Yes
    AC_DEFINE([RELEASE_SACKED_PACKETS], [ 1 ], [Define to 1 to enable release sacked packets])
    add_config_opt([RELEASE_SACKED_PACKETS])
  ],
  [RELEASE_SACKED_PACKETS=No])

AS_IF([test .${enable_write_pcap} = .yes],
  [
    WRITE_PCAP=Yes
    AC_DEFINE([WRITE_PCAP], [ 1 ], [Define to 1 to enable write pcap])
    add_config_opt([WRITE_PCAP])
  ],
  [WRITE_PCAP=No])

AS_IF([test .${enable_debug_ack} = .yes],
  [
    DEBUG_ACK=Yes
    AC_DEFINE([DEBUG_ACK], [ 1 ], [Define to 1 to enable ack debug])
    add_config_opt([DEBUG_ACK])
  ],
  [DEBUG_ACK=No])

AS_IF([test .${enable_debug_ack_mempool} = .yes],
  [
    DEBUG_ACK_MEMPOOL=Yes
    AC_DEFINE([DEBUG_ACK_MEMPOOL], [ 1 ], [Define to 1 to enable ack mempool debug])
    add_config_opt([DEBUG_ACK_MEMPOOL])
  ],
  [DEBUG_ACK_MEMPOOL=No])

AS_IF([test .${enable_debug_ack_mempool_init} = .yes],
  [
    DEBUG_ACK_MEMPOOL_INIT=Yes
    AC_DEFINE([DEBUG_ACK_MEMPOOL_INIT], [ 1 ], [Define to 1 to enable ack mempool init debug])
    AC_DEFINE([APP_DEBUG_ACK_MEMPOOL_INIT], [ 1 ], [Define to 1 to enable app ack mempool init debug])
    add_config_opt([DEBUG_ACK_MEMPOOL_INIT])
  ],
  [DEBUG_ACK_MEMPOOL_INIT=No])

AS_IF([test .${enable_debug_ack_pkt_list} = .yes],
  [
    DEBUG_ACK_PKT_LIST=Yes
    AC_DEFINE([DEBUG_ACK_PKT_LIST], [ 1 ], [Define to 1 to enable ack pkt list debug])
    add_config_opt([DEBUG_ACK_PKT_LIST])
  ],
  [DEBUG_ACK_PKT_LIST=No])

AS_IF([test .${enable_debug_burst} = .yes],
  [
    DEBUG_BURST=Yes
    AC_DEFINE([DEBUG_BURST], [ 1 ], [Define to 1 to enable burst debug])
    add_config_opt([DEBUG_BURST])
  ],
  [DEBUG_BURST=No])

AS_IF([test .${enable_debug_check_addr} = .yes],
  [
    DEBUG_CHECK_ADDR=Yes
    AC_DEFINE([DEBUG_CHECK_ADDR], [ 1 ], [Define to 1 to enable check addr debug])
    add_config_opt([DEBUG_CHECK_ADDR])
  ],
  [DEBUG_CHECK_ADDR=No])

AS_IF([test .${enable_debug_check_pkts} = .yes],
  [
    DEBUG_CHECK_PKTS=Yes
    AC_DEFINE([DEBUG_CHECK_PKTS], [ 1 ], [Define to 1 to check queued packets before and after each send and receive])
    add_config_opt([DEBUG_CHECK_PKTS])
  ],
  [DEBUG_CHECK_PKTS=No])
AM_CONDITIONAL([CHECK_PKTS], [test $DEBUG_CHECK_PKTS=Yes])

AS_IF([test .${enable_debug_checksum} = .yes],
  [
    DEBUG_CHECKSUM=Yes
    AC_DEFINE([DEBUG_CHECKSUM], [ 1 ], [Define to 1 to enable checksum debug])
    add_config_opt([DEBUG_CHECKSUM])
  ],
  [DEBUG_CHECKSUM=No])

AS_IF([test .${enable_debug_checksum_detail} = .yes],
  [
    DEBUG_CHECKSUM_DETAIL=Yes
    AC_DEFINE([DEBUG_CHECKSUM_DETAIL], [ 1 ], [Define to 1 to enable checksum detail debug])
    add_config_opt([DEBUG_CHECKSUM_DETAIL])
  ],
  [DEBUG_CHECKSUM_DETAIL=No])

AS_IF([test .${enable_debug_config} = .yes],
  [
    DEBUG_CONFIG=Yes
    AC_DEFINE([DEBUG_CONFIG], [ 1 ], [Define to 1 to enable config debug])
    add_config_opt([DEBUG_CONFIG])
  ],
  [DEBUG_CONFIG=No])

AS_IF([test .${enable_debug_delayed_ack} = .yes],
  [
    DEBUG_DELAYED_ACK=Yes
    AC_DEFINE([DEBUG_DELAYED_ACK], [ 1 ], [Define to 1 to enable delayed ack debug])
    add_config_opt([DEBUG_DELAYED_ACK])
  ],
  [DEBUG_DELAYED_ACK=No])

AS_IF([test .${enable_debug_disable_sack} = .yes],
  [
    DEBUG_DISABLE_SACK=Yes
    AC_DEFINE([DEBUG_DISABLE_SACK], [ 1 ], [Define to 1 to enable disable sack debug])
    add_config_opt([DEBUG_DISABLE_SACK])
  ],
  [DEBUG_DISABLE_SACK=No])

AS_IF([test .${enable_debug_disable_ts} = .yes],
  [
    DEBUG_DISABLE_TS=Yes
    AC_DEFINE([DEBUG_DISABLE_TS], [ 1 ], [Define to 1 to enable disable ts debug])
    add_config_opt([DEBUG_DISABLE_TS])
  ],
  [DEBUG_DISABLE_TS=No])

AS_IF([test .${enable_debug_dlspeed} = .yes],
  [
    DEBUG_DLSPEED=Yes
    AC_DEFINE([DEBUG_DLSPEED], [ 1 ], [Define to 1 to enable dlspeed debug])
    add_config_opt([DEBUG_DLSPEED])
  ],
  [DEBUG_DLSPEED=No])

AS_IF([test .${enable_debug_dlspeed_debug} = .yes],
  [
    DEBUG_DLSPEED_DEBUG=Yes
    AC_DEFINE([DEBUG_DLSPEED_DEBUG], [ 1 ], [Define to 1 to enable dlspeed debug debug])
    add_config_opt([DEBUG_DLSPEED_DEBUG])
  ],
  [DEBUG_DLSPEED_DEBUG=No])

AS_IF([test .${enable_debug_duplicate_mbufs} = .yes],
  [
    DEBUG_DUPLICATE_MBUFS=Yes
    AC_DEFINE([DEBUG_DUPLICATE_MBUFS], [ 1 ], [Define to 1 to enable duplicate mbufs debug])
    add_config_opt([DEBUG_DUPLICATE_MBUFS])
  ],
  [DEBUG_DUPLICATE_MBUFS=No])

AS_IF([test .${enable_debug_dup_sack_send} = .yes],
  [
    DEBUG_DUP_SACK_SEND=Yes
    AC_DEFINE([DEBUG_DUP_SACK_SEND], [ 1 ], [Define to 1 to enable dup sack send debug])
    add_config_opt([DEBUG_DUP_SACK_SEND])
  ],
  [DEBUG_DUP_SACK_SEND=No])

AS_IF([test .${enable_debug_empty_packets} = .yes],
  [
    DEBUG_EMPTY_PACKETS=Yes
    AC_DEFINE([DEBUG_EMPTY_PACKETS], [ 1 ], [Define to 1 to enable empty packets debug])
    add_config_opt([DEBUG_EMPTY_PACKETS])
  ],
  [DEBUG_EMPTY_PACKETS=No])

AS_IF([test .${enable_debug_ethdev} = .yes],
  [
    DEBUG_ETHDEV=Yes
    AC_DEFINE([DEBUG_ETHDEV], [ 1 ], [Define to 1 to enable ethdev debug])
    add_config_opt([DEBUG_ETHDEV])
  ],
  [DEBUG_ETHDEV=No])

AS_IF([test .${enable_debug_fin} = .yes],
  [
    DEBUG_FIN=Yes
    AC_DEFINE([DEBUG_FIN], [ 1 ], [Define to 1 to enable fin debug])
    add_config_opt([DEBUG_FIN])
  ],
  [DEBUG_FIN=No])

AS_IF([test .${enable_debug_flow} = .yes],
  [
    DEBUG_FLOW=Yes
    AC_DEFINE([DEBUG_FLOW], [ 1 ], [Define to 1 to enable flow debug])
    add_config_opt([DEBUG_FLOW])
  ],
  [DEBUG_FLOW=No])

AS_IF([test .${enable_debug_fwd_freed_pkt} = .yes],
  [
    DEBUG_FWD_FREED_PKT=Yes
    AC_DEFINE([DEBUG_FWD_FREED_PKT], [ 1 ], [Define to 1 to enable fwd freed pkt debug])
    add_config_opt([DEBUG_FWD_FREED_PKT])
  ],
  [DEBUG_FWD_FREED_PKT=No])

AS_IF([test .${enable_debug_in_flight} = .yes],
  [
    DEBUG_IN_FLIGHT=Yes
    AC_DEFINE([DEBUG_IN_FLIGHT], [ 1 ], [Define to 1 to enable in flight debug])
    add_config_opt([DEBUG_IN_FLIGHT])
  ],
  [DEBUG_IN_FLIGHT=No])

AS_IF([test .${enable_debug_keepalives} = .yes],
  [
    DEBUG_KEEPALIVES=Yes
    AC_DEFINE([DEBUG_KEEPALIVES], [ 1 ], [Define to 1 to enable keepalives debug])
    add_config_opt([DEBUG_KEEPALIVES])
  ],
  [DEBUG_KEEPALIVES=No])

AS_IF([test .${enable_debug_last_sent} = .yes],
  [
    DEBUG_LAST_SENT=Yes
    AC_DEFINE([DEBUG_LAST_SENT], [ 1 ], [Define to 1 to enable last sent debug])
    add_config_opt([DEBUG_LAST_SENT])
  ],
  [DEBUG_LAST_SENT=No])

AS_IF([test .${enable_debug_mbuf_cookies} = .yes],
  [
    AC_MSG_CHECKING([DPDK built with mempool debug])
    SAV_CFLAGS=$CFLAGS
    SAV_CPPFLAGS=$CPPFLAGS
    CFLAGS="$CFLAGS $dpdk_CFLAGS"
    CPPFLAGS="$CFLAGS $dpdk_CPPFLAGS"
    AC_COMPILE_IFELSE([AC_LANG_SOURCE([[
      int main(void)
      {
#ifndef RTE_LIBRTE_MEMPOOL_DEBUG
	i = RTE_LIBRTE_MEMPOOL_DEBUG;
#endif
      }
    ]])],
    [
      AC_MSG_RESULT([yes])
      DEBUG_MBUF_COOKIES=Yes
      AC_DEFINE([DEBUG_MBUF_COOKIES], [ 1 ], [Define to 1 to enable mbuf cookies debug])
      add_config_opt([DEBUG_MBUF_COOKIES])
    ],
    [
      AC_MSG_RESULT([no])
      AC_ERROR([--enable-debug-mbuf-cookies requires DPDK built with RTE_LIBRTE_MEMPOOL_DEBUG enabled])
    ])
    CFLAGS=${SAV_CFLAGS}
    CPPFLAGS=${SAV_CPPFLAGS}
  ],
  [DEBUG_MBUF_COOKIES=No])

AS_IF([test .${enable_debug_mem} = .yes],
  [
    DEBUG_MEM=Yes
    AC_DEFINE([DEBUG_MEM], [ 1 ], [Define to 1 to enable mem debug])
    add_config_opt([DEBUG_MEM])
  ],
  [DEBUG_MEM=No])

AS_IF([test .${enable_debug_mempool} = .yes],
  [
    DEBUG_MEMPOOL=Yes
    AC_DEFINE([DEBUG_MEMPOOL], [ 1 ], [Define to 1 to enable mempool debug])
    add_config_opt([DEBUG_MEMPOOL])
  ],
  [DEBUG_MEMPOOL=No])

AS_IF([test .${enable_debug_mempool_init} = .yes],
  [
    DEBUG_MEMPOOL_INIT=Yes
    AC_DEFINE([DEBUG_MEMPOOL_INIT], [ 1 ], [Define to 1 to enable mempool init debug])
    AC_DEFINE([APP_DEBUG_MEMPOOL_INIT], [ 1 ], [Define to 1 to enable app mempool init debug])
    add_config_opt([DEBUG_MEMPOOL_INIT])
  ],
  [DEBUG_MEMPOOL_INIT=No])

AS_IF([test .${enable_debug_no_mbuf} = .yes],
  [
    DEBUG_NO_MBUF=Yes
    AC_DEFINE([DEBUG_NO_MBUF], [ 1 ], [Define to 1 to enable no mbuf debug])
    add_config_opt([DEBUG_NO_MBUF])
  ],
  [DEBUG_NO_MBUF=No])

AS_IF([test .${enable_debug_optimize} = .yes],
  [
    DEBUG_OPTIMIZE=Yes
    AC_DEFINE([DEBUG_OPTIMIZE], [ 1 ], [Define to 1 to enable optimize debug])
    add_config_opt([DEBUG_OPTIMIZE])
  ],
  [DEBUG_OPTIMIZE=No])

AS_IF([test .${enable_debug_packet_overlap} = .yes],
  [
    DEBUG_PACKET_OVERLAP=Yes
    AC_DEFINE([DEBUG_PACKET_OVERLAP], [ 1 ], [Define to 1 to enable packet overlap debug])
    add_config_opt([DEBUG_PACKET_OVERLAP])
  ],
  [DEBUG_PACKET_OVERLAP=No])

AS_IF([test .${enable_debug_packet_pool} = .yes],
  [
    DEBUG_PACKET_POOL=Yes
    AC_DEFINE([DEBUG_PACKET_POOL], [ 1 ], [Define to 1 to enable packet pool debug])
    add_config_opt([DEBUG_PACKET_POOL])
  ],
  [DEBUG_PACKET_POOL=No])

AS_IF([test .${enable_debug_pcap_mempool} = .yes],
  [
    DEBUG_PCAP_MEMPOOL=Yes
    AC_DEFINE([DEBUG_PCAP_MEMPOOL], [ 1 ], [Define to 1 to enable pcap mempool debug])
    add_config_opt([DEBUG_PCAP_MEMPOOL])
  ],
  [DEBUG_PCAP_MEMPOOL=No])

AS_IF([test .${enable_debug_pkt_delays} = .yes],
  [
    DEBUG_PKT_DELAYS=Yes
    AC_DEFINE([DEBUG_PKT_DELAYS], [ 1 ], [Define to 1 to enable pkt delays debug])
    add_config_opt([DEBUG_PKT_DELAYS])
  ],
  [DEBUG_PKT_DELAYS=No])

AS_IF([test .${enable_debug_pkt_num} = .yes],
  [
    DEBUG_PKT_NUM=Yes
    AC_DEFINE([DEBUG_PKT_NUM], [ 1 ], [Define to 1 to enable pkt num debug])
    add_config_opt([DEBUG_PKT_NUM])
  ],
  [DEBUG_PKT_NUM=No])

AS_IF([test .${enable_debug_pkt_ptrs} = .yes],
  [
    DEBUG_PKT_PTRS=Yes
    AC_DEFINE([DEBUG_PKT_PTRS], [ 1 ], [Define to 1 to enable pkt ptrs debug])
    add_config_opt([DEBUG_PKT_PTRS])
  ],
  [DEBUG_PKT_PTRS=No])

AS_IF([test .${enable_debug_pkt_refcnt} = .yes],
  [
    DEBUG_PKT_REFCNT=Yes
    AC_DEFINE([DEBUG_PKT_REFCNT], [ 1 ], [Define to 1 to enable pkt refcnt debug])
    add_config_opt([DEBUG_PKT_REFCNT])
  ],
  [DEBUG_PKT_REFCNT=No])

AS_IF([test .${enable_debug_pkt_rx} = .yes],
  [
    DEBUG_PKT_RX=Yes
    AC_DEFINE([DEBUG_PKT_RX], [ 1 ], [Define to 1 to enable pkt rx debug])
    add_config_opt([DEBUG_PKT_RX])
  ],
  [DEBUG_PKT_RX=No])

AS_IF([test .${enable_debug_pkts} = .yes],
  [
    DEBUG_PKTS=Yes
    AC_DEFINE([DEBUG_PKTS], [ 1 ], [Define to 1 to enable pkts debug])
    add_config_opt([DEBUG_PKTS])
  ],
  [DEBUG_PKTS=No])

AS_IF([test .${enable_debug_pkt_sanity} = .yes],
  [
    DEBUG_PKT_SANITY=Yes
    AC_DEFINE([DEBUG_PKT_SANITY], [ 1 ], [Define to 1 to enable pkt sanity debug])
    add_config_opt([DEBUG_PKT_SANITY])
  ],
  [DEBUG_PKT_SANITY=No])

AS_IF([test .${enable_debug_pkt_types} = .yes],
  [
    DEBUG_PKT_TYPES=Yes
    AC_DEFINE([DEBUG_PKT_TYPES], [ 1 ], [Define to 1 to enable pkt types debug])
    add_config_opt([DEBUG_PKT_TYPES])
  ],
  [DEBUG_PKT_TYPES=No])

AS_IF([test .${enable_debug_pkt_valid} = .yes],
  [
    DEBUG_PKT_VALID=Yes
    AC_DEFINE([DEBUG_PKT_VALID], [ 1 ], [Define to 1 to enable pkt valid debug])
    add_config_opt([DEBUG_PKT_VALID])
  ],
  [DEBUG_PKT_VALID=No])

AS_IF([test .${enable_debug_postprocess} = .yes],
  [
    DEBUG_POSTPROCESS=Yes
    AC_DEFINE([DEBUG_POSTPROCESS], [ 1 ], [Define to 1 to enable postprocess debug])
    add_config_opt([DEBUG_POSTPROCESS])
  ],
  [DEBUG_POSTPROCESS=No])

AS_IF([test .${enable_debug_process_pkt_info} = .yes],
  [
    DEBUG_PROCESS_PKT_INFO=Yes
    AC_DEFINE([DEBUG_PROCESS_PKT_INFO], [ 1 ], [Define to 1 to enable process pkt info debug])
    add_config_opt([DEBUG_PROCESS_PKT_INFO])
  ],
  [DEBUG_PROCESS_PKT_INFO=No])

AS_IF([test .${enable_debug_print_to_buf} = .yes],
  [
    DEBUG_PRINT_TO_BUF=Yes
    AC_DEFINE([DEBUG_PRINT_TO_BUF], [ 1 ], [Define to 1 to enable print to buf debug])
    add_config_opt([DEBUG_PRINT_TO_BUF])
  ],
  [DEBUG_PRINT_TO_BUF=No])
AM_CONDITIONAL([TFO_PRINTF], [test $DEBUG_PRINT_TO_BUF = Yes])

AS_IF([test .${enable_debug_queued} = .yes],
  [
    DEBUG_QUEUED=Yes
    AC_DEFINE([DEBUG_QUEUED], [ 1 ], [Define to 1 to enable queued debug])
    add_config_opt([DEBUG_QUEUED])
  ],
  [DEBUG_QUEUED=No])

AS_IF([test .${enable_debug_queue_pkts} = .yes],
  [
    DEBUG_QUEUE_PKTS=Yes
    AC_DEFINE([DEBUG_QUEUE_PKTS], [ 1 ], [Define to 1 to enable queue pkts debug])
    add_config_opt([DEBUG_QUEUE_PKTS])
  ],
  [DEBUG_QUEUE_PKTS=No])

AS_IF([test .${enable_debug_rack} = .yes],
  [
    DEBUG_RACK=Yes
    AC_DEFINE([DEBUG_RACK], [ 1 ], [Define to 1 to enable rack debug])
    add_config_opt([DEBUG_RACK])
  ],
  [DEBUG_RACK=No])

AS_IF([test .${enable_debug_rack_loss} = .yes],
  [
    DEBUG_RACK_LOSS=Yes
    AC_DEFINE([DEBUG_RACK_LOSS], [ 1 ], [Define to 1 to enable rack loss debug])
    add_config_opt([DEBUG_RACK_LOSS])
  ],
  [DEBUG_RACK_LOSS=No])

AS_IF([test .${enable_debug_rack_sacked} = .yes],
  [
    DEBUG_RACK_SACKED=Yes
    AC_DEFINE([DEBUG_RACK_SACKED], [ 1 ], [Define to 1 to enable rack sacked debug])
    add_config_opt([DEBUG_RACK_SACKED])
  ],
  [DEBUG_RACK_SACKED=No])

AS_IF([test .${enable_debug_rcv_win} = .yes],
  [
    DEBUG_RCV_WIN=Yes
    AC_DEFINE([DEBUG_RCV_WIN], [ 1 ], [Define to 1 to enable rcv win debug])
    add_config_opt([DEBUG_RCV_WIN])
  ],
  [DEBUG_RCV_WIN=No])

AS_IF([test .${enable_debug_recovery} = .yes],
  [
    DEBUG_RECOVERY=Yes
    AC_DEFINE([DEBUG_RECOVERY], [ 1 ], [Define to 1 to enable recovery debug])
    add_config_opt([DEBUG_RECOVERY])
  ],
  [DEBUG_RECOVERY=No])

AS_IF([test .${enable_debug_relative_seq} = .yes],
  [
    DEBUG_RELATIVE_SEQ=Yes
    AC_DEFINE([DEBUG_RELATIVE_SEQ], [ 1 ], [Define to 1 to enable relative seq debug])
    add_config_opt([DEBUG_RELATIVE_SEQ])
  ],
  [DEBUG_RELATIVE_SEQ=No])

AS_IF([test .${enable_debug_remove_tx_pkt} = .yes],
  [
    DEBUG_REMOVE_TX_PKT=Yes
    AC_DEFINE([DEBUG_REMOVE_TX_PKT], [ 1 ], [Define to 1 to enable remove tx pkt debug])
    add_config_opt([DEBUG_REMOVE_TX_PKT])
  ],
  [DEBUG_REMOVE_TX_PKT=No])

AS_IF([test .${enable_debug_resend_failed_packets} = .yes],
  [
    DEBUG_RESEND_FAILED_PACKETS=Yes
    AC_DEFINE([DEBUG_RESEND_FAILED_PACKETS], [ 1 ], [Define to 1 to enable resend failed packets debug])
    add_config_opt([DEBUG_RESEND_FAILED_PACKETS])
  ],
  [DEBUG_RESEND_FAILED_PACKETS=No])

AS_IF([test .${enable_debug_rfc5681} = .yes],
  [
    DEBUG_RFC5681=Yes
    AC_DEFINE([DEBUG_RFC5681], [ 1 ], [Define to 1 to enable rfc5681 debug])
    add_config_opt([DEBUG_RFC5681])
  ],
  [DEBUG_RFC5681=No])

AS_IF([test .${enable_debug_rst} = .yes],
  [
    DEBUG_RST=Yes
    AC_DEFINE([DEBUG_RST], [ 1 ], [Define to 1 to enable rst debug])
    add_config_opt([DEBUG_RST])
  ],
  [DEBUG_RST=No])

AS_IF([test .${enable_debug_rto} = .yes],
  [
    DEBUG_RTO=Yes
    AC_DEFINE([DEBUG_RTO], [ 1 ], [Define to 1 to enable rto debug])
    add_config_opt([DEBUG_RTO])
  ],
  [DEBUG_RTO=No])

AS_IF([test .${enable_debug_rtt_min} = .yes],
  [
    DEBUG_RTT_MIN=Yes
    AC_DEFINE([DEBUG_RTT_MIN], [ 1 ], [Define to 1 to enable rtt min debug])
    add_config_opt([DEBUG_RTT_MIN])
  ],
  [DEBUG_RTT_MIN=No])

AS_IF([test .${enable_debug_rx_pkts} = .yes],
  [
    DEBUG_RX_PKTS=Yes
    AC_DEFINE([DEBUG_RX_PKTS], [ 1 ], [Define to 1 to enable rx pkts debug])
    add_config_opt([DEBUG_RX_PKTS])
  ],
  [DEBUG_RX_PKTS=No])

AS_IF([test .${enable_debug_sack_rx} = .yes],
  [
    DEBUG_SACK_RX=Yes
    AC_DEFINE([DEBUG_SACK_RX], [ 1 ], [Define to 1 to enable sack rx debug])
    add_config_opt([DEBUG_SACK_RX])
  ],
  [DEBUG_SACK_RX=No])

AS_IF([test .${enable_debug_sack_send} = .yes],
  [
    DEBUG_SACK_SEND=Yes
    AC_DEFINE([DEBUG_SACK_SEND], [ 1 ], [Define to 1 to enable sack send debug])
    add_config_opt([DEBUG_SACK_SEND])
  ],
  [DEBUG_SACK_SEND=No])

AS_IF([test .${enable_debug_sack_verify} = .yes],
  [
    DEBUG_SACK_VERIFY=Yes
    AC_DEFINE([DEBUG_SACK_VERIFY], [ 1 ], [Define to 1 to enable sack verify debug])
    add_config_opt([DEBUG_SACK_VERIFY])
  ],
  [DEBUG_SACK_VERIFY=No])

AS_IF([test .${enable_debug_send_burst} = .yes],
  [
    DEBUG_SEND_BURST=Yes
    AC_DEFINE([DEBUG_SEND_BURST], [ 1 ], [Define to 1 to enable send burst debug])
    add_config_opt([DEBUG_SEND_BURST])
  ],
  [DEBUG_SEND_BURST=No])

AS_IF([test .${enable_debug_send_burst_errors} = .yes],
  [
    DEBUG_SEND_BURST_ERRORS=Yes
    AC_DEFINE([DEBUG_SEND_BURST_ERRORS], [ 1 ], [Define to 1 to enable send burst errors debug])
    add_config_opt([DEBUG_SEND_BURST_ERRORS])
  ],
  [DEBUG_SEND_BURST_ERRORS=No])

AS_IF([test .${enable_debug_send_burst_not_sent} = .yes],
  [
    DEBUG_SEND_BURST_NOT_SENT=Yes
    AC_DEFINE([DEBUG_SEND_BURST_NOT_SENT], [ 1 ], [Define to 1 to enable send burst not sent debug])
    add_config_opt([DEBUG_SEND_BURST_NOT_SENT])
  ],
  [DEBUG_SEND_BURST_NOT_SENT=No])

AS_IF([test .${enable_debug_send_dsack_check} = .yes],
  [
    DEBUG_SEND_DSACK_CHECK=Yes
    AC_DEFINE([DEBUG_SEND_DSACK_CHECK], [ 1 ], [Define to 1 to enable send dsack check debug])
    add_config_opt([DEBUG_SEND_DSACK_CHECK])
  ],
  [DEBUG_SEND_DSACK_CHECK=No])

AS_IF([test .${enable_debug_send_pkt} = .yes],
  [
    DEBUG_SEND_PKT=Yes
    AC_DEFINE([DEBUG_SEND_PKT], [ 1 ], [Define to 1 to enable send pkt debug])
    add_config_opt([DEBUG_SEND_PKT])
  ],
  [DEBUG_SEND_PKT=No])

AS_IF([test .${enable_debug_send_pkt_location} = .yes],
  [
    DEBUG_SEND_PKT_LOCATION=Yes
    AC_DEFINE([DEBUG_SEND_PKT_LOCATION], [ 1 ], [Define to 1 to enable send pkt location debug])
    add_config_opt([DEBUG_SEND_PKT_LOCATION])
  ],
  [DEBUG_SEND_PKT_LOCATION=No])

AS_IF([test .${enable_debug_send_probe} = .yes],
  [
    DEBUG_SEND_PROBE=Yes
    AC_DEFINE([DEBUG_SEND_PROBE], [ 1 ], [Define to 1 to enable send probe debug])
    add_config_opt([DEBUG_SEND_PROBE])
  ],
  [DEBUG_SEND_PROBE=No])

AS_IF([test .${enable_debug_sm} = .yes],
  [
    DEBUG_SM=Yes
    AC_DEFINE([DEBUG_SM], [ 1 ], [Define to 1 to enable sm debug])
    add_config_opt([DEBUG_SM])
  ],
  [DEBUG_SM=No])

AS_IF([test .${enable_debug_snd_nxt} = .yes],
  [
    DEBUG_SND_NXT=Yes
    AC_DEFINE([DEBUG_SND_NXT], [ 1 ], [Define to 1 to enable snd nxt debug])
    add_config_opt([DEBUG_SND_NXT])
  ],
  [DEBUG_SND_NXT=No])

AS_IF([test .${enable_debug_structures} = .yes],
  [
    DEBUG_STRUCTURES=Yes
    AC_DEFINE([DEBUG_STRUCTURES], [ 1 ], [Define to 1 to enable structures debug])
    add_config_opt([DEBUG_STRUCTURES])
  ],
  [DEBUG_STRUCTURES=No])

AS_IF([test .${enable_debug_supported_pkt_types} = .yes],
  [
    DEBUG_SUPPORTED_PKT_TYPES=Yes
    AC_DEFINE([DEBUG_SUPPORTED_PKT_TYPES], [ 1 ], [Define to 1 to enable supported pkt types debug])
    add_config_opt([DEBUG_SUPPORTED_PKT_TYPES])
  ],
  [DEBUG_SUPPORTED_PKT_TYPES=No])

AS_IF([test .${enable_debug_tcp_opt} = .yes],
  [
    DEBUG_TCP_OPT=Yes
    AC_DEFINE([DEBUG_TCP_OPT], [ 1 ], [Define to 1 to enable tcp opt debug])
    add_config_opt([DEBUG_TCP_OPT])
  ],
  [DEBUG_TCP_OPT=No])

AS_IF([test .${enable_debug_tcp_window} = .yes],
  [
    DEBUG_TCP_WINDOW=Yes
    AC_DEFINE([DEBUG_TCP_WINDOW], [ 1 ], [Define to 1 to enable tcp window debug])
    add_config_opt([DEBUG_TCP_WINDOW])
  ],
  [DEBUG_TCP_WINDOW=No])

AS_IF([test .${enable_debug_timers} = .yes],
  [
    DEBUG_TIMERS=Yes
    AC_DEFINE([DEBUG_TIMERS], [ 1 ], [Define to 1 to enable timers debug])
    add_config_opt([DEBUG_TIMERS])
  ],
  [DEBUG_TIMERS=No])

AS_IF([test .${enable_debug_ts_speed} = .yes],
  [
    DEBUG_TS_SPEED=Yes
    AC_DEFINE([DEBUG_TS_SPEED], [ 1 ], [Define to 1 to enable ts speed debug])
    add_config_opt([DEBUG_TS_SPEED])
  ],
  [DEBUG_TS_SPEED=No])

AS_IF([test .${enable_debug_tx_bufs} = .yes],
  [
    DEBUG_TX_BUFS=Yes
    AC_DEFINE([DEBUG_TX_BUFS], [ 1 ], [Define to 1 to enable tx bufs debug])
    add_config_opt([DEBUG_TX_BUFS])
  ],
  [DEBUG_TX_BUFS=No])

AS_IF([test .${enable_debug_users_tx_clock} = .yes],
  [
    DEBUG_USERS_TX_CLOCK=Yes
    AC_DEFINE([DEBUG_USERS_TX_CLOCK], [ 1 ], [Define to 1 to enable users tx clock debug])
    add_config_opt([DEBUG_USERS_TX_CLOCK])
  ],
  [DEBUG_USERS_TX_CLOCK=No])

AS_IF([test .${enable_debug_valid_options} = .yes],
  [
    DEBUG_VALID_OPTIONS=Yes
    AC_DEFINE([DEBUG_VALID_OPTIONS], [ 1 ], [Define to 1 to enable valid options debug])
    add_config_opt([DEBUG_VALID_OPTIONS])
  ],
  [DEBUG_VALID_OPTIONS=No])

AS_IF([test .${enable_debug_vlan} = .yes],
  [
    DEBUG_VLAN=Yes
    AC_DEFINE([DEBUG_VLAN], [ 1 ], [Define to 1 to enable vlan debug])
    add_config_opt([DEBUG_VLAN])
  ],
  [DEBUG_VLAN=No])

AS_IF([test .${enable_debug_vlan1} = .yes],
  [
    DEBUG_VLAN1=Yes
    AC_DEFINE([DEBUG_VLAN1], [ 1 ], [Define to 1 to enable vlan1 debug])
    add_config_opt([DEBUG_VLAN1])
  ],
  [DEBUG_VLAN1=No])

AS_IF([test .${enable_debug_vlan_tci} = .yes],
  [
    DEBUG_VLAN_TCI=Yes
    AC_DEFINE([DEBUG_VLAN_TCI], [ 1 ], [Define to 1 to enable vlan tci debug])
    add_config_opt([DEBUG_VLAN_TCI])
  ],
  [DEBUG_VLAN_TCI=No])

AS_IF([test .${enable_debug_xmit_list} = .yes],
  [
    DEBUG_XMIT_LIST=Yes
    AC_DEFINE([DEBUG_XMIT_LIST], [ 1 ], [Define to 1 to enable xmit list debug])
    add_config_opt([DEBUG_XMIT_LIST])
  ],
  [DEBUG_XMIT_LIST=No])

AS_IF([test .${enable_debug_zero_window} = .yes],
  [
    DEBUG_ZERO_WINDOW=Yes
    AC_DEFINE([DEBUG_ZERO_WINDOW], [ 1 ], [Define to 1 to enable zero window debug])
    add_config_opt([DEBUG_ZERO_WINDOW])
  ],
  [DEBUG_ZERO_WINDOW=No])

AS_IF([test .${enable_app_sends_pkts} = .yes],
  [
    APP_SENDS_PKTS=Yes
    AC_DEFINE([APP_SENDS_PKTS], [ 1 ], [Define to 1 to enable app sends pkts])
    add_config_opt([APP_SENDS_PKTS])
  ],
  [APP_SENDS_PKTS=No])

AS_IF([test .${enable_app_updates_mac_addr} = .yes],
  [
    APP_UPDATES_MAC_ADDR=Yes
    AC_DEFINE([APP_UPDATES_MAC_ADDR], [ 1 ], [Define to 1 to enable app updates MAC addr])
    add_config_opt([APP_UPDATES_MAC_ADDR])
  ],
  [APP_UPDATES_MAC_ADDR=No])

AS_IF([test .${enable_app_updates_vlan} = .yes],
  [
    APP_UPDATES_VLAN=Yes
    AC_DEFINE([APP_UPDATES_VLAN], [ 1 ], [Define to 1 to enable app updates Vlan])
    add_config_opt([APP_UPDATES_VLAN])
  ],
  [APP_UPDATES_VLAN=No])

AS_IF([test .${enable_app_vlan_swap} = .yes],
  [
    APP_VLAN_SWAP=Yes
    AC_DEFINE([APP_VLAN_SWAP], [ 1 ], [Define to 1 to enable app Vlan swap])
    add_config_opt([APP_VLAN_SWAP])
  ],
  [APP_VLAN_SWAP=No])

AS_IF([test .${enable_app_clear_rx_bufs} = .yes],
  [
    APP_CLEAR_RX_BUFS=Yes
    AC_DEFINE([APP_CLEAR_RX_BUFS], [ 1 ], [Define to 1 to enable app clear rx bufs])
    add_config_opt([APP_CLEAR_RX_BUFS])
  ],
  [APP_CLEAR_RX_BUFS=No])

AS_IF([test .${enable_app_debug_duplicate_mbufs} = .yes],
  [
    APP_DEBUG_DUPLICATE_MBUFS=Yes
    AC_DEFINE([APP_DEBUG_DUPLICATE_MBUFS], [ 1 ], [Define to 1 to enable app debug duplicate mbufs])
    add_config_opt([APP_DEBUG_DUPLICATE_MBUFS])
  ],
  [APP_DEBUG_DUPLICATE_MBUFS=No])

AS_IF([test .${enable_app_debug_pkt_details} = .yes],
  [
    APP_DEBUG_PKT_DETAILS=Yes
    AC_DEFINE([APP_DEBUG_PKT_DETAILS], [ 1 ], [Define to 1 to enable app debug pkt details])
    add_config_opt([APP_DEBUG_PKT_DETAILS])
  ],
  [APP_DEBUG_PKT_DETAILS=No])

AS_IF([test .${enable_app_debug_pkt_type_unknown} = .yes],
  [
    APP_DEBUG_PKT_TYPE_UNKNOWN=Yes
    AC_DEFINE([APP_DEBUG_PKT_TYPE_UNKNOWN], [ 1 ], [Define to 1 to enable app debug pkt type unknown])
    add_config_opt([APP_DEBUG_PKT_TYPE_UNKNOWN])
  ],
  [APP_DEBUG_PKT_TYPE_UNKNOWN=No])

AS_IF([test .${enable_app_fix_duplicate_mbufs} = .yes],
  [
    APP_FIX_DUPLICATE_MBUFS=Yes
    AC_DEFINE([APP_FIX_DUPLICATE_MBUFS], [ 1 ], [Define to 1 to enable app fix duplicate mbufs])
    add_config_opt([APP_FIX_DUPLICATE_MBUFS])
  ],
  [APP_FIX_DUPLICATE_MBUFS=No])

AS_IF([test .${enable_app_log_actions} = .yes],
  [
    APP_LOG_ACTIONS=Yes
    AC_DEFINE([APP_LOG_ACTIONS], [ 1 ], [Define to 1 to enable app log actions])
    add_config_opt([APP_LOG_ACTIONS])
  ],
  [APP_LOG_ACTIONS=No])

AS_IF([test .${enable_app_log_shutdown} = .yes],
  [
    APP_LOG_SHUTDOWN=Yes
    AC_DEFINE([APP_LOG_SHUTDOWN], [ 1 ], [Define to 1 to enable app log shutdown])
    add_config_opt([APP_LOG_SHUTDOWN])
  ],
  [APP_LOG_SHUTDOWN=No])

AS_IF([test .${enable_app_log_timer_secs} = .yes],
  [
    APP_LOG_TIMER_SECS=Yes
    AC_DEFINE([APP_LOG_TIMER_SECS], [ 1 ], [Define to 1 to enable app log timer secs])
    add_config_opt([APP_LOG_TIMER_SECS])
  ],
  [APP_LOG_TIMER_SECS=No])

AS_IF([test .${enable_app_log_tx_timer} = .yes],
  [
    APP_LOG_TX_TIMER=Yes
    AC_DEFINE([APP_LOG_TX_TIMER], [ 1 ], [Define to 1 to enable app log tx timer])
    add_config_opt([APP_LOG_TX_TIMER])
  ],
  [APP_LOG_TX_TIMER=No])

AS_IF([test .${with_app_rx_ring_size} != .],
      [RX_RING_SIZE=$with_app_rx_ring_size], [RX_RING_SIZE=1024])
AC_DEFINE_UNQUOTED([APP_RX_RING_SIZE], [ $RX_RING_SIZE ], [specify receive ring size for app])

AS_IF([test .${with_app_tx_ring_size} != .],
      [TX_RING_SIZE=$with_app_tx_ring_size], [TX_RING_SIZE=1024])
AC_DEFINE_UNQUOTED([APP_TX_RING_SIZE], [ $TX_RING_SIZE ], [specify transmit ring size for app])

AS_IF([test .${with_app_num_bufs} != .],
      [NUM_MBUFS=$with_app_num_mbufs], [NUM_MBUFS=8091])
AC_DEFINE_UNQUOTED([APP_NUM_MBUFS], [ $NUM_MBUFS ], [specify number of mbufs for app])

AS_IF([test .${with_app_mbuf_cache_size} != .],
      [MBUF_CACHE_SIZE=$with_app_mbuf_cache_size], [MBUF_CACHE_SIZE=250])
AC_DEFINE_UNQUOTED([APP_MBUF_CACHE_SIZE], [ $MBUF_CACHE_SIZE ], [specify mbuf cache size for app])

AS_IF([test .${with_app_default_burst_size} != .],
      [DEFAULT_BURST_SIZE=$with_app_default_burst_size], [DEFAULT_BURST_SIZE=250])
AC_DEFINE_UNQUOTED([APP_DEFAULT_BURST_SIZE], [ $DEFAULT_BURST_SIZE ], [specify default burst size for app])

AS_IF([test .${with_app_max_if} != .],
      [MAX_IF=$with_app_max_if], [MAX_IF=2])
AC_DEFINE_UNQUOTED([APP_MAX_IF], [ $MAX_IF ], [specify maximum number of interfaces supported in app])

AM_CONDITIONAL([SHOW_MEMPOOL], [test $DEBUG_MEMPOOL_INIT=Yes -o $DEBUG_ACK_MEMPOOL_INIT=Yes])


# Update compiler flags with any options given
regular_CFLAGS="$regular_CFLAGS ${CC_OPTIMIZATION}"

AC_OUTPUT

dnl ----[ Display current configuration ]----
cat <<EOF

libtfo configuration
------------------------
libtfo version           : ${VERSION}
Compiler                 : $(${CC} --version | head -1)
Preprocessor flags       : $(echo ${regular_CPPFLAGS} ${dpdk_CPPFLAGS} | sed -e "s/  */ /g")
Compiler flags           : $(echo ${regular_CFLAGS} ${dpdk_CFLAGS} | sed -e "s/  */ /g")
EOF

dnl ----[ display optional vars  ]----
# AS_IF([test -n ${regular_LDFLAGS} -o -n ${regular_LIBS} -o -n ${dpdk_LDFLAGS} -o -n ${dpdk_LIBS}], [
  echo "Linker flags             :" ${regular_LDFLAGS} ${dpdk_LDFLAGS}
  echo "Extra Lib                :" ${regular_LIBS} ${dpdk_LIBS}
# ])

# Configuration options
AS_IF([test ${CALC_TS_CLOCK} = No],
  [echo "Calc TS clock            :" No])
AS_IF([test ${CWND_USE_ALTERNATE} = Yes],
  [echo "Use alternate CWND calc  :" Yes])

# Library functionality options
AS_IF([test ${DETECT_LOSS_MIN} = Yes],
  [echo "Detect loss min          :" Yes])
AS_IF([test ${DO_QUICKACK} = Yes],
  [echo "Do quickack              :" Yes])
AS_IF([test ${EFLOW_DUMP} = Yes],
  [echo "Eflow_dump exposed       :" Yes])
AS_IF([test ${HAVE_DUPLICATE_MBUF_BUG} = Yes],
  [echo "Have duplicate mbuf bug  :" Yes])
AS_IF([test ${RECEIVE_WINDOW_ALLOW_MAX} = Yes],
  [echo "Receive window allow max :" Yes])
AS_IF([test ${RECEIVE_WINDOW_MSS_MULT} = Yes],
  [echo "Receive window mss mult  :" ${enable_receive_window_mss_mult}])
AS_IF([test ${RELEASE_SACKED_PACKETS} = Yes],
  [echo "Release sacked packets   :" Yes])
AS_IF([test ${WRITE_PCAP} = Yes],
  [echo "Write pcap               :" Yes])

# Library debug options
AS_IF([test ${DEBUG_ACK} = Yes],
  [echo "ACK debug                :" Yes])
AS_IF([test ${DEBUG_ACK_MEMPOOL} = Yes],
  [echo "ACK mempool debug        :" Yes])
AS_IF([test ${DEBUG_ACK_MEMPOOL_INIT} = Yes],
  [echo "ACK mempool init debug   :" Yes])
AS_IF([test ${DEBUG_ACK_PKT_LIST} = Yes],
  [echo "ACK pkt list debug       :" Yes])
AS_IF([test ${DEBUG_BURST} = Yes],
  [echo "Burst debug              :" Yes])
AS_IF([test ${DEBUG_CHECK_ADDR} = Yes],
  [echo "Check addr debug         :" Yes])
AS_IF([test ${DEBUG_CHECK_PKTS} = Yes],
  [echo "Check pkts debug         :" Yes])
AS_IF([test ${DEBUG_CHECKSUM} = Yes],
  [echo "Checksum debug           :" Yes])
AS_IF([test ${DEBUG_CHECKSUM_DETAIL} = Yes],
  [echo "Checksum detail debug    :" Yes])
AS_IF([test ${DEBUG_CONFIG} = Yes],
  [echo "Config debug             :" Yes])
AS_IF([test ${DEBUG_DELAYED_ACK} = Yes],
  [echo "Delayed ack debug        :" Yes])
AS_IF([test ${DEBUG_DISABLE_SACK} = Yes],
  [echo "Disable sack debug       :" Yes])
AS_IF([test ${DEBUG_DISABLE_TS} = Yes],
  [echo "Disable ts debug         :" Yes])
AS_IF([test ${DEBUG_DLSPEED} = Yes],
  [echo "Dlspeed debug            :" Yes])
AS_IF([test ${DEBUG_DLSPEED_DEBUG} = Yes],
  [echo "Dlspeed debug debug      :" Yes])
AS_IF([test ${DEBUG_DUPLICATE_MBUFS} = Yes],
  [echo "Duplicate mbufs debug    :" Yes])
AS_IF([test ${DEBUG_DUP_SACK_SEND} = Yes],
  [echo "Dup sack send debug      :" Yes])
AS_IF([test ${DEBUG_EMPTY_PACKETS} = Yes],
  [echo "Empty packets debug      :" Yes])
AS_IF([test ${DEBUG_ETHDEV} = Yes],
  [echo "Ethdev debug             :" Yes])
AS_IF([test ${DEBUG_FIN} = Yes],
  [echo "Fin debug                :" Yes])
AS_IF([test ${DEBUG_FLOW} = Yes],
  [echo "Flow debug               :" Yes])
AS_IF([test ${DEBUG_FWD_FREED_PKT} = Yes],
  [echo "Fwd freed pkt debug      :" Yes])
AS_IF([test ${DEBUG_IN_FLIGHT} = Yes],
  [echo "In flight debug          :" Yes])
AS_IF([test ${DEBUG_KEEPALIVES} = Yes],
  [echo "Keepalives debug         :" Yes])
AS_IF([test ${DEBUG_LAST_SENT} = Yes],
  [echo "Last sent debug          :" Yes])
AS_IF([test ${DEBUG_MBUF_COOKIES} = Yes],
  [echo "Mbuf cookies debug       :" Yes])
AS_IF([test ${DEBUG_MEM} = Yes],
  [echo "Mem debug                :" Yes])
AS_IF([test ${DEBUG_MEMPOOL} = Yes],
  [echo "Mempool debug            :" Yes])
AS_IF([test ${DEBUG_MEMPOOL_INIT} = Yes],
  [echo "Mempool init debug       :" Yes])
AS_IF([test ${DEBUG_NO_MBUF} = Yes],
  [echo "No mbuf debug            :" Yes])
AS_IF([test ${DEBUG_OPTIMIZE} = Yes],
  [echo "Optimize debug           :" Yes])
AS_IF([test ${DEBUG_PACKET_OVERLAP} = Yes],
  [echo "Packet overlap debug     :" Yes])
AS_IF([test ${DEBUG_PACKET_POOL} = Yes],
  [echo "Packet pool debug        :" Yes])
AS_IF([test ${DEBUG_PCAP_MEMPOOL} = Yes],
  [echo "Pcap mempool debug       :" Yes])
AS_IF([test ${DEBUG_PKT_DELAYS} = Yes],
  [echo "Pkt delays debug         :" Yes])
AS_IF([test ${DEBUG_PKT_NUM} = Yes],
  [echo "Pkt num debug            :" Yes])
AS_IF([test ${DEBUG_PKT_PTRS} = Yes],
  [echo "Pkt ptrs debug           :" Yes])
AS_IF([test ${DEBUG_PKT_REFCNT} = Yes],
  [echo "Pkt refcnt debug         :" Yes])
AS_IF([test ${DEBUG_PKT_RX} = Yes],
  [echo "Pkt rx debug             :" Yes])
AS_IF([test ${DEBUG_PKTS} = Yes],
  [echo "Pkts debug               :" Yes])
AS_IF([test ${DEBUG_PKT_SANITY} = Yes],
  [echo "Pkt sanity debug         :" Yes])
AS_IF([test ${DEBUG_PKT_TYPES} = Yes],
  [echo "Pkt types debug          :" Yes])
AS_IF([test ${DEBUG_PKT_VALID} = Yes],
  [echo "Pkt valid debug          :" Yes])
AS_IF([test ${DEBUG_POSTPROCESS} = Yes],
  [echo "Postprocess debug        :" Yes])
AS_IF([test ${DEBUG_PROCESS_PKT_INFO} = Yes],
  [echo "Process pkt info debug   :" Yes])
AS_IF([test ${DEBUG_PRINT_TO_BUF} = Yes],
  [echo "Print to buf debug       :" Yes])
AS_IF([test ${DEBUG_QUEUED} = Yes],
  [echo "Queued debug             :" Yes])
AS_IF([test ${DEBUG_QUEUE_PKTS} = Yes],
  [echo "Queue pkts debug         :" Yes])
AS_IF([test ${DEBUG_RACK} = Yes],
  [echo "Rack debug               :" Yes])
AS_IF([test ${DEBUG_RACK_LOSS} = Yes],
  [echo "Rack loss debug          :" Yes])
AS_IF([test ${DEBUG_RACK_SACKED} = Yes],
  [echo "Rack sacked debug        :" Yes])
AS_IF([test ${DEBUG_RCV_WIN} = Yes],
  [echo "Rcv win debug            :" Yes])
AS_IF([test ${DEBUG_RECOVERY} = Yes],
  [echo "Recovery debug           :" Yes])
AS_IF([test ${DEBUG_RELATIVE_SEQ} = Yes],
  [echo "Relative seq debug       :" Yes])
AS_IF([test ${DEBUG_REMOVE_TX_PKT} = Yes],
  [echo "Remove tx pkt debug      :" Yes])
AS_IF([test ${DEBUG_RESEND_FAILED_PACKETS} = Yes],
  [echo "Resend failed packets debug:" Yes])
AS_IF([test ${DEBUG_RFC5681} = Yes],
  [echo "RFC5681 debug            :" Yes])
AS_IF([test ${DEBUG_RST} = Yes],
  [echo "RST debug                :" Yes])
AS_IF([test ${DEBUG_RTO} = Yes],
  [echo "RTO debug                :" Yes])
AS_IF([test ${DEBUG_RTT_MIN} = Yes],
  [echo "RTT min debug            :" Yes])
AS_IF([test ${DEBUG_RX_PKTS} = Yes],
  [echo "Rx pkts debug            :" Yes])
AS_IF([test ${DEBUG_SACK_RX} = Yes],
  [echo "Sack rx debug            :" Yes])
AS_IF([test ${DEBUG_SACK_SEND} = Yes],
  [echo "Sack send debug          :" Yes])
AS_IF([test ${DEBUG_SACK_VERIFY} = Yes],
  [echo "Sack verify debug        :" Yes])
AS_IF([test ${DEBUG_SEND_BURST} = Yes],
  [echo "Send burst debug         :" Yes])
AS_IF([test ${DEBUG_SEND_BURST_ERRORS} = Yes],
  [echo "Send burst errors debug  :" Yes])
AS_IF([test ${DEBUG_SEND_BURST_NOT_SENT} = Yes],
  [echo "Send burst not sent debug:" Yes])
AS_IF([test ${DEBUG_SEND_DSACK_CHECK} = Yes],
  [echo "Send dsack check debug   :" Yes])
AS_IF([test ${DEBUG_SEND_PKT} = Yes],
  [echo "Send pkt debug           :" Yes])
AS_IF([test ${DEBUG_SEND_PKT_LOCATION} = Yes],
  [echo "Send pkt location debug  :" Yes])
AS_IF([test ${DEBUG_SEND_PROBE} = Yes],
  [echo "Send probe debug         :" Yes])
AS_IF([test ${DEBUG_SM} = Yes],
  [echo "Sm debug                 :" Yes])
AS_IF([test ${DEBUG_SND_NXT} = Yes],
  [echo "Snd nxt debug            :" Yes])
AS_IF([test ${DEBUG_STRUCTURES} = Yes],
  [echo "Structures debug         :" Yes])
AS_IF([test ${DEBUG_SUPPORTED_PKT_TYPES} = Yes],
  [echo "Supported pkt types debug:" Yes])
AS_IF([test ${DEBUG_TCP_OPT} = Yes],
  [echo "Tcp opt debug            :" Yes])
AS_IF([test ${DEBUG_TCP_WINDOW} = Yes],
  [echo "Tcp window debug         :" Yes])
AS_IF([test ${DEBUG_TIMERS} = Yes],
  [echo "Timers debug             :" Yes])
AS_IF([test ${DEBUG_TS_SPEED} = Yes],
  [echo "Ts speed debug           :" Yes])
AS_IF([test ${DEBUG_TX_BUFS} = Yes],
  [echo "Tx bufs debug            :" Yes])
AS_IF([test ${DEBUG_USERS_TX_CLOCK} = Yes],
  [echo "Users tx clock debug     :" Yes])
AS_IF([test ${DEBUG_VALID_OPTIONS} = Yes],
  [echo "Valid options debug      :" Yes])
AS_IF([test ${DEBUG_VLAN} = Yes],
  [echo "Vlan debug               :" Yes])
AS_IF([test ${DEBUG_VLAN1} = Yes],
  [echo "Vlan1 debug              :" Yes])
AS_IF([test ${DEBUG_VLAN_TCI} = Yes],
  [echo "Vlan tci debug           :" Yes])
AS_IF([test ${DEBUG_XMIT_LIST} = Yes],
  [echo "Xmit list debug          :" Yes])
AS_IF([test ${DEBUG_ZERO_WINDOW} = Yes],
  [echo "Zero window debug        :" Yes])
AS_IF([test ${APP_SENDS_PKTS} = Yes],
  [echo "App sends pkts           :" Yes])
AS_IF([test ${APP_UPDATES_MAC_ADDR} = Yes],
  [echo "App updates mac addr     :" Yes])
AS_IF([test ${APP_UPDATES_VLAN} = Yes],
  [echo "App updates vlan         :" Yes])
AS_IF([test ${APP_VLAN_SWAP} = Yes],
  [echo "App vlan swap            :" Yes])
AS_IF([test ${APP_CLEAR_RX_BUFS} = Yes],
  [echo "App clear rx bufs        :" Yes])
AS_IF([test ${APP_DEBUG_DUPLICATE_MBUFS} = Yes],
  [echo "App debug duplicate mbufs:" Yes])
AS_IF([test ${APP_DEBUG_PKT_DETAILS} = Yes],
  [echo "App debug pkt details    :" Yes])
AS_IF([test ${APP_DEBUG_PKT_TYPE_UNKNOWN} = Yes],
  [echo "App debug pkt type unknown:" Yes])
AS_IF([test ${APP_FIX_DUPLICATE_MBUFS} = Yes],
  [echo "App fix duplicate mbufs  :" Yes])
AS_IF([test ${APP_LOG_ACTIONS} = Yes],
  [echo "App log actions          :" Yes])
AS_IF([test ${APP_LOG_SHUTDOWN} = Yes],
  [echo "App log shutdown         :" Yes])
AS_IF([test ${APP_LOG_TIMER_SECS} = Yes],
  [echo "App log timer secs       :" Yes])
AS_IF([test ${APP_LOG_TX_TIMER} = Yes],
  [echo "App log tx timer         :" Yes])
AS_IF([test .${with_app_rx_ring_size} != .],
  [echo "App rx ring size         :" $RX_RING_SIZE])
AS_IF([test .${with_app_tx_ring_size} != .],
  [echo "App tx ring size         :" $TX_RING_SIZE])
AS_IF([test .${with_app_num_mbufs} != .],
  [echo "App num mbufs            :" $NUM_MBUFS])
AS_IF([test .${with_app_mbufs_cache_size} != .],
  [echo "App mbufs cache size     :" $MBUF_CACHE_SIZE])
AS_IF([test .${with_app_default_burst_size} != .],
  [echo "App default burst size   :" $DEFAULT_BURST_SIZE])
AS_IF([test .${with_app_max_if} != .],
  [echo "App maximum interfaces   :" $MAX_IF])
