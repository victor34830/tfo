/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright(c) 2022 P Quentin Armitage <quentin@armitage.org.uk>
 */

/*
** tfo_debug.c for tcp flow optimizer
**
** Author: P Quentin Armitage <quentin@armitage.org.uk>
**           Olivier Gournet <ogournet@corp.free.fr>
**
*/

#include "tfo_config.h"

#ifdef WRITE_PCAP
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/utsname.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>

#include <rte_net.h>
#include <rte_tcp.h>
#ifdef WRITE_PCAP
#include <rte_cycles.h>
#include <rte_pcapng.h>
#include <rte_errno.h>
#include <rte_version.h>
#include <rte_malloc.h>
#endif

#include "tfo_common.h"
#include "tfo_worker.h"
#include "tfo_rbtree.h"
#include "tfo_debug.h"

#ifdef WRITE_PCAP
static thread_local struct rte_mempool *pcap_mempool;
static thread_local int pcap_priv_fd;
static thread_local rte_pcapng_t *pcap_priv;
static thread_local int pcap_pub_fd;
static thread_local rte_pcapng_t *pcap_pub;
static thread_local int pcap_all_fd;
static thread_local rte_pcapng_t *pcap_all;
bool save_pcap = false;
uint16_t port_id = 0;
uint16_t queue_idx = 0;
#endif


/****************************************************************************/
/* DEBUGGING FUNCTIONS */
/****************************************************************************/

#if defined NEED_DUMP_DETAILS || defined DEBUG_MEM || defined DEBUG_PKT_RX
static const char *state_names[] = {
	"SYN",
	"SYN_ACK",
	"ESTABLISHED",
	"CLEAR_OPT"
};

static const char *timer_names[] = {
	"NONE",
	"RTO",
	"PTO",
	"REO",
	"ZERO-WIN",
	"KEEPALIVE"
};

static thread_local char unknown_state_buf[21];		// "UNKNOWN (%u)
#endif

#ifdef NEED_DUMP_DETAILS
static thread_local time_ns_t last_time;
#endif

#ifdef DEBUG_DLSPEED
/* This code is "borrowed" from wget. wget has shown that the download
 * speed sometimes drops by 30% or more then gradually improves again.
 * We need to same code as wget so that we can write to the logs when
 * this happens.
 *
 * This code attempts to maintain the notion of a "current" download
 * speed, over the course of no less than 3s.  (Shorter intervals
 * produce very erratic results.)

 * To do so, it samples the speed in 150ms intervals and stores the
 * recorded samples in a FIFO history ring.  The ring stores no more
 * than 20 intervals, hence the history covers the period of at least
 * three seconds and at most 20 reads into the past.  This method
 * should produce reasonable results for downloads ranging from very
 * slow to very fast.

 * The idea is that for fast downloads, we get the speed over exactly
 * the last three seconds.  For slow downloads (where a network read
 * takes more than 150ms to complete), we get the speed over a larger
 * time period, as large as it takes to complete twenty reads.  This
 * is good because slow downloads tend to fluctuate more and a
 * 3-second average would be too erratic.
 */
void
update_speed_ring(struct tfo_side *fos, uint64_t howmuch)
{
	struct dl_speed_hist *hist = &fos->dl.hist;
	time_ns_t recent_age = now - fos->dl.recent_start;

	/* Update the download count. */
	fos->dl.recent_bytes += howmuch;
	if (!fos->dl.recent_start) {
		fos->dl.recent_start = now;
		return;
	}

	/* For very small time intervals, we return after having updated the
	 * "recent" download count.  When its age reaches or exceeds minimum
	 * sample time, it will be recorded in the history ring. */
	if (recent_age < DLSPEED_SAMPLE_MIN)
		return;

	if (!howmuch) {
		/* If we're not downloading anything, we might be stalling,
		 * i.e. not downloading anything for an extended period of time.
		 * Since 0-reads do not enter the history ring, recent_age
		 * effectively measures the time since last read. */
		if (recent_age >= STALL_START_TIME) {
			/* If we're stalling, reset the ring contents because it's
			 * stale and because it will make bar_update stop printing
			 * the (bogus) current bandwidth.  */
			fos->dl.stalled = true;
			memset(hist, 0, sizeof(*hist));
			fos->dl.recent_bytes = 0;
		}
		return;
	}

	/* We now have a non-zero amount to store to the speed ring */

	/* If the stall status was acquired, reset it. */
	if (fos->dl.stalled) {
		fos->dl.stalled = false;
		/* "recent_age" includes the entire stalled period, which
		 * could be very long.  Don't update the speed ring with that
		 * value because the current bandwidth would start too small.
		 * Start with an arbitrary (but more reasonable) time value and
		 * let it level out.
		 */
		recent_age = 1;
	}

	/* Store "recent" bytes and download time to history ring at the position POS.  */

	/* To correctly maintain the totals, first invalidate existing data
	 * (least recent in time) at this position. */
	hist->total_time  -= hist->times[hist->pos];
	hist->total_bytes -= hist->bytes[hist->pos];

	/* Now store the new data and update the totals. */
	hist->times[hist->pos] = recent_age;
	hist->bytes[hist->pos] = fos->dl.recent_bytes;
	hist->total_time  += recent_age;
	hist->total_bytes += fos->dl.recent_bytes;

	/* Start a new "recent" period. */
	fos->dl.recent_start = now;
	fos->dl.recent_bytes = 0;

	/* Advance the current ring position. */
	if (++hist->pos == DLSPEED_HISTORY_SIZE)
		hist->pos = 0;

#if 0
	/* Sledgehammer check to verify that the totals are accurate. */
	int i;
	uint64_t sumt = 0, sumb = 0;
	for (i = 0; i < DLSPEED_HISTORY_SIZE; i++) {
		sumt += hist->times[i];
		sumb += hist->bytes[i];
	}
	assert (sumb == hist->total_bytes);
// The following coment does not work when ising ns timers
	/* We can't use assert(sumt==hist->total_time) because some
	 precision is lost by adding and subtracting floating-point
	 numbers.  But during a download this precision should not be
	 detectable, i.e. no larger than 1ns.  */
	time_ns_t diff = sumt - hist->total_time;
	if (diff < 0) diff = -diff;
	assert (diff < 1);
#endif
}

/* Calculate the download rate and trim it as appropriate for the
   speed.  Appropriate means that if rate is greater than 1K/s,
   kilobytes are used, and if rate is greater than 1MB/s, megabytes
   are used.

   UNITS is zero for B/s, one for KB/s, two for MB/s, and three for
   GB/s.  */

bool report_bps;

static uint64_t
convert_to_bits(uint64_t bytes)
{
	if (report_bps)
		return bytes * 8;

	return bytes;
}

static uint64_t
calc_rate(uint64_t bytes, time_ns_t nano_secs, int *units)
{
	uint64_t dlrate, dlrate_mille;
	uint64_t bibyte;

	if (!report_bps)
		bibyte = 1024;
	else
		bibyte = 1000;

#if 0
	if (secs == 0)
		/* If elapsed time is exactly zero, it means we're under the
		 * resolution of the timer.  This can easily happen on systems
		 * that use time() for the timer.  Since the interval lies between
		 * 0 and the timer's resolution, assume half the resolution. */
		secs = ptimer_resolution () / 2.0;
#endif

	dlrate_mille = nano_secs ? convert_to_bits(bytes * 1000000000) / (nano_secs / 1000) : 0;
	dlrate = dlrate_mille / 1000;
	if (dlrate < bibyte)
		*units = 0;
	else if (dlrate < (bibyte * bibyte))
		*units = 1, dlrate_mille /= bibyte;
	else if (dlrate < (bibyte * bibyte * bibyte))
		*units = 2, dlrate_mille /= (bibyte * bibyte);
	else if (dlrate < (bibyte * bibyte * bibyte * bibyte))
		*units = 3, dlrate_mille /= (bibyte * bibyte * bibyte);
	else {
		*units = 4, dlrate_mille /= (bibyte * bibyte * bibyte * bibyte);
#if 0
		if (dlrate_mille > 99.99)
			dlrate_mille = 99.99; // upper limit 99.99TB/s
#endif
	}

	return dlrate_mille;
}

#if 0
/* Return a printed representation of the download rate, along with
   the units appropriate for the download speed.  */
static const char *
retr_rate (uint64_t bytes, time_ns_t n_secs)
{
  static char res[20];
  static const char *rate_names[] = {"B/s", "KB/s", "MB/s", "GB/s", "TB/s" };
  static const char *rate_names_bits[] = {"b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s" };
  int units;

  uint64_t dlrate = calc_rate(bytes, n_secs, &units);
  /* Use more digits for smaller numbers (regardless of unit used),
     e.g. "1022", "247", "12.5", "2.38".  */
  snprintf(res, sizeof(res), "%lu.%.*lu %s",
	   dlrate / 1000,
	   dlrate >= 100000 ? 0 : dlrate >= 10000 ? 1 : 2,
	   dlrate >= 100000 ? 0 : dlrate >= 10000 ? (dlrate % 1000) / 100 : (dlrate % 1000) / 10,
	   !report_bps ? rate_names[units]: rate_names_bits[units]);

  return res;
}
#endif

static const char *short_units[] = { " B/s", "KB/s", "MB/s", "GB/s", "TB/s" };
static const char *short_units_bits[] = { " b/s", "Kb/s", "Mb/s", "Gb/s", "Tb/s" };

void
print_dl_speed(struct tfo_side *fos)
{
	/* " 12.52Kb/s or 12.52KB/s" */
	if (fos->dl.hist.total_time > 0 && fos->dl.hist.total_bytes) {
		int units = 0;
		/* Calculate the download speed using the history ring and
		 * recent data that hasn't made it to the ring yet. */
		uint64_t dlquant = fos->dl.hist.total_bytes + fos->dl.recent_bytes;
		time_ns_t dltime = fos->dl.hist.total_time + (now - fos->dl.recent_start);
		uint64_t dlspeed = calc_rate(dlquant, dltime, &units);
		printf("%lu.%*.*lu%s", dlspeed / 1000,
			dlspeed >= 100000 ? 0 : dlspeed >= 10000 ? 1 : 2,
			dlspeed >= 100000 ? 0 : dlspeed >= 10000 ? 1 : 2,
			dlspeed >= 100000 ? 0 : dlspeed >= 10000 ? (dlspeed % 1000) / 100 : (dlspeed % 1000) / 10,
			!report_bps ? short_units[units] : short_units_bits[units]);
	}
}
#endif

#if defined DEBUG_PKT_SANITY || defined DEBUG_CHECK_PKTS || defined DEBUG_PKT_VALID || defined DEBUG_CLEAR_OPTIMIZE
static void
dump_bytes(const void *start, size_t len, const char *what)
{
	unsigned i;
	const unsigned char *p = start;

	printf("\n%s:", what);

	for (i = 0; i < len; i++) {
		if (!(i % 16))
			printf("\n%p: ", p + i);
		else if ((!i % 8))
			printf(" ");
		printf(" %2.2x", p[i]);
	}
	printf("\n");
}

#if defined DEBUG_PKT_SANITY || defined DEBUG_CHECK_PKTS
static void
dump_pkt_mbuf(const struct tfo_pkt *pkt)
{
	dump_bytes(pkt, sizeof(struct tfo_pkt), "tfo_pkt");
	if (pkt->m) {
		dump_bytes(pkt->m, sizeof(struct rte_mbuf), "mbuf");
		dump_bytes(rte_pktmbuf_mtod(pkt->m, const void *), pkt->m->data_len + 0x10, "data + 0x10");
	}
}
#endif

#if defined DEBUG_PKT_VALID || defined DEBUG_CLEAR_OPTIMIZE
void
dump_pkt_ctx_mbuf(const struct tfo_pktrx_ctx *tr)
{
	dump_bytes(tr, sizeof(struct tfo_pktrx_ctx), "tfo_pkt");
	if (tr->m) {
		dump_bytes(tr->m, sizeof(struct rte_mbuf), "mbuf");
		dump_bytes(rte_pktmbuf_mtod(tr->m, const void *), tr->m->data_len + 0x10, "data + 0x10");
	}
}
#endif
#endif //!(defined DEBUG_PKT_SANITY || defined DEBUG_CHECK_PKTS || defined DEBUG_PKT_VALID || defined DEBUG_CLEAR_OPTIMIZE)

#if defined NEED_DUMP_DETAILS || defined DEBUG_MEM || defined DEBUG_PKT_RX
const char *
get_state_name(enum tcp_state state)
{
	if (state < sizeof(state_names) / sizeof(state_names[0]))
		return state_names[state];

	if (state == TFO_STATE_NONE)
		return "NONE";

	sprintf(unknown_state_buf, "UNKNOWN (%u)", state);

	return unknown_state_buf;
}

const char *
get_timer_name(enum tfo_timer timer)
{
	if (timer < sizeof(timer_names) / sizeof(timer_names[0]))
		return timer_names[timer];

	sprintf(unknown_state_buf, "UNKNOWN (%u)", timer);

	return unknown_state_buf;
}
#endif


#if defined DEBUG_MEMPOOL || defined DEBUG_ACK_MEMPOOL || defined DEBUG_MEMPOOL_INIT || defined DEBUG_ACK_MEMPOOL_INIT || defined DEBUG_PCAP_MEMPOOL
static void
__show_mempool(FILE *fp, const char *name)
{
	const char *bdr_fmt = "==========";
	char bdr_str[32];

	snprintf(bdr_str, sizeof(bdr_str), " show - MEMPOOL ");
	fprintf(fp, "%s%s%s\n", bdr_fmt, bdr_str, bdr_fmt);

	if (name != NULL) {
		struct rte_mempool *ptr = rte_mempool_lookup(name);
		if (ptr != NULL) {
			struct rte_mempool_ops *ops;
			uint64_t flags = ptr->flags;

			ops = rte_mempool_get_ops(ptr->ops_index);
			fprintf(fp, "  - Name: %s on socket %d\n"
				"  - flags:\n"
				"\t  -- No spread (%c)\n"
				"\t  -- No cache align (%c)\n"
				"\t  -- SP put (%c), SC get (%c)\n"
				"\t  -- Pool created (%c)\n"
				"\t  -- No IOVA config (%c)\n"
				"\t  -- Not used for IO (%c)\n",
				ptr->name,
				ptr->socket_id,
				(flags & RTE_MEMPOOL_F_NO_SPREAD) ? 'y' : 'n',
				(flags & RTE_MEMPOOL_F_NO_CACHE_ALIGN) ? 'y' : 'n',
				(flags & RTE_MEMPOOL_F_SP_PUT) ? 'y' : 'n',
				(flags & RTE_MEMPOOL_F_SC_GET) ? 'y' : 'n',
				(flags & RTE_MEMPOOL_F_POOL_CREATED) ? 'y' : 'n',
				(flags & RTE_MEMPOOL_F_NO_IOVA_CONTIG) ? 'y' : 'n',
				(flags & RTE_MEMPOOL_F_NON_IO) ? 'y' : 'n');
			fprintf(fp, "  - Size %u Cache %u element %u\n"
				"  - header %u trailer %u\n"
				"  - private data size %u\n",
				ptr->size,
				ptr->cache_size,
				ptr->elt_size,
				ptr->header_size,
				ptr->trailer_size,
				ptr->private_data_size);
			fprintf(fp, "  - memezone - socket %d\n",
				ptr->mz->socket_id);
			fprintf(fp, "  - Count: avail (%u), in use (%u)\n",
				rte_mempool_avail_count(ptr),
				rte_mempool_in_use_count(ptr));
			fprintf(fp, "  - ops_index %d ops_name %s\n",
				ptr->ops_index, ops ? ops->name : "NA");

			return;
		}
	}

	rte_mempool_list_dump(fp);
}

#if defined DEBUG_MEMPOOL_INIT || defined DEBUG_ACK_MEMPOOL_INIT
__visible
#else
static
#endif
void
show_mempool(const char *name)
{
	__show_mempool(stdout, name);
}
#endif

#ifdef WRITE_PCAP
static void
open_pcap(void)
{
	pid_t tid = gettid();
	char filename[100];
	struct utsname uts;
	char osname[sizeof(uts.sysname) + 1 + sizeof(uts.release) + 1];
	char appname[50];

	uname(&uts);
	sprintf(osname, "%s %s", uts.sysname, uts.release);
	sprintf(appname, "tfo 0.2 %s", rte_version());

	sprintf(filename, "/tmp/tfo-priv-%u-%u-%d.pcapng", port_id, queue_idx, tid);
	pcap_priv_fd = open(filename, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP);
	pcap_priv = rte_pcapng_fdopen(pcap_priv_fd, osname, uts.machine, appname, "Packets on private side");

	sprintf(filename, "/tmp/tfo-pub-%u-%u-%d.pcapng", port_id, queue_idx, tid);
	pcap_pub_fd = open(filename, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP);
	pcap_pub = rte_pcapng_fdopen(pcap_pub_fd, osname, uts.machine, appname, "Packets on public side");

	sprintf(filename, "/tmp/tfo-all-%u-%u-%d.pcapng", port_id, queue_idx, tid);
	pcap_all_fd = open(filename, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP);
	pcap_all = rte_pcapng_fdopen(pcap_all_fd, osname, uts.machine, appname, "Packets on both sides");
}

static inline void
write_and_free_pcap(struct rte_mbuf **pcap_bufs_all, uint16_t *nb_all,
			struct rte_mbuf **pcap_bufs_pub, uint16_t *nb_pub,
			struct rte_mbuf **pcap_bufs_priv, uint16_t *nb_priv)
{
	if (*nb_all) {
		rte_pcapng_write_packets(pcap_all, pcap_bufs_all, *nb_all);
		rte_pktmbuf_free_bulk(pcap_bufs_all, *nb_all);
		*nb_all = 0;
	}

	if (*nb_pub) {
		rte_pcapng_write_packets(pcap_pub, pcap_bufs_pub, *nb_pub);
		rte_pktmbuf_free_bulk(pcap_bufs_pub, *nb_pub);
		*nb_pub = 0;
	}

	if (*nb_priv) {
		rte_pcapng_write_packets(pcap_priv, pcap_bufs_priv, *nb_priv);
		rte_pktmbuf_free_bulk(pcap_bufs_priv, *nb_priv);
		*nb_priv = 0;
	}
}

void
write_pcap(struct rte_mbuf **bufs, uint16_t nb_buf, enum rte_pcapng_direction direction)
{
	uint64_t tsc = rte_rdtsc();
	struct rte_mbuf **pcap_bufs_all;
	struct rte_mbuf **pcap_bufs_priv;
	struct rte_mbuf **pcap_bufs_pub;
	uint16_t i;
	uint16_t nb_pub = 0;
	uint16_t nb_priv = 0;
	uint16_t nb_all = 0;
	struct rte_mbuf *copy_all, *copy_side;
	char packet_pool_name[16];
	bool failed = false;

	if (!nb_buf)
		return;

	if (!pcap_mempool) {
		if (rte_pktmbuf_data_room_size(bufs[0]->pool) >= rte_pcapng_mbuf_size(1500))
			pcap_mempool = bufs[0]->pool;
		else {
			snprintf(packet_pool_name, sizeof(packet_pool_name), "pcap_pool_%u", port_id);
			/* We want BURST_SIZE * 2 * 2 - every received packet could be forwarded and ack'd, and
			 * we save each packet twice. The correct way to do this would be for BURST_SIZE to be
			 * passed as a parameter at tfo_worker_init() */
			pcap_mempool = rte_pktmbuf_pool_create(packet_pool_name,
								32 * 2 * 2 * 2 - 1,
								32,
								0,
								rte_pcapng_mbuf_size(1500),
								rte_socket_id());
		}
	}

	pcap_bufs_all = rte_malloc("pcap_all", nb_buf * sizeof(struct rte_mbuf *), 0);
	pcap_bufs_priv = rte_malloc("pcap_all", nb_buf * sizeof(struct rte_mbuf *), 0);
	pcap_bufs_pub = rte_malloc("pcap_all", nb_buf * sizeof(struct rte_mbuf *), 0);

	for (i = 0; i < nb_buf; i++) {
		copy_all = rte_pcapng_copy(port_id, queue_idx, bufs[i], pcap_mempool, UINT32_MAX, tsc, direction);
		copy_side = rte_pcapng_copy(port_id, queue_idx, bufs[i], pcap_mempool, UINT32_MAX, tsc, direction);
		if (!copy_all || !copy_side) {
			if (copy_all || copy_side)
				rte_pktmbuf_free(copy_all ? copy_all : copy_side);

			printf("rte_pcap_copy failed, i %u, nb_all %u, nb_buf %u, rte_errno %d\n", i, nb_all, nb_buf, rte_errno);

			if (nb_all == 0 || failed)
				return;

			write_and_free_pcap(pcap_bufs_all, &nb_all, pcap_bufs_pub, &nb_pub, pcap_bufs_priv, &nb_priv);

			failed = true;
			i--;
			continue;
		}

		failed = false;
		pcap_bufs_all[nb_all++] = copy_all;
		if (!!(bufs[i]->ol_flags & config->dynflag_priv_mask) ==
		    (direction == RTE_PCAPNG_DIRECTION_IN))
			pcap_bufs_priv[nb_priv++] = copy_side;
		else
			pcap_bufs_pub[nb_pub++] = copy_side;
	}

#ifdef DEBUG_PCAP_MEMPOOL
	snprintf(packet_pool_name, sizeof(packet_pool_name), "pcap_pool_%u", port_id);
	show_mempool(packet_pool_name);
#endif

	write_and_free_pcap(pcap_bufs_all, &nb_all, pcap_bufs_pub, &nb_pub, pcap_bufs_priv, &nb_priv);

	rte_free(pcap_bufs_all);
	rte_free(pcap_bufs_pub);
	rte_free(pcap_bufs_priv);
}
#endif

#if (defined DEBUG_QUEUE_PKTS && defined DEBUG_PKTS) || defined DEBUG_CHECKSUM || defined DEBUG_CHECK_ADDR
static void
dump_m(struct rte_mbuf *m)
{
	uint8_t *p = rte_pktmbuf_mtod(m, uint8_t *);

	for (unsigned i = 0; i < m->data_len; i++) {
		if (i && !(i % 8)) {
			if (!(i % 16))
				printf("\n");
			else
				printf(" ");
		}
		if (!(i % 16))
			printf("%4.4x\t", i);
		else
			printf(" ");
		printf("%2.2x", p[i]);
	}
	printf("\n");
}
#endif

#ifdef DEBUG_XMIT_LIST
void
check_xmit_ts_list(struct tfo_side *fos)
{
	struct tfo_pkt *pkt, *pkt1;
	unsigned pkt_count = 0;
	bool found_last_sent = false;

	if (list_empty(&fos->xmit_ts_list)) {
		if (!list_is_head(fos->last_sent, &fos->xmit_ts_list) || fos->pkts_in_flight)
			printf("ERROR - ef %p fos %p xmit_ts_list (%p-%p<->%p) empty but last_sent %p in_flight %u\n", fos->ef, fos, &fos->xmit_ts_list, fos->xmit_ts_list.prev, fos->xmit_ts_list.next, fos->last_sent, fos->pkts_in_flight);
		return;
	}

	list_for_each_entry(pkt, &fos->xmit_ts_list, xmit_ts_list) {
		/* Check we haven't traversed more packets than are on pktlist */
		if (++pkt_count > fos->pktcount) {
			printf("xmit_ts_list prev %p next %p\n",
				list_entry(fos->xmit_ts_list.prev, struct tfo_pkt, xmit_ts_list),
				list_entry(fos->xmit_ts_list.next, struct tfo_pkt, xmit_ts_list));
				list_for_each_entry(pkt1, &fos->xmit_ts_list, xmit_ts_list) {
				printf("  pkt %p m %p xmit_list prev %p next %p\n",
					pkt, pkt->m,
					list_prev_entry(pkt, xmit_ts_list),
					list_next_entry(pkt, xmit_ts_list));
				if (pkt1 == pkt)
					break;
			}

			printf("ERROR %uth packet %p found on fos %p xmit_ts_list when only %u queued packets\n",
				pkt_count, pkt, fos, fos->pktcount);
			return;
		}

		/* Check previous and next pointers make sense */
		if (pkt->xmit_ts_list.prev->next != &pkt->xmit_ts_list || /* We wouldn't be here it this weren't correct! */
		    pkt->xmit_ts_list.next->prev != &pkt->xmit_ts_list) {
			printf("ERROR prev/next in fos %p xmit_ts_list pkt %p prev %p, prev->next %p, next %p next->prev %p\n",
				fos, pkt,
				pkt->xmit_ts_list.prev, pkt->xmit_ts_list.prev->next,
				pkt->xmit_ts_list.next, pkt->xmit_ts_list.next->prev);
			return;
		}

		/* Check the packet is on fos->pktlist */
		list_for_each_entry(pkt1, &fos->pktlist, list) {
			if (pkt1 == pkt)
				break;
		}
		if (pkt1 != pkt) {
			printf("ERROR fos %p xmit_list pkt %p not found on packet list\n", fos, pkt);
			return;
		}

		if (fos->last_sent == &pkt->xmit_ts_list)
			found_last_sent = true;
	}

	if (!found_last_sent &&
	    (fos->last_sent != &fos->xmit_ts_list || fos->pkts_in_flight))
		printf("ERROR - ef %p fos %p last_sent %p not on xmit_ts_list (%p-%p<->%p) in_flight %u\n", fos->ef, fos, fos->last_sent,
				&fos->xmit_ts_list, fos->xmit_ts_list.prev, fos->xmit_ts_list.next, fos->pkts_in_flight);
}
#endif

#ifdef NEED_DUMP_DETAILS
#define	SI	"  "
#define	SIS	" "
time_ns_t start_ns;

thread_local char debug_time_abs[19];
thread_local char debug_time_rel[20 + 1 + 9 + 5 + 20 + 1 + 9 + 1];

void
format_debug_time(void)
{
	struct timespec ts_wallclock;
	struct tm tm;
	time_ns_t gap;

	if (!last_time)
		last_time = start_ns;

	clock_gettime(CLOCK_REALTIME, &ts_wallclock);
	gap = now - last_time;
	localtime_r(&ts_wallclock.tv_sec, &tm);
	strftime(debug_time_abs, sizeof(debug_time_abs), "%T", &tm);
	sprintf(debug_time_abs + 8, ".%9.9ld", ts_wallclock.tv_nsec);
	sprintf(debug_time_rel, NSEC_TIME_PRINT_FORMAT " gap " NSEC_TIME_PRINT_FORMAT, NSEC_TIME_PRINT_PARAMS(now), gap / NSEC_PER_SEC, gap % NSEC_PER_SEC);
	last_time = now;
}

static void
print_side(FILE *fp, const struct tfo_side *s,
#ifndef DEBUG_RELATIVE_SEQ
	   __attribute__((unused))
#endif
				   const struct tfo_side *s_other)
{
	const struct tfo_eflow *ef = s->ef;
	struct tfo_pkt *p;
	uint32_t next_exp;
	time_ns_t time_diff;
	uint16_t num_gaps = 0;
	uint8_t *data_start;
	unsigned sack_entry, last_sack_entry;
	uint16_t num_in_flight = 0;
	uint16_t num_sacked = 0;
	uint16_t num_queued = 0;
	char flags[14];
#ifdef DEBUG_MBUF_COOKIES
	uint64_t cookie;
#endif

	flags[0] = '\0';
	if (s->flags & TFO_SIDE_FL_IN_RECOVERY) strcat(flags, "R");
	if (s->flags & TFO_SIDE_FL_ENDING_RECOVERY) strcat(flags, "r");
	if (s->flags & TFO_SIDE_FL_RACK_REORDERING_SEEN) strcat(flags, "O");
	if (s->flags & TFO_SIDE_FL_DSACK_ROUND) strcat(flags, "D");
	if (s->flags & TFO_SIDE_FL_DSACK_SEEN) strcat(flags, "d");
	if (s->flags & TFO_SIDE_FL_TLP_IN_PROGRESS) strcat(flags, "P");
	if (s->flags & TFO_SIDE_FL_TLP_IS_RETRANS) strcat(flags, "t");
	if (s->flags & TFO_SIDE_FL_RTT_CALC_IN_PROGRESS) strcat(flags, "C");
	if (s->flags & TFO_SIDE_FL_TLP_NEW_RTT) strcat(flags, "n");
	if (s->flags & TFO_SIDE_FL_FIN_RX) strcat(flags, "F");
	if (s->flags & TFO_SIDE_FL_CLOSED) strcat(flags, "c");
	if (s->flags & TFO_SIDE_FL_RTT_FROM_SYN) strcat(flags, "S");
#ifdef CALC_TS_CLOCK
	if (s->flags & TFO_SIDE_FL_TS_CLOCK_OVERFLOW) strcat (flags, "T");
#endif

	fprintf(fp, SI SI SI "rcv_nxt %u snd_una %u snd_nxt %u snd_win %u rcv_win %u ssthresh 0x%x"
		" cwnd 0x%x dup_ack %u last_rcv_win_end %u",
		s->rcv_nxt, s->snd_una, s->snd_nxt, s->snd_win, s->rcv_win, s->ssthresh, s->cwnd, s->dup_ack, s->last_rcv_win_end);
	fprintf(fp, " first_seq %u", s->first_seq);
	if (s->flags & TFO_SIDE_FL_FIN_RX)
		fprintf(fp, " fin_seq %u", s->fin_seq);
	fprintf(fp, "\n" SI SI SI SIS "snd_win_shift %u rcv_win_shift %u mss %u flags-%s packet_type 0x%x in_flight %u queued %u",
		s->snd_win_shift, s->rcv_win_shift, s->mss, flags, s->packet_type, s->pkts_in_flight, s->pkts_queued_send);
	if (ef->flags & TFO_EF_FL_SACK)
		fprintf(fp, " rtt_min %u", minmax_get(&s->rtt_min));
	if (!list_empty(&s->xmit_ts_list))
		fprintf(fp, " xmit_ts seq %u <-> %u",
			list_first_entry(&s->xmit_ts_list, struct tfo_pkt, xmit_ts_list)->seq,
			list_last_entry(&s->xmit_ts_list, struct tfo_pkt, xmit_ts_list)->seq);
	if (s->last_sent == &s->xmit_ts_list)
		fprintf(fp, " no last sent");
	else
		fprintf(fp, " last sent 0x%x", list_entry(s->last_sent, struct tfo_pkt, xmit_ts_list)->seq);
	fprintf(fp, " last_ack %u pktcount %u\n", s->last_ack_sent, s->pktcount);
	if ((ef->flags & TFO_EF_FL_SACK) &&
	     (s->sack_entries || s->sack_gap)) {
		fprintf(fp, SI SI SI SIS "sack_gaps %u sack_entries %u, first_entry %u", s->sack_gap, s->sack_entries, s->first_sack_entry);
		last_sack_entry = (s->first_sack_entry + s->sack_entries + MAX_SACK_ENTRIES - 1) % MAX_SACK_ENTRIES;
		for (sack_entry = s->first_sack_entry; ; sack_entry = (sack_entry + 1) % MAX_SACK_ENTRIES) {
			fprintf(fp, " [%u]: 0x%x -> 0x%x", sack_entry, s->sack_edges[sack_entry].left_edge, s->sack_edges[sack_entry].right_edge);
			if (sack_entry == last_sack_entry)
				break;
		}
		fprintf(fp, "\n");
	}
	fprintf(fp, SI SI SI SIS "srtt %u rttvar %u rto %u #pkt %u, ttl %u", s->srtt_us, s->rttvar_us, s->rto_us, s->pktcount, s->rcv_ttl);
	if (ef->flags & TFO_EF_FL_IPV6)
		fprintf(fp, ", vtc_flow 0x%x", s->vtc_flow);
	fprintf(fp, " snd_win_end 0x%x rcv_win_end 0x%x",
		s->snd_una + (s->snd_win << s->snd_win_shift),
		s->rcv_nxt + (s->rcv_win << s->rcv_win_shift));
#ifdef DEBUG_RTT_MIN
	if (ef->flags & TFO_EF_FL_SACK) {
		fprintf(fp, " rtt_min [0] %u," NSEC_TIME_PRINT_FORMAT,
			s->rtt_min.s[0].v, NSEC_TIME_PRINT_PARAMS(s->rtt_min.s[0].t * NSEC_PER_USEC));
		if (s->rtt_min.s[1].t == s->rtt_min.s[0].t &&
		    s->rtt_min.s[1].v == s->rtt_min.s[0].v)
			fprintf(fp, " [1] = [0]");
		else
			fprintf(fp, " [1] %u," NSEC_TIME_PRINT_FORMAT,
				s->rtt_min.s[1].v, NSEC_TIME_PRINT_PARAMS(s->rtt_min.s[1].t * NSEC_PER_USEC));
		if (s->rtt_min.s[2].t == s->rtt_min.s[1].t &&
		    s->rtt_min.s[2].v == s->rtt_min.s[2].v)
			fprintf(fp, " [2] = [1]");
		else
			fprintf(fp, " [2] %u," NSEC_TIME_PRINT_FORMAT,
				s->rtt_min.s[2].v, NSEC_TIME_PRINT_PARAMS(s->rtt_min.s[2].t * NSEC_PER_USEC));
	}
#endif
	if (ef->flags & TFO_EF_FL_TIMESTAMP) {
		fprintf(fp, "\n" SI SI SI SIS "ts_recent %1$u (0x%1$x) latest_ts_val %2$u (0x%2$x)", rte_be_to_cpu_32(s->ts_recent), s->latest_ts_val);
#ifdef CALC_TS_CLOCK
		fprintf(fp, " last_ts_val_sent %u TS start %u",
				s->last_ts_val_sent, s->ts_start);
		fprintf(fp, " at " NSEC_TIME_PRINT_FORMAT, NSEC_TIME_PRINT_PARAMS(s->ts_start_time));
		if (s->flags & TFO_SIDE_FL_TS_CLOCK_OVERFLOW)
			fprintf(fp, " ovf");
		fprintf(fp, " nsecs per tock %u", s->nsecs_per_tock);
#endif
	}

#ifndef CWND_USE_ALTERNATE
	fprintf(fp, " cum_ack 0x%x", s->cum_ack);
#endif
	fprintf(fp, " ack_delay ");
	if (s->delayed_ack_timeout == TFO_INFINITE_TS)
		fprintf(fp, "unset");
	else if (s->delayed_ack_timeout == TFO_ACK_NOW_TS)
		fprintf(fp, "3WHS ACK");
	else if (s->delayed_ack_timeout >= now)
		fprintf(fp, NSEC_TIME_PRINT_FORMAT " in " NSEC_TIME_PRINT_FORMAT, NSEC_TIME_PRINT_PARAMS(s->delayed_ack_timeout), NSEC_TIME_PRINT_PARAMS_ABS(s->delayed_ack_timeout - now));
	else
		fprintf(fp, NSEC_TIME_PRINT_FORMAT " - " NSEC_TIME_PRINT_FORMAT " ago", NSEC_TIME_PRINT_PARAMS(s->delayed_ack_timeout), NSEC_TIME_PRINT_PARAMS_ABS(now - s->delayed_ack_timeout));
#ifdef DEBUG_RACK
	if (using_rack(ef)) {
		time_diff = now - s->rack_xmit_ts;
		fprintf(fp, "\n" SI SI SI SIS "RACK: xmit_ts " NSEC_TIME_PRINT_FORMAT " end_seq %u segs_sacked %u fack %u rtt %u reo_wnd %u dsack_round 0x%x reo_wnd_mult %u\n"
		       SI SI SI SIS "      reo_wnd_persist %u tlp_end_seq %u tlp_max_ack_delay %u",
			NSEC_TIME_PRINT_PARAMS_ABS(time_diff), s->rack_end_seq, s->rack_total_segs_sacked, s->rack_fack,
			s->rack_rtt_us, s->rack_reo_wnd_us, s->rack_dsack_round, s->rack_reo_wnd_mult,
			s->rack_reo_wnd_persist, s->tlp_end_seq, s->tlp_max_ack_delay_us);
	}
#endif

	fprintf(fp, " recovery_end_seq 0x%x cur_timer ", s->recovery_end_seq);
	if (s->cur_timer == TFO_TIMER_NONE) fprintf(fp, "none");
	else if (s->cur_timer == TFO_TIMER_RTO) fprintf(fp, "RTO");
	else if (s->cur_timer == TFO_TIMER_PTO) fprintf(fp, "PTO");
	else if (s->cur_timer == TFO_TIMER_REO) fprintf(fp, "REO");
	else if (s->cur_timer == TFO_TIMER_ZERO_WINDOW) fprintf(fp, "ZW");
	else if (s->cur_timer == TFO_TIMER_KEEPALIVE) fprintf(fp, "KA");
	else fprintf(fp, "unknown %u", s->cur_timer);
	if (s->timeout_at == TFO_INFINITE_TS)
		fprintf(fp, " unset");
	else if (s->timeout_at >= now)
		fprintf(fp, " timeout " NSEC_TIME_PRINT_FORMAT " in " NSEC_TIME_PRINT_FORMAT, NSEC_TIME_PRINT_PARAMS(s->timeout_at), NSEC_TIME_PRINT_PARAMS_ABS(s->timeout_at - now));
	else
		fprintf(fp, " timeout " NSEC_TIME_PRINT_FORMAT " - " NSEC_TIME_PRINT_FORMAT " ago", NSEC_TIME_PRINT_PARAMS(s->timeout_at), NSEC_TIME_PRINT_PARAMS_ABS(now - s->timeout_at));
	fprintf(fp, " ka probes %u\n", s->keepalive_probes);

#ifdef DEBUG_DLSPEED_DEBUG
	fprintf(fp, SI SI SI SIS "total: time " NSEC_TIME_PRINT_FORMAT " bytes %lu, recent: time " NSEC_TIME_PRINT_FORMAT " bytes %lu pos %d\n",
		 NSEC_TIME_PRINT_PARAMS_ABS(s->dl.hist.total_time), s->dl.hist.total_bytes, NSEC_TIME_PRINT_PARAMS_ABS(now - s->dl.recent_start), s->dl.recent_bytes, s->dl.hist.pos);
	for (unsigned i = 0; i < DLSPEED_HISTORY_SIZE; i++) {
		if (!(i % 5))
			fprintf(fp, SI SI SI SIS);
		fprintf(fp, "[%2u] " NSEC_TIME_PRINT_FORMAT " %lu", i, NSEC_TIME_PRINT_PARAMS_ABS(s->dl.hist.times[(i) % DLSPEED_HISTORY_SIZE]), s->dl.hist.bytes[(i) % DLSPEED_HISTORY_SIZE]);
		if (i % 5 == 4) {
			fprintf(fp, "\n");
		} else if (i != DLSPEED_HISTORY_SIZE - 1)
			fprintf(fp, ", ");
	}
	if (DLSPEED_HISTORY_SIZE % 5)
		fprintf(fp, "\n");
#endif

	next_exp = s->snd_una;
	unsigned i = 0;
	list_for_each_entry(p, &s->pktlist, list) {
		char s_flags[10];
		char tcp_flags[9];

		s_flags[0] = '\0';
		if (p->flags & TFO_PKT_FL_SENT) strcat(s_flags, "S");
		if (p->flags & TFO_PKT_FL_RESENT) strcat(s_flags, "R");
		if (p->flags & TFO_PKT_FL_RTT_CALC) strcat(s_flags, "r");
		if (p->flags & TFO_PKT_FL_LOST) strcat(s_flags, "L");
		if (p->flags & TFO_PKT_FL_FROM_PRIV) strcat(s_flags, "P");
		if (p->flags & TFO_PKT_FL_QUEUED_SEND) strcat(s_flags, "Q");

		i++;
		if (after(p->seq, next_exp)) {
			fprintf(fp, SI SI SI "%4u:\t  *** expected %u, gap = %u\n", i, next_exp, p->seq - next_exp);
			num_gaps++;
			i++;
		}

		/* Check ordering of packets */
		if (!list_is_first(&p->list, &s->pktlist) &&
		    !before(list_prev_entry(p, list)->seq, p->seq))
			fprintf(fp, " *** pkt not after previous pkt ERROR");
		if (!list_is_last(&p->list, &s->pktlist) &&
		    !before(segend(p), segend(list_next_entry(p, list))))
			fprintf(fp, " *** pkt ends after next pkt ends ERROR");

		data_start = p->m ? rte_pktmbuf_mtod(p->m, uint8_t *) : 0;
		if (p->m != NULL) {
			tcp_flags[0] = '\0';
			if (p->tcp->tcp_flags & RTE_TCP_SYN_FLAG) strcat(tcp_flags, "S");
			if (p->tcp->tcp_flags & RTE_TCP_ACK_FLAG) strcat(tcp_flags, "A");
			if (p->tcp->tcp_flags & RTE_TCP_URG_FLAG) strcat(tcp_flags, "U");
			if (p->tcp->tcp_flags & RTE_TCP_PSH_FLAG) strcat(tcp_flags, "P");
			if (p->tcp->tcp_flags & RTE_TCP_CWR_FLAG) strcat(tcp_flags, "C");
			if (p->tcp->tcp_flags & RTE_TCP_ECE_FLAG) strcat(tcp_flags, "E");
			if (p->tcp->tcp_flags & RTE_TCP_FIN_FLAG) strcat(tcp_flags, "F");
			if (p->tcp->tcp_flags & RTE_TCP_RST_FLAG) strcat(tcp_flags, "R");

			fprintf(fp, SI SI SI "%4u:\tm %p, seq %u%s"
#ifdef DEBUG_RELATIVE_SEQ
			       " (%u:%u)"
#endif
			       " ack %u, len %4u flags-%-3s tcp_flags-%-2s ip %ld tcp %ld",
			       i, p->m, p->seq, after(segend(p), s->snd_una + (s->snd_win << s->snd_win_shift)) ? "*" : "",
#ifdef DEBUG_RELATIVE_SEQ
			       p->seq - s_other->first_seq, p->seq - s_other->first_seq + p->seglen,
#endif
			       ntohl(p->tcp->recv_ack), p->seglen, s_flags, tcp_flags,
			       (uint8_t *)p->iph.ip4h - data_start,
			       (uint8_t *)p->tcp - data_start);
			if (ef->flags & TFO_EF_FL_TIMESTAMP || p->ts)
				fprintf(fp, " ts %ld", p->ts ? (uint8_t *)p->ts - data_start : 0U);
			if (p->sack != NULL)
				fprintf(fp, " sack %ld", (uint8_t *)p->sack - data_start);
			if ((ef->flags & TFO_EF_FL_SACK) && p->rack_segs_sacked)
				fprintf(fp, " sacked segs %u", p->rack_segs_sacked);
			fprintf(fp, " refcnt %u", p->m->refcnt);

#ifdef DEBUG_MBUF_COOKIES
			cookie = rte_mempool_get_header(p->m)->cookie;
			if (cookie == RTE_MEMPOOL_HEADER_COOKIE2)
				fprintf(fp, " FREED");
			else if (cookie != RTE_MEMPOOL_HEADER_COOKIE1)
				fprintf(fp, " COOKIE %" PRIx64, cookie);
#endif
		} else
			fprintf(fp, SI SI SI "%4u:\t               seq %u%s"
#ifdef DEBUG_RELATIVE_SEQ
			       " (%u:%u)"
#endif
			       " len %u flags-%s sacked_segs %u",
			       i, p->seq, segend(p) > s->snd_una + (s->snd_win << s->snd_win_shift) ? "*" : "",
#ifdef DEBUG_RELATIVE_SEQ
			       p->seq - s_other->first_seq, p->seq - s_other->first_seq + p->seglen,
#endif
			       p->seglen, s_flags, p->rack_segs_sacked);
		if (p->ns != TFO_TS_NONE) {
			time_diff = now - p->ns;
			fprintf(fp, " ns " NSEC_TIME_PRINT_FORMAT, NSEC_TIME_PRINT_PARAMS_ABS(time_diff));

			if (!(p->flags & TFO_PKT_FL_SENT))
				fprintf(fp, " (%lu)", p->ns);
		}
		if (!list_empty(&p->xmit_ts_list)) {
			fprintf(fp, " flgt %u <-> %u",
				list_is_first(&p->xmit_ts_list, &s->xmit_ts_list) ? 0 : list_prev_entry(p, xmit_ts_list)->seq,
				list_is_last(&p->xmit_ts_list, &s->xmit_ts_list) ? 0 : list_next_entry(p, xmit_ts_list)->seq);

			if (!(p->flags & TFO_PKT_FL_LOST))
				num_in_flight++;

			if (s->last_sent == &p->xmit_ts_list)
				fprintf(fp, " last sent");
		}

		if (p->flags & TFO_PKT_FL_QUEUED_SEND)
			num_queued++;

		if (p->rack_segs_sacked)
			num_sacked += p->rack_segs_sacked;

		if (before(p->seq, next_exp)) {
			if (!before(next_exp, segend(p)))
				fprintf(fp, " *** packet contained in previous packet ERROR");
			else
				fprintf(fp, " *** overlap = %ld", (int64_t)next_exp - (int64_t)p->seq);
		}

#ifdef DEBUG_PKT_PTRS
		if (p->m) {
			struct tfo_mbuf_priv *m_priv = get_priv_addr(p->m);

			if (m_priv->pkt != p)
				fprintf(fp, " pkt %p != priv->pkt %p ERROR", p, m_priv->pkt);
			if (m_priv->fos != s)
				fprintf(fp, " priv->fos %p != fos %p ERROR", m_priv->fos, s);
		}
#endif

		fprintf(fp, "\n");
		next_exp = segend(p);

#ifdef DEBUG_PKT_SANITY
		//const struct tfo *fo = &worker.f[ef->tfo_idx];
		if (!p->m) {
			if (!p->rack_segs_sacked) {
				dump_pkt_mbuf(p);
				fprintf(fp, "[%s] ERROR in pkt p %p p->iph.ip4h %p data_start %p recv_ack 0x%x snd_una 0x%x snd_nxt 0x%x\n",
					_spfx(s), p, p->iph.ip4h, data_start, p->tcp ? ntohl(p->tcp->recv_ack) : 0xcafeaded,
					s == ef->pub ? ef->priv->snd_una : ef->pub->snd_una, s == ef->pub ? ef->priv->snd_nxt : ef->pub->snd_nxt);
			}
		} else if ((s == ef->pub &&
		     (p->m->vlan_tci ||
		      (uint8_t *)p->iph.ip4h - data_start != 14 /* ||
		      before(ntohl(p->tcp->recv_ack), fo->priv.snd_una) ||
		      after(ntohl(p->tcp->recv_ack), fo->priv.snd_nxt) */)) ||
		    (s == ef->priv &&
		     (p->m->vlan_tci != 100 ||
		      (uint8_t *)p->iph.ip4h - data_start != 18 /* ||
		      before(ntohl(p->tcp->recv_ack), fo->pub.snd_una) ||
		      after(ntohl(p->tcp->recv_ack), fo->pub.snd_nxt) */))) {
			dump_pkt_mbuf(p);
			fprintf(fp, "[%s] ERROR in pkt vlan %u p->iph.ip4h %p data_start %p recv_ack 0x%x snd_una 0x%x snd_nxt 0x%x\n",
				_spfx(s), p->m->vlan_tci, p->iph.ip4h, data_start, ntohl(p->tcp->recv_ack),
				s == ef->pub ? ef->priv->snd_una : ef->pub->snd_una, s == ef->pub ? ef->priv->snd_nxt : ef->pub->snd_nxt);
		}
#endif
	}

	if (num_gaps != s->sack_gap)
		fprintf(fp, "ERROR *** s->sack_gap %u, num_gaps %u\n", s->sack_gap, num_gaps);

	if (s->pkts_in_flight != num_in_flight)
		fprintf(fp, "ERROR *** NUM_IN_FLIGHT should be %u\n", num_in_flight);

	if (s->pkts_queued_send != num_queued)
		fprintf(fp, "ERROR *** NUM_QUEUED should be %u\n", num_queued);

	if (s->rack_total_segs_sacked != num_sacked)
		fprintf(fp, "ERROR *** NUM_SEGS_SACKED %u should be %u\n",
			s->rack_total_segs_sacked, num_sacked);
}


static void
do_dump_eflow(FILE *fp, const struct tfo_eflow *ef)
{
	char flags[9];
	char pub_addr_str[INET6_ADDRSTRLEN];
	char priv_addr_str[INET6_ADDRSTRLEN];
	in_addr_t addr;

	flags[0] = '\0';
	if (ef->flags & TFO_EF_FL_SYN_FROM_PRIV) strcat(flags, "P");
	if (ef->flags & TFO_EF_FL_SIMULTANEOUS_OPEN) strcat(flags, "s");
	if (ef->flags & TFO_EF_FL_SACK) strcat(flags, "S");
	if (ef->flags & TFO_EF_FL_TIMESTAMP) strcat(flags, "T");
	if (ef->flags & TFO_EF_FL_IPV6) strcat(flags, "6");
	if (ef->flags & TFO_EF_FL_DUPLICATE_SYN) strcat(flags, "D");

	if (ef->flags & TFO_EF_FL_IPV6) {
		inet_ntop(AF_INET6, &ef->pub_addr.v6, pub_addr_str, sizeof(pub_addr_str));
		inet_ntop(AF_INET6, &ef->priv_addr.v6, priv_addr_str, sizeof(priv_addr_str));
	} else {
		addr = rte_be_to_cpu_32(ef->pub_addr.v4.s_addr);
		inet_ntop(AF_INET, &addr, pub_addr_str, sizeof(pub_addr_str));
		addr = rte_be_to_cpu_32(ef->priv_addr.v4.s_addr);
		inet_ntop(AF_INET, &addr, priv_addr_str, sizeof(priv_addr_str));
	}
	fprintf(fp, "%s state %s addr: priv %s pub %s port: priv %u pub %u flags-%s\n",
		_epfx(ef, NULL), get_state_name(ef->state), priv_addr_str, pub_addr_str, ef->priv_port, ef->pub_port, flags);
	fprintf(fp, "idle_timeout " NSEC_TIME_PRINT_FORMAT " (" NSEC_TIME_PRINT_FORMAT ") timer " NSEC_TIME_PRINT_FORMAT " (" NSEC_TIME_PRINT_FORMAT ") rb %p / %p \\ %p\n",
		NSEC_TIME_PRINT_PARAMS(ef->idle_timeout), NSEC_TIME_PRINT_PARAMS_ABS(ef->idle_timeout - now),
		NSEC_TIME_PRINT_PARAMS(ef->timer.time), NSEC_TIME_PRINT_PARAMS_ABS(ef->timer.time - now),
		ef->timer.node.rb_left ? container_of(ef->timer.node.rb_left, struct tfo_eflow, timer.node) : NULL,
		rb_parent(&ef->timer.node) ? container_of(rb_parent(&ef->timer.node), struct tfo_eflow, timer.node) : NULL,
		ef->timer.node.rb_right ? container_of(ef->timer.node.rb_right, struct tfo_eflow, timer.node) : NULL);
	if (ef->state == TCP_STATE_SYN)
		fprintf(fp, "svr_snd_una 0x%x cl_snd_win 0x%x cl_rcv_nxt 0x%x cl_ttl %u SYN ns " NSEC_TIME_PRINT_FORMAT "\n",
		       ef->server_snd_una, ef->client_snd_win, ef->client_rcv_nxt, ef->client_ttl, NSEC_TIME_PRINT_PARAMS(ef->start_time));
	if (ef->priv != NULL) {
		if (ef != ef->priv->ef || ef != ef->pub->ef)
			fprintf(fp, "%s ERROR flow/eflow ptr\n", _epfx(ef, NULL));
		fprintf(fp, "private: (%p)\n", ef->priv);
		print_side(fp, ef->priv, ef->pub);
		fprintf(fp, "public: (%p)\n", ef->pub);
		print_side(fp, ef->pub, ef->priv);
	}
	fprintf(fp, "\n");
}

void
dump_eflow(const struct tfo_eflow *ef)
{
	do_dump_eflow(stdout, ef);
}

static void
do_dump_details(FILE *fp, const struct tcp_worker *w)
{
	struct tfo_eflow *ef;
	unsigned i;
#ifdef DEBUG_ETHDEV
	uint16_t port;
	struct rte_eth_stats eth_stats;
#endif

	fprintf(fp, "In use: eflows %u, flows %u, packets %u, max_packets %u timer rb root %p left %p\n", w->ef_use, w->f_use, w->p_use, w->p_max_use,
		RB_EMPTY_ROOT(&timer_tree.rb_root) ? NULL : container_of(timer_tree.rb_root.rb_node, struct tfo_eflow, timer.node),
		timer_tree.rb_leftmost ? container_of(timer_tree.rb_leftmost, struct tfo_eflow, timer.node) : NULL);
	for (i = 0; i < config->hef_n; i++) {
		if (hlist_empty(&w->hef[i]))
			continue;

		hlist_for_each_entry(ef, &w->hef[i], hlist) {
			// print eflow
			do_dump_eflow(fp, ef);
		}
	}

#ifdef DEBUG_ETHDEV
	if (rte_eth_stats_get(port = (rte_lcore_id() - 1), &eth_stats))
		fprintf(fp, "Failed to get stats for port %u\n", port);
	else {
		fprintf(fp, "port %u: i (p, b, e) %lu %lu %lu o %lu %lu %lu m %lu nom %lu\n",
			port,
			eth_stats.ipackets, eth_stats.ibytes, eth_stats.ierrors,
			eth_stats.opackets, eth_stats.obytes, eth_stats.oerrors,
			eth_stats.imissed, eth_stats.rx_nombuf);

#ifdef DEBUG_MEMPOOL
		if (eth_stats.rx_nombuf)
			show_mempool(fp, "packet_pool_0");
#endif
	}
#endif //!DEBUG_ETHDEV

	fprintf(fp, "\n");
}

void
dump_details(const struct tcp_worker *w)
{
	do_dump_details(stdout, w);

#ifndef DEBUG_PRINT_TO_BUF
	fflush(stdout);
#endif
}

#ifdef DEBUG_STRUCTURES
void
do_post_pkt_dump(const struct tcp_worker *w, struct tfo_eflow *ef)
{
	if (config->option_flags & TFO_CONFIG_FL_DUMP_ALL_EFLOWS) {
		dump_details(w);
		return;
	}

	dump_eflow(ef);
}
#endif //!DEBUG_STRUCTURES

#ifdef EXPOSE_EFLOW_DUMP
__visible void
tfo_eflow_dump(void)
{
	do_dump_details(stdout, &worker);
}

__visible void
tfo_eflow_dump_fp(FILE *fp)
{
	do_dump_details(fp, &worker);
}
#endif //!EXPOSE_EFLOW_DUMP
#endif //!NEED_DUMP_DETAILS

#ifdef DEBUG_CHECK_PKTS
static unsigned
check_side_packets(const struct tfo_side *s, bool priv, const struct tfo_eflow *ef)
{
	const struct tfo_pkt *pkt;
	union {		// This mirrors union tfo_ip_p but the pointers are const
		const struct rte_ipv4_hdr *ip4h;
		const struct rte_ipv6_hdr *ip6h;
	} ip;
	const struct rte_tcp_hdr *tcp = NULL;
	uint16_t hdr_len = 0;
	uint32_t off;
	int16_t proto;
	int frag;
	bool is_ipv6 = false;
	const struct rte_vlan_hdr *vlan = NULL;
	unsigned num_error = 0;
	char errors[128];

	list_for_each_entry(pkt, &s->pktlist, list) {
		errors[0] = '\0';

		if (!pkt->m) {
			if (pkt->rack_segs_sacked)
				continue;
			strcat(errors, " no-m-no-sackd");
			continue;
		}

		switch (pkt->m->packet_type & RTE_PTYPE_L2_MASK) {
		case RTE_PTYPE_L2_ETHER:
			hdr_len = sizeof (struct rte_ether_hdr);
			break;
		case RTE_PTYPE_L2_ETHER_VLAN:
			vlan = rte_pktmbuf_mtod_offset(pkt->m, struct rte_vlan_hdr *, sizeof(struct rte_ether_hdr));
			hdr_len = sizeof (struct rte_ether_hdr) + sizeof (struct rte_vlan_hdr);
			break;
		default:
			strcat(errors, " L2");
			break;
		}

		ip.ip4h = rte_pktmbuf_mtod_offset(pkt->m, struct rte_ipv4_hdr *, hdr_len);

		switch (pkt->m->packet_type & RTE_PTYPE_L3_MASK) {
		case RTE_PTYPE_L3_IPV4:
			tcp = rte_pktmbuf_mtod_offset(pkt->m, struct rte_tcp_hdr *, hdr_len + sizeof(struct rte_ipv4_hdr));
			break;
		case RTE_PTYPE_L3_IPV4_EXT:
		case RTE_PTYPE_L3_IPV4_EXT_UNKNOWN:
			tcp = rte_pktmbuf_mtod_offset(pkt->m, struct rte_tcp_hdr *, hdr_len + rte_ipv4_hdr_len(ip.ip4h));
			break;
		case RTE_PTYPE_L3_IPV6:
			is_ipv6 = true;
			tcp = rte_pktmbuf_mtod_offset(pkt->m, struct rte_tcp_hdr *, hdr_len + sizeof(struct rte_ipv6_hdr));
			break;
		case RTE_PTYPE_L3_IPV6_EXT:
		case RTE_PTYPE_L3_IPV6_EXT_UNKNOWN:
			is_ipv6 = true;
			off = hdr_len;
			proto = rte_net_skip_ip6_ext(pkt->iph.ip6h->proto, pkt->m, &off, &frag);
			if (proto != IPPROTO_TCP) {
				if (unlikely(proto < 0))
					strcat(errors, " proto_invalid");
				else
					strcat(errors, " proto_not_tcp");
				continue;
			}

			tcp = rte_pktmbuf_mtod_offset(pkt->m, struct rte_tcp_hdr *, hdr_len + off);
			break;
		default:
			strcat(errors, " L3");
			break;
		}

		/* Check the vlan is correct */
		if ((!vlan && pkt->m->vlan_tci) ||
		    (vlan && rte_be_to_cpu_16(vlan->vlan_tci) != pkt->m->vlan_tci))
			strcat(errors, " vlan");

		/* Check IP and TCP offsets */
		if (ip.ip4h != pkt->iph.ip4h ||
		    tcp != pkt->tcp)
			strcat(errors, " offsets");

		/* Check src and dest addrs */
		if (!is_ipv6) {
			if ((priv &&
			     (rte_be_to_cpu_32(ip.ip4h->src_addr) != ef->pub_addr.v4.s_addr ||
			      rte_be_to_cpu_32(ip.ip4h->dst_addr) != ef->priv_addr.v4.s_addr)) ||
			    (!priv &&
			     (rte_be_to_cpu_32(ip.ip4h->src_addr) != ef->priv_addr.v4.s_addr ||
			      rte_be_to_cpu_32(ip.ip4h->dst_addr) != ef->pub_addr.v4.s_addr)))
				strcat(errors," IP4 addr");
		} else {
			if ((priv &&
			     (memcmp(&ip.ip6h->src_addr, &ef->pub_addr.v6, sizeof(ip.ip6h->src_addr)) ||
			      memcmp(&ip.ip6h->dst_addr, &ef->priv_addr.v6, sizeof(ip.ip6h->dst_addr)))) ||
			    (!priv &&
			     (memcmp(&ip.ip6h->src_addr, &ef->priv_addr.v6, sizeof(ip.ip6h->src_addr)) ||
			      memcmp(&ip.ip6h->dst_addr, &ef->pub_addr.v6, sizeof(ip.ip6h->dst_addr)))))
				strcat(errors, " IP6 addr");
		}

		/* Check ports */
		if ((priv &&
		     (rte_be_to_cpu_16(tcp->src_port) != ef->pub_port ||
		      rte_be_to_cpu_16(tcp->dst_port) != ef->priv_port)) ||
		    (!priv &&
		     (rte_be_to_cpu_16(tcp->src_port) != ef->priv_port ||
		      rte_be_to_cpu_16(tcp->dst_port) != ef->pub_port)))
			strcat(errors, " ports");

		if (!pkt->rack_segs_sacked) {
		/* Check seq */
			if (pkt->seq != rte_be_to_cpu_32(tcp->sent_seq))
				strcat(errors, " seq");

			/* Check TCP payload len */
			if (!pkt->rack_segs_sacked &&
			    pkt->seglen != pkt->m->pkt_len - ((uint8_t *)pkt->tcp - rte_pktmbuf_mtod(pkt->m, uint8_t *))
						- ((pkt->tcp->data_off & 0xf0) >> 2)
						+ !!(pkt->tcp->tcp_flags & (RTE_TCP_SYN_FLAG | RTE_TCP_FIN_FLAG)))
				strcat(errors, " seglen");

			/*
			 * check seq and ack makes sense for side
			 */
		}

		if (errors[0]) {
			num_error++;
			printf("check packet ef %p pkt %p m %p seq 0x%x %s\n", ef, pkt, pkt->m, pkt->seq, errors);
			dump_pkt_mbuf(pkt);
		}
	}

	return num_error;
}

__visible void
check_packets(const char *where)
{
	unsigned i;
	const struct tfo_eflow *ef;
	const struct tfo *fo;
	unsigned error = 0;

	for (i = 0; i < config->hef_n; i++) {
		if (hlist_empty(&worker.hef[i]))
			continue;

		hlist_for_each_entry(ef, &worker.hef[i], hlist) {
			if (ef->tfo_idx != TFO_IDX_UNUSED) {
				fo = &worker.f[ef->tfo_idx];
				error += check_side_packets(&fo->priv, true, ef);
				error += check_side_packets(&fo->pub, false, ef);

				if (error &&
				    !(config->option_flags & TFO_CONFIG_FL_DUMP_ALL_EFLOWS)) {
					dump_eflow(ef);
					printf("check_packets (%s) -  %u packet(s) had an ERROR\n", where, error);
					error = 0;
				}
			}
		}
	}

	if (error) {
		dump_details(&worker);
		printf("check_packets (%s) -  %u packet(s) had an ERROR\n", where, error);
	}
}
#endif //!DEBUG_CHECK_PKTS

#ifdef DEBUG_CHECKSUM
bool
check_checksum(struct tfo_pkt *pkt, const char *msg)
{
	if (pkt->m->packet_type & RTE_PTYPE_L3_IPV4) {
		if (rte_ipv4_udptcp_cksum_verify(pkt->iph.ip4h, pkt->tcp)) {
			printf("%s: ip checksum 0x%4.4x (%4.4x), tcp checksum 0x%4.4x (%4.4x), not GOOD ERROR\n", msg,
			(unsigned)rte_be_to_cpu_16(pkt->iph.ip4h->hdr_checksum), (unsigned)rte_ipv4_cksum(pkt->iph.ip4h),
			(unsigned)rte_be_to_cpu_16(pkt->tcp->cksum), (unsigned)rte_ipv4_udptcp_cksum(pkt->iph.ip4h, pkt->tcp));

			dump_m(pkt->m);

			return false;
		}
	} else {
		if (rte_ipv6_udptcp_cksum_verify(pkt->iph.ip6h, pkt->tcp)) {
			printf("%s: tcp checksum 0x%4.4x (%4.4x), not GOOD ERROR\n", msg,
			(unsigned)rte_be_to_cpu_16(pkt->tcp->cksum), (unsigned)rte_ipv6_udptcp_cksum(pkt->iph.ip6h, pkt->tcp));

			dump_m(pkt->m);

			return false;
		}
	}

	return true;
}

bool
check_checksum_in(struct rte_mbuf *m, const char *msg)
{
	struct tfo_pkt pkt = { .tcp = NULL };
	uint16_t hdr_len = 0;
	uint32_t off;
	int16_t proto;
	int frag;

	pkt.m = m;
	switch (m->packet_type & RTE_PTYPE_L2_MASK) {
	case RTE_PTYPE_L2_ETHER:
		hdr_len = sizeof (struct rte_ether_hdr);
		break;
	case RTE_PTYPE_L2_ETHER_VLAN:
		hdr_len = sizeof (struct rte_ether_hdr) + sizeof (struct rte_vlan_hdr);
		break;
	}
	pkt.iph.ip4h = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, hdr_len);
	switch (m->packet_type & RTE_PTYPE_L3_MASK) {
	case RTE_PTYPE_L3_IPV4:
		pkt.tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + sizeof(struct rte_ipv4_hdr));
		break;
	case RTE_PTYPE_L3_IPV4_EXT:
	case RTE_PTYPE_L3_IPV4_EXT_UNKNOWN:
		pkt.tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + rte_ipv4_hdr_len(pkt.iph.ip4h));
		break;
	case RTE_PTYPE_L3_IPV6:
		pkt.tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + sizeof(struct rte_ipv6_hdr));
		break;
	case RTE_PTYPE_L3_IPV6_EXT:
	case RTE_PTYPE_L3_IPV6_EXT_UNKNOWN:
		off = hdr_len;
		proto = rte_net_skip_ip6_ext(pkt.iph.ip6h->proto, m, &off, &frag);
		if (unlikely(proto < 0))
			return false;
		if (proto != IPPROTO_TCP)
			return false;

		pkt.tcp = rte_pktmbuf_mtod_offset(m, struct rte_tcp_hdr *, hdr_len + off);
		break;
	}

	return check_checksum(&pkt, msg);
}
#endif

#ifdef DEBUG_DUPLICATE_MBUFS
bool
check_mbuf_in_use(struct rte_mbuf *m, struct tcp_worker *w)
{
	unsigned i;
	struct tfo_eflow *ef;
	struct tfo_side *s;
	struct tfo_pkt *pkt;
	bool in_use = false;
	unsigned pkt_no;

	for (i = 0; i < config->hef_n; i++) {
		if (hlist_empty(&w->hef[i]))
			continue;

		hlist_for_each_entry(ef, &w->hef[i], hlist) {
			if (ef->priv == NULL)
				continue;
			s = ef->priv;
			while (s) {
				pkt_no = 0;
				list_for_each_entry(pkt, &s->pktlist, list) {
					pkt_no++;
					if (pkt->m == m) {
						printf("New mbuf %p already in use by eflow %p %s pkt %u\n",
						       m, ef, s == ef->priv ? "priv" : "pub", pkt_no);
						in_use = true;
					}
				}
				s = s == ef->priv ? ef->pub : NULL;
			}
		}
	}

	return in_use;
}
#endif //!DEBUG_DUPLICATE_MBUFS

#ifdef DEBUG_CONFIG
static void
dump_config(const struct tcp_config *c)
{
	printf("u_n = %u\n", c->u_n);
	printf("hu_n = %u\n", c->hu_n);
	printf("hu_mask = %u\n", c->hu_mask);
	printf("ef_n = %u\n", c->ef_n);
	printf("hef_n = %u\n", c->hef_n);
	printf("hef_mask = %u\n", c->hef_mask);
	printf("f_n = %u\n", c->f_n);
	printf("p_n = %u\n", c->p_n);
	printf("tcp_min_rtt_wlen = %u\n", c->tcp_min_rtt_wlen);
	printf("keepalive timer = %u\n", c->tcp_keepalive_time);
	printf("keepalive probes = %u\n", c->tcp_keepalive_probes);
	printf("keepalive intvl = %u\n", c->tcp_keepalive_intvl);

	printf("\nmax_port_to %u\n", c->max_port_to);
	for (int i = 0; i <= c->max_port_to; i++) {
		if (!i || c->tcp_to[i].to_syn != c->tcp_to[0].to_syn ||
			  c->tcp_to[i].to_est != c->tcp_to[0].to_est ||
			  c->tcp_to[i].to_fin != c->tcp_to[0].to_fin)
			printf("%5d: %6d %6d %6d\n", i, c->tcp_to[i].to_syn, c->tcp_to[i].to_est, c->tcp_to[i].to_fin);
	}
}
#endif

#ifdef DEBUG_SUPPORTED_PKT_TYPES
static void
em_check_ptype(int portid)
{
	int i, ret;
	uint32_t ptype_mask = RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK | RTE_PTYPE_L4_MASK;

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, NULL, 0);
	if (ret <= 0)
		return;

	uint32_t ptypes[ret];

	ret = rte_eth_dev_get_supported_ptypes(portid, ptype_mask, ptypes, ret);
	for (i = 0; i < ret; ++i) {
		printf("Support %u %s %s %s\n", ptypes[i], rte_get_ptype_l2_name(ptypes[i]), rte_get_ptype_l3_name(ptypes[i]), rte_get_ptype_l4_name(ptypes[i]));
	}
}
#endif

#ifdef DEBUG_TCP_WINDOW
void
tfo_debug_print_eflow_window(struct tfo_eflow *ef)
{
	uint32_t pub_snd_win = ef->pub->snd_win << ef->pub->snd_win_shift;
	uint32_t priv_snd_win = ef->priv->snd_win << ef->priv->snd_win_shift;

	printf("  priv: snd %u,%u (%u/%u) rcv %u (%u/%u)\n"
	       "  pub : snd %u,%u (%u/%u) rcv %u (%u/%u)\n",
	       ef->priv->snd_una, ef->priv->snd_nxt, ef->priv->snd_nxt - ef->priv->snd_una,
	       min(priv_snd_win, ef->priv->cwnd),
	       ef->priv->rcv_nxt, ef->priv->rcv_win << ef->priv->rcv_win_shift,
	       pub_snd_win,
	       ef->pub->snd_una, ef->pub->snd_nxt, ef->pub->snd_nxt - ef->pub->snd_una,
	       min(pub_snd_win, ef->pub->cwnd),
	       ef->pub->rcv_nxt, ef->pub->rcv_win << ef->pub->rcv_win_shift,
	       priv_snd_win);
}
#endif

void
tfo_debug_worker_init(void)
{
#ifdef PER_THREAD_LOGS
	open_thread_log(global_config_data.log_file_name_template);
#endif

#ifdef DEBUG_PRINT_TO_BUF
	if (global_config_data.print_buf_size)
		tfo_printf_init((uint64_t)global_config_data.print_buf_size << 20, !!(global_config_data.option_flags & TFO_CONFIG_FL_BUFFER_KEEP));
#endif

#ifdef DEBUG_MEMPOOL
	show_mempool("packet_pool_0");
#endif

#ifdef DEBUG_SUPPORTED_PKT_TYPES
	em_check_ptype(rte_lcore_id() - 1);
#endif

#ifdef WRITE_PCAP
	if (save_pcap)
		open_pcap();
#endif

#ifdef DEBUG_CONFIG
	printf("Dump config for socket %d\n", socket_id);
	dump_config(c);
#endif
}
