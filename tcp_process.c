/* SPDX-License-Identifier: GPL-3.0-only
 * Copyright(c) 2022 P Quentin Armitage <quentin@armitage.org.uk>
 */

#include <errno.h>

_Pragma("GCC diagnostic push")
_Pragma("GCC diagnostic ignored \"-Wsuggest-attribute=pure\"")
#include <rte_mbuf.h>
_Pragma("GCC diagnostic pop")
#include <rte_ether.h>
#include <rte_ip.h>

#include "tcp_process.h"

/* nb_tx is a value/result field. On entry it is the number of tx_bufs available, on return it is
 * the number of tx_bufs in use. */
uint16_t
monitor_pkts(struct rte_mbuf **rx_bufs, uint16_t nb_rx)
{
	struct rte_ether_hdr *eh;
	struct rte_vlan_hdr *vh;
	struct rte_ipv4_hdr *iph;
	struct rte_ipv6_hdr *ip6h;
#ifdef DEBUG
	struct rte_tcp_hdr *tcph;
#endif
	struct rte_mbuf *m;
	uint16_t next_proto;
	int next_next_proto;
	uint8_t *next_header;
	size_t ext_len;
	unsigned o_pkts = 0;

	for (unsigned i = 0; i < nb_rx; i++) {
		m = rx_bufs[i];
		eh = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

#ifdef DEBUG
		printf(RTE_ETHER_ADDR_PRT_FMT " -> " RTE_ETHER_ADDR_PRT_FMT " Ethernet proto (offs %d) %x\n",
			RTE_ETHER_ADDR_BYTES(&eh->src_addr),
			RTE_ETHER_ADDR_BYTES(&eh->dst_addr),
			(char *)&eh->ether_type - (char *)eh,
			rte_be_to_cpu_16(eh->ether_type));
#endif

		/* Skip multicast/broadcast packets */
		if (!rte_is_unicast_ether_addr(&eh->dst_addr)) {
			rte_pktmbuf_free(m);
			continue;
		}

		if (eh->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN) ||
                    eh->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_QINQ)) {
                        vh = (struct rte_vlan_hdr *)(eh + 1);
                        while (vh->eth_proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN) ||
                                 vh->eth_proto == rte_cpu_to_be_16(RTE_ETHER_TYPE_QINQ)) {
                                vh++;
// Check haven't reached end of packet - ignore pkt if so
			}
			next_proto = vh->eth_proto;
			next_header = (uint8_t *)(vh + 1);
		} else {
			next_proto = eh->ether_type;
			next_header = (uint8_t *)(eh + 1);
		}

// Consider IP-IP, GRE, GUE tunnelling - consider checksum options (see ipvsadm)
// DPDK also has Vxlan, Geneve, MPLSinUDP, Vxlan_gpe, GTP and ESP tunnels, but not GUE
// Consider IPv6 fragmentation - see https://network-insight.net/2015/10/ipv6-fragmentation/
//   will need a 60 second timeout for all fragments to have been seen
		if (next_proto == rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV4)) {
			iph = (struct rte_ipv4_hdr *)next_header;

			if (iph->next_proto_id != IPPROTO_TCP) {
				rx_bufs[o_pkts++] = rx_bufs[i];
				continue;
			}

#ifdef DEBUG
			tcph = (struct rte_tcp_hdr *)((uint8_t *)(iph) +
				((iph->version_ihl & RTE_IPV4_HDR_IHL_MASK) << 2));
#endif
		} else if (next_proto == rte_be_to_cpu_16(RTE_ETHER_TYPE_IPV6)) {
			ip6h = (struct rte_ipv6_hdr *)next_header;
			next_proto = ip6h->proto;
			next_header = (uint8_t *)(ip6h + 1);
			while (next_proto != IPPROTO_AH &&
			       (next_next_proto = rte_ipv6_get_next_ext(next_header, next_proto, &ext_len)) != -EINVAL) {
				next_proto = (uint16_t)next_next_proto;
				next_header += ext_len;
			}
			if (next_proto != IPPROTO_TCP) {
				rx_bufs[o_pkts++] = rx_bufs[i];
				continue;
			}
#ifdef DEBUG
			tcph = (struct rte_tcp_hdr *)next_header;
#endif
		} else {
			/* We only want to forward IPv4 and IPv6 packets */
			rte_pktmbuf_free(m);
			continue;
		}

#ifdef DEBUG
		printf("%s%s%s%s%s%u -> %u, seq %u ack %u, flags 0x%x, data_off %u (header len %u), rx_win %u, total_len %u, pkt_len %u (payload %u)\n",
		       tcph->tcp_flags & RTE_TCP_SYN_FLAG ? "SYN " : "",
		       tcph->tcp_flags & RTE_TCP_ACK_FLAG ? "ACK " : "",
		       tcph->tcp_flags & RTE_TCP_FIN_FLAG ? "FIN " : "",
		       tcph->tcp_flags & RTE_TCP_PSH_FLAG ? "PSH " : "",
		       tcph->tcp_flags & RTE_TCP_RST_FLAG ? "RST " : "",
		       rte_be_to_cpu_16(tcp->src_port),
		       rte_be_to_cpu_16(tcp->dst_port),
		       rte_be_to_cpu_32(tcp->sent_seq),
		       rte_be_to_cpu_32(tcp->recv_ack),
		       tcph->tcp_flags | (tcp->data_off & 0x0f << 8),
		       tcph->data_off >> 4,
		       (tcph->data_off >> 4) * 4,
		       rte_be_to_cpu_16(tcph->rx_win),
		       m->data_len,
		       m->pkt_len,
		       m->data_len - ((char *)tcph - (char *)eh + (tcp->data_off >> 4) * 4));
#endif

		rx_bufs[o_pkts++] = rx_bufs[i];
	}

printf("Monitor_pkts returning %u from %u packets\n", o_pkts, nb_rx);
	return o_pkts;
}
