/* dhcp-helper

   Copyright (c) 2004,2008 Simon Kelley
   Copyright (c) 2018 Westermo Teleindustri AB

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/filter.h>
#include <linux/udp.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ev.h>

#include "conf.h"
#include "packet.h"
#include "logging.h"
#include "config.h"
#include "misc.h"

static int sd_out = 0;

static ev_signal sighup_watcher;
static ev_signal sigint_watcher;
static ev_signal sigquit_watcher;
static ev_signal sigterm_watcher;

static ev_io io_upstreams;

static char config_file[128] = "/etc/dhcphelper.json";

static int get_ifindex(struct msghdr *msg)
{
	struct cmsghdr *cmptr;
	int ifindex = 0;

	for (cmptr = CMSG_FIRSTHDR(msg); cmptr; cmptr = CMSG_NXTHDR(msg, cmptr)) {
		if (cmptr->cmsg_level == SOL_IP && cmptr->cmsg_type == IP_PKTINFO) {
			union {
				unsigned char *c;
				struct in_pktinfo *p;
			} p;

			p.c = CMSG_DATA(cmptr);
			ifindex = p.p->ipi_ifindex;
		}
	}

	return ifindex;
}

static struct dhcp_packet_with_opts *packet_rcv_udp(int sd, unsigned char *buf, int sz, int *len, int *ifindex)
{
	union {
		struct cmsghdr align;	/* this ensures alignment */
		char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
	} control_u;
	struct msghdr msg;
	struct iovec iov;
	struct sockaddr_in saddr;

	msg.msg_control = control_u.control;
	msg.msg_controllen = sizeof(control_u);
	msg.msg_name = &saddr;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	iov.iov_base = buf;	// packet;
	iov.iov_len = sz;
	*len = recvmsg(sd, &msg, 0);

	*ifindex = get_ifindex(&msg);

	if (*len < 1) {
		syslog2(LOG_WARNING, "Received udp packet size %d.", *len);
		return NULL;
	}

	if (!*ifindex) {
		syslog2(LOG_WARNING, "Invalid ifindex for received udp packet (%d).", *ifindex);
		return NULL;
	}

	return (struct dhcp_packet_with_opts *)buf;
}

static struct dhcp_packet_with_opts *packet_rcv_raw(int sd, unsigned char *buf, int sz, int *len, int *ifindex)
{
	struct sockaddr_ll sl;
	struct ethhdr *eth_hdr = (struct ethhdr *)buf;
	struct iphdr *ip_hdr = (struct iphdr *)((char *)eth_hdr + (sizeof(struct ethhdr)));
	struct udphdr *udp;
	int dport;

	socklen_t salen = sizeof sl;

	*len = recvfrom(sd, buf, sz, 0, (struct sockaddr *)&sl, &salen);
	if (*len < 1) {
		syslog2(LOG_WARNING, "Received raw packet size %d.", *len);
		return NULL;
	}

	/* Not interested in outgoing packets. */
	if (sl.sll_pkttype & PACKET_OUTGOING)
		return NULL;

	*ifindex = sl.sll_ifindex;
	if (!*ifindex) {
		syslog2(LOG_WARNING, "Invalid ifindex for received raw packet (%d).", *ifindex);
		return NULL;
	}

	udp = (struct udphdr *)((char *)ip_hdr + (4 * ip_hdr->ihl));
	dport = ntohs(udp->dest);

	if (dport != 67 && dport != 68) {
		syslog2(LOG_NOTICE, "Received raw packet with invalid destination port (%d).", dport);
		return NULL;
	}

	return (struct dhcp_packet_with_opts *)((char *)(udp) + sizeof(struct udphdr));
}

static void packet_cb_raw(struct ev_loop *loop __attribute__ ((unused)), ev_io *w, int revents __attribute__ ((unused)))
{
	static unsigned char buf[2048];	/* MAXIMUM_PACKET_SIZE */
	cfg_t *cfg = ev_userdata(loop);
	struct dhcp_packet_with_opts *packet;
	int ifindex;
	int len;

	ev_io_stop(loop, w);

	packet = packet_rcv_raw(w->fd, buf, sizeof(buf), &len, &ifindex);
	if (packet)
		handle_packet(cfg, &packet->header, len, ifindex, sd_out);

	ev_io_start(loop, w);
}

static void packet_cb_udp(struct ev_loop *loop __attribute__ ((unused)), ev_io *w, int revents __attribute__ ((unused)))
{
	static unsigned char buf[2048];	/* MAXIMUM_PACKET_SIZE */
	cfg_t *cfg = ev_userdata(loop);
	struct dhcp_packet_with_opts *packet;
	int ifindex;
	int len;

	ev_io_stop(loop, w);

	packet = packet_rcv_udp(w->fd, buf, sizeof(buf), &len, &ifindex);
	if (packet)
		handle_packet(cfg, &packet->header, len, ifindex, sd_out);
	ev_io_start(loop, w);
}

/*
sudo tcpdump -dd -s0 -i enx0080c83bb148 "ether[12] == 0x08 && ether[13] == 0x00 
&& ether[23]==17 && ether[36] == 00 && ether[37] == 67"
 */
int add_filter(int sd)
{
	struct sock_fprog fprog;

	static struct sock_filter filter[] = {
		{0x30, 0, 0, 0x0000000c},
		{0x15, 0, 9, 0x00000008},
		{0x30, 0, 0, 0x0000000d},
		{0x15, 0, 7, 0x00000000},
		{0x30, 0, 0, 0x00000017},
		{0x15, 0, 5, 0x00000011},
		{0x30, 0, 0, 0x00000024},
		{0x15, 0, 3, 0x00000000},
		{0x30, 0, 0, 0x00000025},
		{0x15, 0, 1, 0x00000043},
		{0x6, 0, 0, 0x00040000},
		{0x6, 0, 0, 0x00000000},
	};
	fprog.len = sizeof filter / sizeof(filter[0]);
	fprog.filter = filter;

	if ((setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog))) < 0) {
		syslog2(LOG_WARNING, "Failed to set socket filter.");
		return 1;
	}
	return 0;
}

static int bind_to_interface(int sd, int ifindex)
{
	struct sockaddr_ll sll;

	bzero(&sll, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifindex;
	sll.sll_pkttype = PACKET_BROADCAST;
	if ((bind(sd, (struct sockaddr *)&sll, sizeof(sll))) == -1) {
		syslog2(LOG_WARNING, "Failed to bind socket to interface.");
		return 1;
	}
	return 0;
}

static int setup_sockets_raw(struct ev_loop *loop, cfg_t *cfg)
{
	cfg_group_t *group;
	cfg_iface_t *iface;

	TAILQ_FOREACH(group, &cfg->group_list, link) {
		TAILQ_FOREACH(iface, &group->iface_list, link) {
			int index = iface->ifindex;

			iface->sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
			if (iface->sd == -1) {
				perror("Unable to create in socket");
				return 1;
			}
			add_filter(iface->sd);
			bind_to_interface(iface->sd, index);
			ev_io_init(&iface->io, packet_cb_raw, iface->sd, EV_READ);
			ev_io_start(loop, &iface->io);
		}
	}
	return 0;
}

/*
 * Setup socket for listening to packets form server and to be used 
 * for sending replies to clients.
 */
static int setup_socket_udp(struct ev_loop *loop)
{
	int oneopt = 1;

	if (sd_out > 0)
		return 0;

	sd_out = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, IPPROTO_UDP);
	if (sd_out == -1) {
		perror("Unable to create out socket");
		return 1;
	}
	if (setsockopt(sd_out, SOL_IP, IP_PKTINFO, &oneopt, sizeof(oneopt)) == -1 ||
	    setsockopt(sd_out, SOL_SOCKET, SO_BROADCAST, &oneopt, sizeof(oneopt)) == -1) {
		perror("Unable to set socket option, SO_BROADCAST");
		close(sd_out);
		return 1;
	}

	struct sockaddr_in saddr;

	memset(&saddr, 0, sizeof(saddr));

	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(DHCP_SERVER_PORT);
	saddr.sin_addr.s_addr = INADDR_ANY;
	if (bind(sd_out, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in))) {
		perror("dhcp-helper: cannot bind DHCP high level socket");
		return -1;
	}

	ev_io_init(&io_upstreams, packet_cb_udp, sd_out, EV_READ);
	ev_io_start(loop, &io_upstreams);


	return 0;
}

static void cleanup(struct ev_loop *loop)
{
	static int first = 1;
	cfg_group_t *group;
	cfg_t *cfg = ev_userdata(loop);

	if (first) {
		first = 0;
		return;
	}

	TAILQ_FOREACH(group, &cfg->group_list, link) {
		cfg_iface_t *iface;

		TAILQ_FOREACH(iface, &group->iface_list, link) {
			char ifname[IFNAMSIZ];

			if_indextoname(iface->ifindex, ifname);
			ev_io_stop(loop, &iface->io);
			syslog2(LOG_DEBUG, "clean-up interface %s\n", ifname);
			if (iface->sd > 0) {
				close(iface->sd);
				iface->sd = 0;
			}
		}
	}
	/* UDP socket not necessary to 'restart' */
	conf_free(cfg);
	cleanup_nftables();
}

static struct ev_loop *init(struct ev_loop *loop, char *fname)
{
	cfg_t *cfg = ev_userdata(loop);

	/* Clear all old settings. */
	cleanup(loop);
	if (!cfg || conf_read(cfg, fname)) {
		syslog2(LOG_ERR, "Failed reading configuration file, %s: %m", fname);
		ev_break(loop, EVBREAK_ALL);
		return NULL;
	}

	if (setup_sockets_raw(loop, cfg) || setup_socket_udp(loop)) {
		syslog2(LOG_ERR, "Failed setting up required sockets.");
		ev_break(loop, EVBREAK_ALL);
		return NULL;
	}

	if (setup_nftables(cfg)) {
		syslog2(LOG_ERR, "Failed setting up nftables.");
		ev_break(loop, EVBREAK_ALL);
		return NULL;
	}
	return loop;
}

static void sigcb(struct ev_loop *loop, ev_signal *w, int rev __attribute__ ((unused)))
{
	switch (w->signum) {
	case SIGHUP:
		init(loop, config_file);
		break;

	default:
		/* Currently graceful shutdown on all other signals */
		cleanup(loop);
		ev_break(loop, EVBREAK_ALL);
		break;
	}
}

static struct ev_loop *init_signals(struct ev_loop *loop)
{
	ev_signal_init(&sigterm_watcher, sigcb, SIGTERM);
	ev_signal_start(loop, &sigterm_watcher);
	ev_signal_init(&sigint_watcher, sigcb, SIGINT);
	ev_signal_start(loop, &sigint_watcher);
	ev_signal_init(&sigquit_watcher, sigcb, SIGQUIT);
	ev_signal_start(loop, &sigquit_watcher);
	ev_signal_init(&sighup_watcher, sigcb, SIGHUP);
	ev_signal_start(loop, &sighup_watcher);

	return loop;
}

static int version(void)
{
	printf("%s v%s\n", PACKAGE_NAME, PACKAGE_VERSION);

	return 0;
}

static int usage(void)
{
	printf("Usage: %s [-hvd] -f <file>\n\n"
	       "  -f <file>   Read config file\n"
	       "  -d          Log all levels to stdout, for debugging.\n"
	       "  -v          Show program version\n"
	       "  -h          Show this help text\n"
	       "\n", PACKAGE_NAME);

	return 0;
}

int main(int argc, char **argv)
{
	struct ev_loop *loop;
	cfg_t cfg;
	int c;

	while ((c = getopt(argc, argv, "f:vdh")) != EOF) {
		switch (c) {
		case 'f':
			strncpy(config_file, optarg, sizeof(config_file));
			break;

		case 'v':
			return version();

		case 'd':
			log_console(1);
			break;

		case 'h':
		default:
			return usage();
		}
	}

	if (access(config_file, F_OK)) {
		fprintf(stderr, "Configuration file (%s) not found!\n", config_file);

		return 1;
	}

	setlogmask(LOG_UPTO(LOG_INFO));
	syslog2(LOG_INFO, "Starting dhcp-helper");

	loop = ev_default_loop(0);

	ev_set_userdata(loop, &cfg);
	init_signals(loop);
	loop = init(loop, config_file);

	if (loop)
		ev_run(loop, 0);

	conf_free(&cfg);
	close(sd_out);

	return 0;
}
