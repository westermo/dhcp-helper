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

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "logging.h"
#include "packet.h"
#include "options.h"
#include "conf.h"
#include <unistd.h>
#include "queue.h"
#include "misc.h"

int send_sd;

union {
	struct cmsghdr align;	/* this ensures alignment */
	char control[CMSG_SPACE(sizeof(struct in_pktinfo))];
} control_u;

/* Search for group by iface index. 
 * @Return  NULL if not found. */
cfg_group_t *find_group(cfg_t *cfg, int ifindex)
{
	cfg_group_t *entry;
	cfg_iface_t *entry2;

	TAILQ_FOREACH(entry, &cfg->group_list, link) {
		TAILQ_FOREACH(entry2, &entry->iface_list, link) {
			int index = entry2->ifindex;

			if (index == ifindex)
				return entry;
		}
	}
	return NULL;
}

/* Search for group by giaddr. 
 * @Return  NULL if not found. */
cfg_group_t *find_group_by_giaddr(cfg_t *cfg, struct in_addr giaddr)
{
	cfg_group_t *entry;
	cfg_iface_t *entry2;

	TAILQ_FOREACH(entry, &cfg->group_list, link) {
		TAILQ_FOREACH(entry2, &entry->iface_list, link) {
			if (entry->giaddr == giaddr.s_addr)
				return entry;
		}
	}
	return NULL;
}

/* Is already gatewayed by us? 
 * TODO: Is this needed? Inherited from original dhcp-helper */
static int is_local_gw(cfg_t *cfg, in_addr_t s_addr)
{
	cfg_group_t *entry;

	TAILQ_FOREACH(entry, &cfg->group_list, link) {
		if (s_addr == entry->giaddr)
			return 1;
	}
	return 0;
}

static int handle_request(cfg_t *cfg, struct dhcp_packet *packet, int ifindex, ssize_t sz)
{
	struct sockaddr_in saddr;
	cfg_group_t *group;
	cfg_server_t *server;

	memset(&saddr, 0, sizeof(saddr));

	syslog2(LOG_DEBUG, "Received a request");

	group = find_group(cfg, ifindex);
	if (!group) {
		syslog2(LOG_ERR, "Received packet on wrong interface (ifindex: %d), discarding it.", ifindex);
		return 1;
	}
	/* already relayed ? */
	if (packet->giaddr.s_addr) {
		syslog2(LOG_DEBUG, "Already relayed by %s", inet_ntoa(packet->giaddr));

		if (is_local_gw(cfg, packet->giaddr.s_addr)) {
			/* RFC3046, 2.1.1, discard if spoofed */
			syslog2(LOG_NOTICE, "Already relayed by this relay agent or spoofed!");
			return 0;
		}

		/* RFC3046, 2.1.1, simply forward if giaddr set, 
		 * without changing giaddr or adding option82.*/
	} else {
		struct in_addr addr;

		syslog2(LOG_DEBUG, "Will relay");
		/* plug in our address */

		addr.s_addr = packet->giaddr.s_addr = group->giaddr;
		if (cfg->opt82.enabled)
			sz = add_options((struct dhcp_packet_with_opts *)packet, sz, ifindex, addr, group, cfg);
	}

	if (!TAILQ_EMPTY(&group->server_list)) {
		TAILQ_FOREACH(server, &group->server_list, link) {
			//saddr.sin_family = AF_INET;
			saddr.sin_addr.s_addr = server->addr;
			saddr.sin_port = htons(server->port);
			syslog2(LOG_DEBUG, "Forward request to %s!", inet_ntoa(saddr.sin_addr));
			while (sendto(send_sd, packet, sz, 0, (struct sockaddr *)&saddr, sizeof(saddr)) == -1 && errno == EINTR) ;
		}
	} else {
		TAILQ_FOREACH(server, &cfg->server_list, link) {
			//saddr.sin_family = AF_INET;
			saddr.sin_addr.s_addr = server->addr;
			saddr.sin_port = htons(server->port);
			syslog2(LOG_DEBUG, "Forward request to %s!", inet_ntoa(saddr.sin_addr));
			while (sendto(send_sd, packet, sz, 0, (struct sockaddr *)&saddr, sizeof(saddr)) == -1 && errno == EINTR) ;
		}
	}
	return 0;
}

int handle_reply(cfg_t *cfg, struct dhcp_packet *packet, int ifindex, ssize_t sz)
{
	struct msghdr msg;
	struct iovec iov;
	struct sockaddr_in saddr;
	struct in_pktinfo *pkt;
	cfg_group_t *group;
	struct cmsghdr *cmptr;
	int result = 0;

	syslog2(LOG_DEBUG, "Received a reply.");
	/* packet from server send back to client */

	group = find_group_by_giaddr(cfg, packet->giaddr);

	memset(&saddr, 0, sizeof(saddr));

	msg.msg_control = control_u.control;
	msg.msg_controllen = sizeof(control_u);
	msg.msg_name = &saddr;
	msg.msg_namelen = 0;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	saddr.sin_port = htons(DHCP_CLIENT_PORT);
	msg.msg_control = NULL;
	msg.msg_controllen = 0;
	msg.msg_namelen = sizeof(saddr);

	iov.iov_base = packet;
	iov.iov_len = sz;

	/* I'm the gateway, remove options (option 82) and reset giaddr */
	if (group) {
		sz = remove_options((struct dhcp_packet_with_opts *)packet, sz);
		packet->giaddr.s_addr = 0;
	}
	if (packet->ciaddr.s_addr)
		saddr.sin_addr = packet->ciaddr;
	else if (ntohs(packet->flags) & 0x8000 || !packet->yiaddr.s_addr || packet->hlen > 14) {
		syslog2(LOG_DEBUG, "Send broadcast reply.");
		/* broadcast to 255.255.255.255 */
		msg.msg_controllen = sizeof(control_u);
		msg.msg_control = control_u.control;
		cmptr = CMSG_FIRSTHDR(&msg);
		saddr.sin_addr.s_addr = INADDR_BROADCAST;
		pkt = (struct in_pktinfo *)CMSG_DATA(cmptr);
		pkt->ipi_ifindex = group->ifindex;
		pkt->ipi_spec_dst.s_addr = 0;
		msg.msg_controllen = cmptr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
		cmptr->cmsg_level = SOL_IP;
		cmptr->cmsg_type = IP_PKTINFO;
	} else if (group) {
		/* client not configured and cannot reply to ARP. 
		   Insert arp entry direct. */
		saddr.sin_addr = packet->yiaddr;

		msg.msg_name = &saddr;
		syslog2(LOG_DEBUG, "Send unicast reply to %s.", inet_ntoa(saddr.sin_addr));
		add_arp_entry(group->ifindex, packet->chaddr, saddr);
	} else
		return 1;

	do {
		result = sendmsg(send_sd, &msg, 0);
		if (result < 0)
			syslog2(LOG_WARNING, "Sending error: %m");
	} while (result == -1 && errno == EINTR);

	return 0;
}

int handle_packet(cfg_t *cfg, struct dhcp_packet *packet, ssize_t sz, int ifindex, int sd_out)
{
	send_sd = sd_out;
	/* rfc1542 says discard if > 16 */
	if ((packet->hops++) > 16)
		return 1;

	if (packet->hlen > DHCP_CHADDR_MAX)
		return 1;

	if (packet->op == BOOTREQUEST)
		handle_request(cfg, packet, ifindex, sz);
	else if (packet->op == BOOTREPLY)
		handle_reply(cfg, packet, ifindex, sz);

	return 0;
}
