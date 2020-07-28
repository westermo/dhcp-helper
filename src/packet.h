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

#ifndef __PACKET_H__
#define __PACKET_H__
#include "conf.h"

#define DHCP_COOKIE       0x63825363

#define MIN_PACKETSZ      300
#define DHCP_PACKET_MAX   16384	/* hard limit on DHCP packet size */

#define INADDRSZ          4

#define DHCP_CHADDR_MAX  16
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_ALTPORT 1067
#define DHCP_CLIENT_ALTPORT 1068
#define BOOTREQUEST      1
#define BOOTREPLY        2

#define DHCP_SERVER_PORT    67
#define DHCP_CLIENT_PORT    68
#define DHCP_SERVER_ALTPORT 1067
#define DHCP_CLIENT_ALTPORT 1068

#define BOOTREQUEST      1
#define BOOTREPLY        2

struct dhcp_packet_with_opts {
	struct dhcp_packet {
		unsigned char op, htype, hlen, hops;
		unsigned int xid;
		unsigned short secs, flags;
		struct in_addr ciaddr, yiaddr, siaddr, giaddr;
		unsigned char chaddr[DHCP_CHADDR_MAX], sname[64], file[128];
	} header;
	unsigned char options[312];
};

typedef struct client_cache_t {
	TAILQ_ENTRY(client_cache_t) link;
	unsigned char hwaddr[DHCP_CHADDR_MAX];
	struct in_addr giaddr;
	int ifindex;
} client_cache_t;

int handle_packet(cfg_t *cfg, struct dhcp_packet *packet, ssize_t sz, int ifindex, int sd_out);

#endif
