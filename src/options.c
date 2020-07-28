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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>

#include "packet.h"
#include "logging.h"

#define option_bool(x) (0)

#define OPTION_PAD               0
#define OPTION_OVERLOAD          52
#define OPTION_MESSAGE_TYPE      53
#define OPTION_AGENT_ID          82
#define OPTION_END               255

#define SUBOPT_CIRCUIT_ID        1
#define SUBOPT_REMOTE_ID         2
#define SUBOPT_SERVER_OR         11	/* RFC 5107 */

#define DHOPT_ADDR               1
#define DHOPT_STRING             2

#define MAX_OPTION_SIZE          255

#define option_len(opt) ((int)(((unsigned char *)(opt))[1]))

typedef unsigned int u32;

struct dhcp_opt {
	int opt, len, flags;
	unsigned char *val;
	struct dhcp_opt *next;
};

/* return length, note this only does the data part */
static int do_opt(struct dhcp_opt *opt, unsigned char *p)
{
	int len = opt->len;

	if (p && len != 0) {
		if (opt->flags & DHOPT_ADDR) {
			int j;
			struct in_addr *a = (struct in_addr *)opt->val;

			for (j = 0; j < opt->len; j += INADDRSZ, a++) {
				memcpy(p, a, INADDRSZ);
				p += INADDRSZ;
			}
		} else
			memcpy(p, opt->val ? opt->val : (unsigned char *)"", len);
	}
	return len;
}

static unsigned char *dhcp_skip_opts(unsigned char *start)
{
	while (*start != 0)
		start += start[1] + 2;
	return start;
}

static unsigned char *free_space(struct dhcp_packet_with_opts *mess, unsigned char *end, int opt, int len)
{
	unsigned char *p = dhcp_skip_opts(&mess->options[0] + sizeof(u32));

	if (p + len + 3 >= end) {
		p = NULL;
		syslog2(LOG_WARNING, "Cannot send DHCP/BOOTP option %d: no space left in packet", opt);
	}

	if (p) {
		*(p++) = opt;
		*(p++) = len;
	}

	return p;
}

static unsigned char *option_find1(unsigned char *p, unsigned char *end, int opt, int minsize)
{
	while (1) {
		if (p >= end)
			return NULL;
		else if (*p == OPTION_END)
			return opt == OPTION_END ? p : NULL;
		else if (*p == OPTION_PAD)
			p++;
		else {
			int opt_len;

			if (p > end - 2)
				return NULL;	/* malformed packet */
			opt_len = option_len(p);
			if (p > end - (2 + opt_len))
				return NULL;	/* malformed packet */
			if (*p == opt && opt_len >= minsize)
				return p;
			p += opt_len + 2;
		}
	}
}

static unsigned char *option_find(struct dhcp_packet_with_opts *mess, size_t size, int opt_type, int minsize)
{
	unsigned char *ret, *overload;

	/* skip over DHCP cookie; */
	if ((ret = option_find1(&mess->options[0] + sizeof(u32), ((unsigned char *)mess) + size, opt_type, minsize)))
		return ret;
	/* look for overload option. */
	if (!(overload = option_find1(&mess->options[0] + sizeof(u32), ((unsigned char *)mess) + size, OPTION_OVERLOAD, 1)))
		return NULL;
	/* Can we look in filename area ? */
	if ((overload[2] & 1) && (ret = option_find1(&mess->header.file[0], &mess->header.file[128], opt_type, minsize)))
		return ret;
	/* finally try sname area */
	if ((overload[2] & 2) && (ret = option_find1(&mess->header.sname[0], &mess->header.sname[64], opt_type, minsize)))
		return ret;
	return NULL;
}


static size_t dhcp_packet_size(struct dhcp_packet_with_opts *mess, unsigned char *real_end)
{
	unsigned char *p = dhcp_skip_opts(&mess->options[0] + sizeof(u32));
	size_t ret;

	(void)real_end;		/* unused */
	*p++ = OPTION_END;

	if (option_bool(OPT_LOG_OPTS)) {
		if (mess->header.siaddr.s_addr != 0)
			syslog2(LOG_DEBUG, "%u next server: %s", ntohl(mess->header.xid), inet_ntoa(mess->header.siaddr));
		if ((mess->header.flags & htons(0x8000)) && mess->header.ciaddr.s_addr == 0)
			syslog2(LOG_DEBUG, "%u broadcast response.", ntohl(mess->header.xid));
	}

	ret = (size_t)(p - (unsigned char *)mess);

	if (ret < MIN_PACKETSZ)
		ret = MIN_PACKETSZ;

	return ret;
}

static void encap_opts(struct dhcp_opt *opt, int encap, struct dhcp_packet_with_opts *mess, unsigned char *end)
{
	int len, enc_len;
	struct dhcp_opt *start;
	unsigned char *p;
	size_t tot_len;

	/* find size in advance */
	for (enc_len = 0, start = opt; opt; opt = opt->next) {
		int new = do_opt(opt, NULL) + 2;
		if (enc_len + new <= MAX_OPTION_SIZE)
			enc_len += new;
		else {
			syslog2(LOG_WARNING, "Cannot add DHCP/BOOTP option %d: option to large (%d).", opt, new);
			return;
		}
	}
	
	tot_len = enc_len;
	if (enc_len != 0 && (p = free_space(mess, end, encap, tot_len))) {
		for (; start; start = start->next) {
			len = do_opt(start, p + 2);
			*(p++) = start->opt;
			*(p++) = len;
			p += len;
		}
	}
}

static void add_option82(struct dhcp_packet_with_opts *mess, unsigned char *end, int ifindex, cfg_t *cfg,
			 cfg_iface_t *iface, struct in_addr addr)
{
	unsigned char ifname[IF_NAMESIZE];
	char *giaddr;
	struct dhcp_opt opt_cid;
	struct dhcp_opt opt_rid;
	struct dhcp_opt opt_sor;
	struct dhcp_opt *opt_root;
	char host[HOST_NAME_MAX];

	memset(ifname, 0, IF_NAMESIZE);

	syslog2(LOG_DEBUG, "Adding option 82.");

	if (!if_indextoname(ifindex, (char *)&ifname[0]))
		return;		/* Report error? */

	opt_rid.opt = SUBOPT_REMOTE_ID;

	switch (cfg->opt82.rid_type) {
	case RID_TYPE_MANUAL:
		opt_rid.val = (unsigned char *)cfg->opt82.remote_id;
		opt_rid.len = cfg->opt82.remote_id_len;
		break;
	case RID_TYPE_GIADDR:
		giaddr = inet_ntoa(addr);
		opt_rid.val = (unsigned char *)giaddr;
		opt_rid.len = strlen(giaddr);
		break;

	case RID_TYPE_HOSTNAME:
		gethostname(host, sizeof(host));
		opt_rid.val = (unsigned char *)host;
		opt_rid.len = strlen(host);
		break;
	}
	opt_rid.flags = 0;
	opt_rid.next = NULL;

	opt_cid.opt = SUBOPT_CIRCUIT_ID;
	syslog2(LOG_DEBUG, "circuit_id: %p, len: %d\n", iface->circuit_id, iface->circuit_id_len);
	if (iface->circuit_id_len > 0) {
		opt_cid.val = (unsigned char *)iface->circuit_id;
		opt_cid.len = iface->circuit_id_len;
	} else {
		opt_cid.val = &ifname[0];
		opt_cid.len = strlen((char *)ifname);
	}
	opt_cid.flags = 0;
	opt_cid.next = &opt_rid;

	if (addr.s_addr) {
		opt_sor.opt = SUBOPT_SERVER_OR;
		opt_sor.val = (unsigned char *)&addr;
		opt_sor.len = 4;
		opt_sor.flags = DHOPT_ADDR;
		opt_sor.next = &opt_cid;
		opt_root = &opt_sor;
	} else
		opt_root = &opt_cid;

	encap_opts(opt_root, OPTION_AGENT_ID, mess, end);
}

/* Is request from @iface_index allowed? */
static cfg_iface_t *find_iface_cfg(cfg_group_t *group, int ifindex)
{
	cfg_iface_t *entry;

	TAILQ_FOREACH(entry, &group->iface_list, link) {
		int index = entry->ifindex;

		if (index == ifindex)
			return entry;
	}
	return NULL;
}

size_t add_options(struct dhcp_packet_with_opts *mess, size_t sz, int ifindex, struct in_addr addr, cfg_group_t *group, cfg_t *cfg)
{
	unsigned char *tmp, *opt, *end = (unsigned char *)(mess + 1);
	unsigned char *real_end = (unsigned char *)(mess + 1);
	cfg_iface_t *iface;
	int nbytes;

	syslog2(LOG_DEBUG, "Adding options");

	if (!cfg->opt82.enabled)
		return 0;

	iface = find_iface_cfg(group, ifindex);
	if (!iface) {
		syslog2(LOG_ERR, "Could not find iface configuration for index %d", ifindex);
		return 1;
	}
	if (mess->header.op != BOOTREQUEST)	//|| mess->hlen > DHCP_CHADDR_MAX)
		return 0;

	/* Why this? From dnsmasq. Don't add options if hardware type is 0. */
	if (mess->header.htype == 0 && mess->header.hlen != 0)
		return 0;

	/* check for DHCP rather than BOOTP */
	if ((opt = option_find(mess, sz, OPTION_MESSAGE_TYPE, 1))) {
		u32 cookie = htonl(DHCP_COOKIE);

		/* only insist on a cookie for DHCP. */
		if (memcmp(mess->options, &cookie, sizeof(u32)) != 0)
			return 0;
	}
	/* Find end of options, set rest of mess to 0 to prepare for additional options. */
	tmp = option_find(mess, sz, OPTION_END, 0);
	nbytes = end - tmp;
	memset(tmp, 0, nbytes);

	/* If not forcing server id, reset address */
	if (!cfg->force_server_id)
		memset(&addr, 0, sizeof(addr));

	/* Option 82 should always be added last */
	add_option82(mess, end, ifindex, cfg, iface, addr);

	return dhcp_packet_size(mess, real_end);
}

/* Remove option 82 before returning to client */
size_t remove_options(struct dhcp_packet_with_opts *mess, size_t sz)
{
	unsigned char *tmp;
	unsigned char *end = (unsigned char *)(mess + 1);

	tmp = option_find(mess, sz, OPTION_AGENT_ID, 0);
	if (tmp) {
		/* number of bytes from option 82 to end option */
		int nbytes = end - tmp;
		/* number of bytes for whole option 82 including option and length field */
		int opt82_len = option_len(tmp) + 2;

		/* move rest of options after option 82 to where option 82 starts */
		memmove(tmp, tmp + opt82_len, nbytes - opt82_len);
		return dhcp_packet_size((struct dhcp_packet_with_opts *)(tmp + nbytes - opt82_len), end);
	}

	return sz;
}
