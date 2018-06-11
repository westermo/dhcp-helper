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
#include <unistd.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>

#include <netlink/route/link.h>
#include <netlink/route/link/bridge.h>
#include <netlink/route/neighbour.h>

#include "conf.h"
#include "logging.h"

#define NFT_IN_CHAIN  "dhcpr-input"
#define NFT_FWD_CHAIN "dhcpr-forward "

static char *mac_ntoa(unsigned char *ptr)
{
	static char address[30];

	sprintf(address, "%02X:%02X:%02X:%02X:%02X:%02X", ptr[0], ptr[1], ptr[2], ptr[3], ptr[4], ptr[5]);

	return (address);
}

static int iface_is_bridged(struct nl_sock *sk, int ifindex)
{
	struct rtnl_link *link, *master;

	rtnl_link_get_kernel(sk, ifindex, NULL, &link);
	/* Only add nftables rules if interface is bridged. */
	if (link) {
		if (rtnl_link_get_master(link)) {
			rtnl_link_get_kernel(sk, rtnl_link_get_master(link), NULL, &master);
			if (rtnl_link_is_bridge(master)) {
				rtnl_link_put(master);
				rtnl_link_put(link);
				return 1;
			}
		}
		rtnl_link_put(link);
	}

	return 0;
}

int setup_nftables(cfg_t *cfg)
{
	cfg_group_t *group;
	cfg_iface_t *iface;
	char file[128] = "/tmp/dhcp-helper.XXXXXX";
	char cmd[256], ifname[IFNAMSIZ];
	FILE *fp;
	struct nl_sock *sk;
	int err = 0, fd, anybridged = 0;
  mode_t cur_umask;

	cur_umask = umask(0600);
	fd = mkstemp(file);
	umask(cur_umask);
	if (fd == -1) {
		syslog2(LOG_ERR, "Could not generate tempfile");
		return 1;
	}

	fp = fdopen(fd, "w+");
	if (!fp) {
		close(fd);
		syslog2(LOG_ERR, "Could not open tempfile");
		err = 1;
		goto err_unlink;
	}

	sk = nl_socket_alloc();
	if (!sk) {
		err = -NLE_NOMEM;
		goto err_close_fp;
	}

	err = nl_connect(sk, NETLINK_ROUTE);
	if (err)
		goto err_free_sk;

	fprintf(fp, "table bridge filter {\n");
	fprintf(fp, "chain " NFT_IN_CHAIN " {\n type filter hook input priority -200\n");
	TAILQ_FOREACH(group, &cfg->group_list, link) {
		TAILQ_FOREACH(iface, &group->iface_list, link) {
			if (iface_is_bridged(sk, iface->ifindex)) {
				anybridged = 1;
				if_indextoname(iface->ifindex, ifname);
				syslog2(LOG_DEBUG, "Interface %s is bridged, setting up nftables", ifname);
				fprintf(fp, "iif %s ip protocol udp udp dport 67 drop\n", ifname);
			}
		}
	}
	fprintf(fp, "}\n");

	fprintf(fp, "chain " NFT_FWD_CHAIN " {\n type filter hook forward priority -200\n");
	TAILQ_FOREACH(group, &cfg->group_list, link) {
		TAILQ_FOREACH(iface, &group->iface_list, link) {
			/* Only add nftables rules if interface is bridged. */
			if (iface_is_bridged(sk, iface->ifindex)) {
				anybridged = 1;
				if_indextoname(iface->ifindex, ifname);
				syslog2(LOG_DEBUG, "Interface %s is bridged, setting up nftables", ifname);
				fprintf(fp, "pkttype broadcast iif %s ip protocol udp udp dport 67 drop\n", ifname);
			}
		}
	}
	fprintf(fp, "}\n}");

	fprintf(fp, "\n");
 err_free_sk:
	nl_socket_free(sk);
 err_close_fp:
	fclose(fp);
	if (anybridged) {
		snprintf(cmd, sizeof(cmd), "nft -f %s", file);
		if (system(cmd))
			syslog2(LOG_ERR, "Failed applying nftables rules");
	}
err_unlink:
	unlink(file);

	return err;
}

int cleanup_nftables(cfg_t *cfg)
{
	cfg_group_t *group;
	int anybridged = 0;
	struct nl_sock *sk;

	sk = nl_socket_alloc();
	if (!sk) {
		return 1;
	}

	if (nl_connect(sk, NETLINK_ROUTE))
		goto err_free_sk;

	TAILQ_FOREACH(group, &cfg->group_list, link) {
		cfg_iface_t *iface;
		TAILQ_FOREACH(iface, &group->iface_list, link) {
			if (iface_is_bridged(sk, iface->ifindex))
				anybridged = 1;
		}
	}

	if (anybridged) {
		syslog2(LOG_DEBUG, "Some interfaces is bridged, remove nftables rules");
		if (system("nft  delete chain bridge filter " NFT_IN_CHAIN))
			syslog2(LOG_ERR, "Failed deleting nftables input rules");
		if (system("nft  delete chain bridge filter " NFT_FWD_CHAIN))
			syslog2(LOG_ERR, "Failed deleting nftables forward rules");
	}
err_free_sk:
	nl_socket_free(sk);
	return 0;
}

/**
   If there is an underlaying switchcore, it may implement 'DHCP-snooping',
   in this case it will most likely not learn the MAC-address correctly.

   To fix this, add a FDB entry in the bridge, if there are a switch under
   the FDB entry will be accelerated.
 */
int add_fdb_entry(int ifindex, unsigned char *mac)
{
	int err = 0;
	struct nl_addr *addr;
	struct rtnl_neigh *neigh;
	struct nl_sock *sk;
	sk = nl_socket_alloc();

	if (!sk)
		return 1;

	err = nl_connect(sk, NETLINK_ROUTE);
	if (err) {
		syslog(LOG_ERR, "Failed setting connecting to NETLINK_ROUTE: %s", nl_geterror(err));
		goto free_sk;
	}

	if (!iface_is_bridged(sk, ifindex)) {
		syslog2(LOG_DEBUG, "Interface %d is not bridged, skipping FDB entry", ifindex);
		nl_socket_free(sk);
		return 0; /* No fail, just exit. */
	}

	addr = nl_addr_alloc(ETH_ALEN);
	if (!addr) {
		syslog2(LOG_ERR, "Could not allocate netlink address");
		err = -NLE_NOMEM;
		goto free_sk;
	}

	syslog2(LOG_DEBUG, "Interface %d is bridged, adding FDB entry", ifindex);
	nl_addr_set_family(addr, AF_LLC);
	err = nl_addr_set_binary_addr(addr, mac, ETH_ALEN);
	if (err) {
		syslog(LOG_ERR, "Failed creating netlink binary address: %s", nl_geterror(err));
		goto free_addr;
		return err;
	}

	neigh = rtnl_neigh_alloc();
	if (!neigh) {
		err = -NLE_NOMEM;
		goto free_addr;
	}
	rtnl_neigh_set_family(neigh, PF_BRIDGE);
	rtnl_neigh_set_lladdr(neigh, addr);
	nl_addr_set_prefixlen(addr, 48);
	rtnl_neigh_set_flags(neigh, NTF_MASTER);
	rtnl_neigh_set_state(neigh, NUD_REACHABLE);
	rtnl_neigh_set_ifindex(neigh, ifindex);

	syslog(LOG_DEBUG, "Adding MAC %02x:%02x:%02x:%02x:%02x:%02x ifindex %d in bridge FDB", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5], ifindex);
	err = rtnl_neigh_add(sk, neigh, NLM_F_CREATE); //NLM_F_CREATE);

	rtnl_neigh_put(neigh);
free_addr:
	nl_addr_put(addr);
free_sk:
	nl_socket_free(sk);

	return err;
}

int add_arp_entry(int ifindex, unsigned char *mac, struct sockaddr_in saddr)
{
	struct arpreq req;
	struct sockaddr_in *sin;
	char ifname[IFNAMSIZ];
	int fd;

	if_indextoname(ifindex, ifname);

	syslog2(LOG_DEBUG, "Add arp entry for address %s, iface %s mac %s", inet_ntoa(saddr.sin_addr), ifname, mac_ntoa(mac));

	bzero(&req, sizeof(req));
	sin = (struct sockaddr_in *)&req.arp_pa;
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = saddr.sin_addr.s_addr;

	memcpy(req.arp_ha.sa_data, mac, ETHER_ADDR_LEN);
	req.arp_flags = ATF_COM;
	strncpy(req.arp_dev, ifname, sizeof(req.arp_dev));

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 1) {
		syslog2(LOG_WARNING, "Failed opening socket to add arp entry");
		return -1;
	}
	if (ioctl(fd, SIOCSARP, &req) < 0) {
		syslog2(LOG_WARNING, "Failed adding arp entry for address %s, iface %s mac %s", inet_ntoa(saddr.sin_addr), ifname, mac_ntoa(mac));
		close(fd);
		return -1;
	}
	close(fd);

	syslog2(LOG_DEBUG, "ARP cache entry successfully added.");

	return 0;
}
