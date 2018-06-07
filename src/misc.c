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
	if (link && rtnl_link_get_master(link)) {
		rtnl_link_get_kernel(sk, rtnl_link_get_master(link), NULL, &master);
		if (rtnl_link_is_bridge(master))
			return 1;
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
	int err = 0;
	int fd;

	fd = mkstemp(file);
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
				if_indextoname(iface->ifindex, ifname);
				syslog2(LOG_DEBUG, "Interface %s is bridged, setting up nftables", ifname);
				fprintf(fp, "pkttype broadcast iif %s ip protocol udp udp dport 67 drop\n", ifname);
			}
		}
	}
	fprintf(fp, "}\n}");

	fprintf(fp, "\n");

	snprintf(cmd, sizeof(cmd), "nft -f %s", file);
	if (system(cmd))
		syslog2(LOG_ERR, "Failed applying nftables rules");

 err_free_sk:
	nl_socket_free(sk);
 err_close_fp:
	fclose(fp);
 err_unlink:
	unlink(file);

	return err;
}

void cleanup_nftables()
{
	if (system("nft  delete chain bridge filter " NFT_IN_CHAIN))
		syslog2(LOG_ERR, "Failed deleting nftables input rules");
	if (system("nft  delete chain bridge filter " NFT_FWD_CHAIN))
		syslog2(LOG_ERR, "Failed deleting nftables forward rules");
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
	strncpy(req.arp_dev, ifname, sizeof(ifname));

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
