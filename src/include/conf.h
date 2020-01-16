/* dhcp-helper

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

#ifndef __CONF_H__
#define __CONF_H__

#include "queue.h"
#include <ev.h>

#define SCRIPT_LEN 100
#define CIRCUIT_ID_LEN 50
#define REMOTE_ID_LEN  50

typedef enum option82_rid_type_t {
	RID_TYPE_HOSTNAME,
	RID_TYPE_GIADDR,
	RID_TYPE_MANUAL,
} opt82_rid_type_t;

typedef enum option82_cid_type_t {
	CID_TYPE_IFNAME,
	CID_TYPE_MANUAL,
} opt82_cid_type_t;

typedef struct cfg_iface_t {
	TAILQ_ENTRY(cfg_iface_t) link;
	int ifindex;

	opt82_cid_type_t type;
	char circuit_id[CIRCUIT_ID_LEN];
	int circuit_id_len;
	ev_io io;
	int sd;			/* sd in io, for clean-up access */
} cfg_iface_t;

typedef struct cfg_group_t {
	TAILQ_ENTRY(cfg_group_t) link;
	TAILQ_HEAD(, cfg_iface_t) iface_list;
	TAILQ_HEAD(, cfg_server_t) server_list;
	unsigned int ifindex;
	int giaddr;
} cfg_group_t;

typedef struct cfg_server_t {
	TAILQ_ENTRY(cfg_server_t) link;
	int addr;
	int port;
} cfg_server_t;

typedef struct cfg_opt82 {
	int enabled;
	opt82_rid_type_t rid_type;

	char remote_id[REMOTE_ID_LEN];
	int remote_id_len;
} cfg_opt82_t;

typedef struct cfg_t {
	TAILQ_HEAD(, cfg_server_t) server_list;
	TAILQ_HEAD(, cfg_group_t) group_list;
	cfg_opt82_t opt82;
	int force_server_id;
	int udp_listen_port;
} cfg_t;

int conf_read(cfg_t *cfg, char *file);
void conf_free(cfg_t *cfg);
#endif
