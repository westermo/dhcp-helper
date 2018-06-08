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

#include <jansson.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <ifaddrs.h>
#include <net/if.h>

#include <conf.h>
#include "logging.h"

/*
  jansson does not support to parse integers as hex, therefore we must
  store/read them as strings, e.g [ "0x1", "0x2" ], and convert them.
 */
static int _parse_hex_arr(json_t *arr, char *dst, int len)
{
	json_t *obj;
	int num = 0;
	size_t i;

	json_array_foreach(arr, i, obj) {
		if (num >= len) {
			errno = ENOMEM;
			return 1;
		}
		if (json_is_string(obj))
			dst[num++] = (char)strtoul(json_string_value(obj), NULL, 16);
	}

	return num;
}

static int read_int(json_t *json, int *dst, char *key, int defvalue)
{
	json_t *obj;

	obj = json_object_get(json, key);
	if (!obj) {
		*dst = defvalue;
		return 0;
	}

	if (!json_is_integer(obj)) {
		*dst = defvalue;
		return 0;
	}

	*dst = json_integer_value(obj);

	return 0;
}

static void option82_parse_manual(json_t *obj, char *buf, int len, int *res)
{
	if (json_is_string(obj)) {
		strncpy(buf, json_string_value(obj), len);
		*res = strlen(buf);
	} else if (json_is_array(obj)) {
		*res = _parse_hex_arr(obj, buf, len);
	}
}

static int read_option82(json_t *json, cfg_t *cfg)
{
	json_t *obj;

	obj = json_object_get(json, "option82");
	if (json_is_object(obj)) {
		json_t *remote;
		const char *str;

		cfg->opt82.enabled = 1;

		remote = json_object_get(obj, "remote-id");
		if (json_is_object(remote)) {
			json_t *type, *data;

			type = json_object_get(remote, "type");
			if (json_is_string(type)) {
				str = json_string_value(type);
				if (!strcmp(str, "giaddr"))
					cfg->opt82.rid_type = RID_TYPE_GIADDR;
				else if (!strcmp(str, "hostname"))
					cfg->opt82.rid_type = RID_TYPE_HOSTNAME;
				else if (!strcmp(str, "manual")) {
					cfg->opt82.rid_type = RID_TYPE_MANUAL;
					data = json_object_get(remote, "data");
					option82_parse_manual(data, cfg->opt82.remote_id, sizeof(cfg->opt82.remote_id),
							      &cfg->opt82.remote_id_len);
				}
			}
		}
	}
	return 0;
}

static int read_ifaces(json_t *json, cfg_group_t *group)
{
	json_t *arr, *obj;
	size_t i;

	TAILQ_INIT(&group->iface_list);

	arr = json_object_get(json, "ifaces");
	if (!json_is_array(arr)) {
		cfg_iface_t *iface;

		syslog2(LOG_DEBUG, "No ifaces node, use same as in group");
		iface = malloc(sizeof(*iface));
		if (!iface) {
			syslog2(LOG_ERR, "Failed allocate memory: %s", strerror(errno));
			return 1;
		}

		memset(iface, 0, sizeof(*iface));
		iface->ifindex = group->ifindex;
		TAILQ_INSERT_TAIL(&group->iface_list, iface, link);
		return 0;
	}

	json_array_foreach(arr, i, obj) {
		cfg_iface_t *iface;
		json_t *ifname, *option82;

		if (!json_is_object(obj))
			return 1;

		ifname = json_object_get(obj, "ifname");
		if (!json_is_string(ifname))
			return 1;

		iface = malloc(sizeof(*iface));
		if (!iface) {
			syslog2(LOG_ERR, "Failed allocate memory: %s", strerror(errno));
			return 1;
		}

		memset(iface, 0, sizeof(*iface));
		iface->ifindex = if_nametoindex(json_string_value(ifname));

		option82 = json_object_get(obj, "option82");	/* Iface specific option82-settings */
		if (json_is_object(option82)) {
			json_t *circuit = json_object_get(option82, "circuit-id");

			option82_parse_manual(circuit, iface->circuit_id, sizeof(iface->circuit_id), &iface->circuit_id_len);
		}

		TAILQ_INSERT_TAIL(&group->iface_list, iface, link);
	}

	return 0;
}

static int read_servers(json_t *json, cfg_t *cfg, cfg_group_t *group)
{
	json_t *arr, *obj, *address;
	size_t i;

	if (group)
		TAILQ_INIT(&group->server_list);
	else
		TAILQ_INIT(&cfg->server_list);

	arr = json_object_get(json, "servers");
	if (!json_is_array(arr))
		return 0;

	json_array_foreach(arr, i, obj) {
		cfg_server_t *server;

		if (!json_is_object(obj))
			return 1;

		address = json_object_get(obj, "address");
		if (!json_is_string(address))
			return 1;

		server = malloc(sizeof(*server));
		if (!server) {
			syslog2(LOG_ERR, "Failed allocate memory: %s", strerror(errno));
			return 1;
		}
		inet_pton(AF_INET, json_string_value(address), &server->addr);
		if (read_int(obj, &server->port, "port", 67)) {
			free(server);
			return 1;
		}
		if (group)
			TAILQ_INSERT_TAIL(&group->server_list, server, link);
		else
			TAILQ_INSERT_TAIL(&cfg->server_list, server, link);
	}

	return 0;
}

static int read_group(json_t *json, cfg_t *cfg)
{
	json_t *obj, *arr;
	int i;
	struct ifaddrs *ifap, *ifa;
	cfg_group_t *group = NULL;

	arr = json_object_get(json, "groups");
	if (!json_is_array(arr))
		return 1;

	getifaddrs(&ifap);
	if (!ifap)
		return 1;

	TAILQ_INIT(&cfg->group_list);
	json_array_foreach(arr, i, obj) {
		json_t *ifname, *giaddr;
		struct sockaddr_in *sa;

		if (!json_is_object(obj))
			goto err;

		group = malloc(sizeof(*group));
		if (!group) {
			syslog2(LOG_ERR, "Failed allocate memory: %s", strerror(errno));
			goto err;
		}
		memset(group, 0, sizeof(*group));

		/* Parse giaddr */
		giaddr = json_object_get(obj, "giaddr");
		if (!json_is_string(giaddr))
			goto err;

		if (!inet_pton(AF_INET, json_string_value(giaddr), &group->giaddr))
			goto err;

		/* Parse/find interface for giaddr */
		ifname = json_object_get(obj, "ifname");
		if (json_is_string(ifname)) {
			group->ifindex = if_nametoindex(json_string_value(ifname));
		} else {
			for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
				if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
					sa = (struct sockaddr_in *)ifa->ifa_addr;
					if (sa->sin_addr.s_addr == group->giaddr) {
						syslog2(LOG_DEBUG, "Found interface %s", ifa->ifa_name);
						group->ifindex = if_nametoindex(ifa->ifa_name);
						break;
					}
				}
			}
		}
		if (!group->ifindex)
			goto err;

		/* Parse all interfaces in this group */
		read_ifaces(obj, group);

		/* Parse all group specific servers. */
		read_servers(obj, NULL, group);
		TAILQ_INSERT_TAIL(&cfg->group_list, group, link);
	}

	freeifaddrs(ifap);
	return 0;
 err:
	if (group)
		free(group);
	freeifaddrs(ifap);
	return 1;
}

/**
   Read option 11 (force server ID)
 */
static int read_force_sid(json_t *json, cfg_t *cfg)
{
	json_t *obj;

	obj = json_object_get(json, "force-server-id");


	if (obj && json_is_boolean(obj))
		cfg->force_server_id = json_is_true(obj);

	return 0;
}

/* Check that config is consistent, return 0 if not ok. */
static int conf_validate(cfg_t *cfg)
{
	cfg_group_t *group;

	TAILQ_FOREACH(group, &cfg->group_list, link) {
		if (TAILQ_EMPTY(&group->server_list) && TAILQ_EMPTY(&cfg->server_list)) {
			syslog2(LOG_ERR, "No servers found for group.");
			return 0;
		}
	}

	return 1;
}

int conf_read(cfg_t *cfg, char *file)
{
	json_t *json;
	json_error_t error;

	memset(cfg, 0, sizeof(*cfg));

	if (!file)
		return 1;

	json = json_load_file(file, 0, &error);
	if (!json) {
		syslog2(LOG_ERR, "Could not open %s, %d:%s", file, error.line, error.text);
		return 1;
	}

	if (read_servers(json, cfg, NULL))
		goto err;

	if (read_force_sid(json, cfg))
		goto err;


	if (read_option82(json, cfg))
		goto err;

	if (read_group(json, cfg))
		goto err;

	if (!conf_validate(cfg))
		goto err;

	json_decref(json);
	return 0;
 err:
	json_decref(json);
	conf_free(cfg);

	return 1;
}

void conf_free(cfg_t *cfg)
{
	cfg_group_t *group, *itemp;
	cfg_server_t *server, *stemp;

	TAILQ_FOREACH_SAFE(group, &cfg->group_list, link, itemp) {
		cfg_iface_t *iface, *ptemp;

		TAILQ_FOREACH_SAFE(server, &group->server_list, link, stemp) {
			TAILQ_REMOVE(&group->server_list, server, link);
			free(server);
		}
		TAILQ_FOREACH_SAFE(iface, &group->iface_list, link, ptemp) {
			TAILQ_REMOVE(&group->iface_list, iface, link);
			free(iface);
		}
		TAILQ_REMOVE(&cfg->group_list, group, link);
		free(group);
	}

	TAILQ_FOREACH_SAFE(server, &cfg->server_list, link, stemp) {
		TAILQ_REMOVE(&cfg->server_list, server, link);
		free(server);
	}
}
