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
#ifndef __MISC_H__
#define __MISC_H__
#include "conf.h"

int setup_nftables(cfg_t *cfg);
int cleanup_nftables(cfg_t *cfg);
int add_arp_entry(int ifindex, unsigned char *mac, struct sockaddr_in saddr);
int add_fdb_entry(int ifindex, unsigned char *mac);
#endif
