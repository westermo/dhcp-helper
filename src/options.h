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

#ifndef __OPTIONS_H__
#define __OPTIONS_H__
#include "packet.h"

size_t add_options (struct dhcp_packet_with_opts *mess, size_t sz, int iface_index, struct in_addr iface_addr, cfg_group_t *group, cfg_t *cfg);
size_t remove_options(struct dhcp_packet_with_opts *mess, size_t sz);

#endif
