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

#include <stdarg.h>
#include <stdio.h>
#include "logging.h"

static int console = 0;

/*
 * Makes it possible to log to console only for debugging.
 */
void syslog2 (int level, const char *format, ...)
{
	va_list args;
	va_start(args, format);

	if (console)
	{
		vprintf(format, args);
		printf("\n");
	}
	else
		vsyslog(level, format, args);
	va_end(args);
}

void log_console(int enable)
{
	console = enable;
}
