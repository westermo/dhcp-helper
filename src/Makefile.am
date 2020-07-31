bin_PROGRAMS          = dhcp-helper

dhcp_helper_CFLAGS    = -W -Wall -Wextra -fno-strict-aliasing
dhcp_helper_CFLAGS   += $(JANSSON_CFLAGS) $(LIBNL_CFLAGS)
dhcp_helper_LDADD     = $(JANSSON_LIBS)   $(LIBNL_LIBS)
dhcp_helper_SOURCES   = dhcp-helper.c options.h queue.h conf.c conf.h	\
			packet.c packet.h options.c logging.c logging.h	\
			misc.c misc.h
