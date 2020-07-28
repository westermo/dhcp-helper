bin_PROGRAMS          = dhcp-helper

dhcp_helper_CFLAGS    = -W -Wall -Wextra
dhcp_helper_CFLAGS   += $(LIB_CFLAGS) $(LIBNL_CFLAGS)
dhcp_helper_LDADD     = $(DEPS_LIBS) $(LIB_CFLAGS) $(JANSSON_LIBS) $(LIBNL_LIBS)
dhcp_helper_SOURCES   = dhcp-helper.c options.h queue.h conf.c conf.h	\
			packet.c packet.h options.c logging.c logging.h	\
			misc.c misc.h
