SUBDIRS = tests
AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}

# additional include paths necessary to compile the C++ library
AM_CFLAGS = -fno-strict-aliasing -I$(top_srcdir)/src/include $(LIB_CFLAGS) $(LIBNL_CFLAGS) -Wall -O0 -g3 -fmessage-length=0  @AM_CFLAGS@

dhcp_helper_LDADD = $(DEPS_LIBS) $(LIB_CFLAGS) $(JANSSON_LIBS) $(LIBNL_LIBS)

bin_PROGRAMS = dhcp-helper
dhcp_helper_SOURCES = \
	src/dhcp-helper.c src/conf.c src/packet.c src/options.c src/logging.c src/misc.c

pkginclude_HEADERS = \
	src/include/conf.h src/include/misc.h src/include/logging.h src/include/options.h src/include/packet.h src/include/queue.h

dist_noinst_SCRIPTS = autogen.sh

# Generate MD5 checksum file
MD5 = md5sum
md5-dist:
	@for file in $(DIST_ARCHIVES); do	\
		$(MD5) $$file > $$file.md5;	\
	done

# Target to run when building a release
release: dist md5-dist
	@for file in $(DIST_ARCHIVES); do				\
		printf "$$file    \tDistribution tarball\n";		\
		printf "$$file.md5\t"; cat $$file.md5 | cut -f1 -d' ';	\
done
