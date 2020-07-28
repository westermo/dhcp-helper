SUBDIRS = src tests
AUTOMAKE_OPTIONS = subdir-objects
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS}

doc_DATA            = README.md ChangeLog.md
EXTRA_DIST          = README.md ChangeLog.md
dist_man8_MANS      = dhcp-helper.8
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
