AUTOMAKE_OPTIONS = subdir-objects foreign
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

# lib_LTLIBRARIES = libchipvpn.la
# libchipvpn_la_SOURCES = src/main.c src/chipvpn.c src/socket.c src/crypto.c src/peer.c src/address.c src/device.c src/list.c src/list.h src/util.c src/xchacha20.c src/sha256.c
# libchipvpn_la_LDFLAGS = -module -avoid-version -export-dynamic

bin_PROGRAMS = chipvpn
chipvpn_SOURCES = src/main.c src/chipvpn.c src/socket.c src/crypto.c src/peer.c src/address.c src/device.c src/list.c src/list.h src/util.c src/xchacha20.c src/sha256.c

CFLAGS = -Ofast -s -std=gnu99 -Wall
LDADD = 

MAINTAINERCLEANFILES =                                  \
        aclocal.m4 config.guess config.xml              \
        config.h.in config.sub configure install-sh     \
        ltconfig ltmain.sh missing mkinstalldirs        \
        stamp-h.in

distclean-local:
	-(cd $(top_srcdir) && rm -rf autom4te*.cache autoscan.*)
	-(cd $(top_srcdir) && rm -rf $(PACKAGE)-*)

mrproper: distclean-local clean
	-(cd $(top_srcdir) && rm -rf autom4te.cache config.h config.log)
	-(cd $(top_srcdir) && rm -rf config.status libtool stamp-h1)
	-(cd $(top_srcdir) && rm -rf auxdir)
	-(cd $(top_srcdir) && rm -f configure configure.ac~)
	-(cd $(top_srcdir) && rm -f aclocal.m4 config.h.in config.h.in~)
	-(cd $(top_srcdir)/m4 && rm -f libtool.m4 ltoptions.m4)
	-(cd $(top_srcdir)/m4 && rm -f ltsugar.m4 ltversion.m4)
	-(cd $(top_srcdir)/m4 && rm -f lt~obsolete.m4)
	-find $(top_srcdir)/ -name "Makefile" -exec rm {} \;
	-find $(top_srcdir)/ -name "Makefile.in" -exec rm {} \;
	-find $(top_srcdir)/ -name ".dirstamp" -exec rm {} \;
	-find $(top_srcdir) -depth -name ".deps" -exec rm -rf {} \;