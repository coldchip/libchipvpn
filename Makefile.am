AM_CFLAGS = -std=gnu99 -Wall -Werror

AUTOMAKE_OPTIONS = subdir-objects foreign
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

lib_LTLIBRARIES = libchipvpn.la

libchipvpn_la_LDFLAGS = -lsodium -version-info $(LIBCHIPVPN_SO_VERSION)
libchipvpn_la_SOURCES = src/list.c src/chipvpn.c src/socket.c src/tun.c src/crypto.c src/peer.c src/address.c src/device.c src/ini.c src/sb.c

libchipvpn_includedir = $(includedir)/chipvpn
#nobase_libcircle_include_HEADERS = libcircle.h

# headers to be installed in /include
libchipvpn_include_HEADERS = src/address.h src/crypto.h src/ini.h src/packet.h src/sb.h src/tun.h src/chipvpn.h src/device.h src/list.h src/peer.h src/socket.h

# headers that should be part of distribution
# but not installed in /include
# noinst_HEADERS = \
#         libcircle/log.h \
#         libcircle/lib.h \
#         libcircle/queue.h \
#         libcircle/token.h \
#         libcircle/worker.h

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libchipvpn.pc

#dist_noinst_SCRIPTS = autogen.sh

MAINTAINERCLEANFILES =                                  \
        aclocal.m4 config.guess config.xml              \
        config.h.in config.sub configure install-sh     \
        ltconfig ltmain.sh missing mkinstalldirs        \
        stamp-h.in

distclean-local:
	-(cd $(top_srcdir) && rm -rf autom4te*.cache autoscan.*)
	-(cd $(top_srcdir) && rm -rf $(PACKAGE)-* libchipvpn.pc)

mrproper: distclean-local clean
	-(cd $(top_srcdir) && rm -rf autom4te.cache config.h config.log)
	-(cd $(top_srcdir) && rm -rf config.status libtool stamp-h1)
	-(cd $(top_srcdir) && rm -rf auxdir)
	-(cd $(top_srcdir) && rm -f configure configure.ac~)
	-(cd $(top_srcdir) && rm -f aclocal.m4 config.h.in config.h.in~)
	-(cd $(top_srcdir)/m4 && rm -f libtool.m4 ltoptions.m4)
	-(cd $(top_srcdir)/m4 && rm -f ltsugar.m4 ltversion.m4)
	-(cd $(top_srcdir)/m4 && rm -f lt~obsolete.m4)
	-(cd $(top_srcdir)/doc && rm -f Doxyfile)
	-(cd $(top_srcdir)/tests && rm -f chipvpn*.txt)
	-find $(top_srcdir)/ -name "Makefile" -exec rm {} \;
	-find $(top_srcdir)/ -name "Makefile.in" -exec rm {} \;
	-find $(top_srcdir)/ -name ".dirstamp" -exec rm {} \;
	-find $(top_srcdir) -depth -name ".deps" -exec rm -rf {} \;
