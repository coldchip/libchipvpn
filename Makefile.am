AUTOMAKE_OPTIONS = subdir-objects foreign
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

bin_PROGRAMS = chipvpn
chipvpn_SOURCES = src/main.c src/chipvpn.c src/socket.c src/chacha20poly1305.c src/crc32.c src/curve25519.c src/peer.c src/address.c src/device.c src/control.c src/list.c src/util.c src/chacha20.c src/poly1305.c src/sha256.c src/hkdf_sha256.c src/hmac_sha256.c src/bitmap.c src/log.c

CFLAGS = -O3 -std=gnu99 -Wall
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