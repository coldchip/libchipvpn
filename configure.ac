AC_INIT([ChipVPN],[0.3.0],[ryan@chip.sg],[libchipvpn],[http://github.com/coldchip/libchipvpn])

# Keep artifacts in directories as much as possible.
AC_CONFIG_AUX_DIR(auxdir)
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([-Wall no-define])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

AC_CONFIG_HEADERS([config.h])

# Check for compilers.
AC_PROG_CC
AM_PROG_CC_C_O

# Pull in libtool. We need to support ancient autotools, so don't use LT_INIT.
#LT_INIT
AC_PROG_LIBTOOL

# Checks for typedefs, structs, and compiler options.
AC_TYPE_SIZE_T
AC_C_INLINE

# Checks for library functs.
AC_FUNC_LSTAT_FOLLOWS_SLASHED_SYMLINK
AC_FUNC_MALLOC

AC_SUBST([LIBCHIPVPN_SO_VERSION], [3:1:1])

AC_SUBST([LIBCHIPVPN_API_VERSION], [0.3.0])

AC_OUTPUT([Makefile libchipvpn.pc:libchipvpn.pc.in])
