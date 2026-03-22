AC_INIT([chipvpn], [10000001], [ryan@chipsixty.com])

AC_CONFIG_AUX_DIR(auxdir)
AC_CONFIG_MACRO_DIR([m4])

LT_INIT

AM_INIT_AUTOMAKE([foreign -Wall])

AC_PROG_CC

AM_PROG_AS

AC_CANONICAL_HOST

AC_MSG_CHECKING([for ARM/NEON support])

case "$host_cpu" in
  aarch64*)
    have_neon=yes
    ;;
  armv7*|arm*)
    have_neon=yes   dnl adjust if you want stricter detection
    ;;
  *)
    have_neon=no
    ;;
esac

AC_MSG_RESULT([$have_neon])

AM_CONDITIONAL([HAVE_NEON], [test "x$have_neon" = "xyes"])

if test "x$have_neon" = "xyes"; then
  AC_DEFINE([HAVE_NEON], [1], [Enable NEON optimizations])
  AC_DEFINE([HAVE_GCC_INLINE_ASM_NEON], [1], [NEON inline asm available])
fi

AC_CONFIG_FILES([Makefile])
AC_OUTPUT