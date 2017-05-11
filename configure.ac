dnl Process this file with autoconf to produce a configure script.
dnl Created by Anjuta application wizard.

dnl get package version from git
AC_INIT([wolpertinger], m4_esyscmd_s(git describe --tags --long --abbrev=7 | sed 's/^v//'))

AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([src/config.h])
AM_MAINTAINER_MODE

AC_ARG_ENABLE(debug,
    AS_HELP_STRING([--enable-debug],
        [enable debugging, default: no]),
    [case "${enableval}" in
        yes) debug=true ;;
        no)  debug=false ;;
        *)   AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
    esac],
    [debug=false])
AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")

AC_PREFIX_DEFAULT([/usr])
dnl sysconfdir default will be changed/hacked in autogen.sh to /etc

dnl disable compiler optimisation
AC_SEARCH_LIBS([strerror],[cposix])
AC_PROG_CC
AC_PROG_CXX
dnl AC_DIAGNOSE([obsolete],[AM_PROG_CC_STDC:
dnl 	your code should no longer depend upon 'am_cv_prog_cc_stdc', but upon
dnl 	'ac_cv_prog_cc_stdc'.  Remove this warning and the assignment when
dnl 	you adjust the code.  You can also remove the above call to
dnl 	AC_PROG_CC if you already called it elsewhere.])
dnl am_cv_prog_cc_stdc=$ac_cv_prog_cc_stdc

AC_HEADER_STDC
AC_CHECK_HEADERS([arpa/inet.h errno.h fcntl.h netdb.h netinet/in.h netinet/ether.h stdlib.h string.h sys/time.h unistd.h pcap.h sqlite3.h openssl/evp.h uuid/uuid.h sys/socket.h sys/ioctl.h sys/wait.h sys/types.h net/if.h arpa/inet.h asm/types.h stdio.h linux/netlink.h linux/rtnetlink.h],[],[AC_MSG_ERROR([required header files missing])])
dnl check for libdnet header
dnet=0
AC_CHECK_HEADERS([dumbnet.h],[dnet=1],[])
AC_CHECK_HEADERS([dnet.h],[dnet=1],[])
if test "x$dnet" = "x0"; then
  AC_MSG_ERROR([required header file for libdnet missing])
fi


dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_HEADER_TIME
AC_STRUCT_TM

dnl Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([bzero gethostbyaddr gethostbyname gettimeofday inet_ntoa memset select socket connect getsockname strdup strtol close ioctl memcpy])

dnl Check for librarys
_CONF_LIB="$LIBS"
LIBS=""
WOLPERTINGER_LIBS=""
WOLPERDRONE_LIBS=""
AC_CHECK_LIB([pcap], [pcap_lookupnet, pcap_open_live, pcap_compile, pcap_geterr, pcap_setfilter, pcap_setdirection, pcap_setnonblock, pcap_datalink, pcap_get_selectable_fd, pcap_dispatch], [], [AC_MSG_ERROR([required library libpcap missing or incomplete])])
WOLPERDRONE_LIBS="$WOLPERDRONE_LIBS $LIBS"; LIBS=""
AC_CHECK_LIB([crypto], [EVP_MD_CTX_create, EVP_MD_CTX_destroy, EVP_md5, EVP_DigestInit, EVP_DigestUpdate, EVP_DigestFinal_ex, EVP_MD_CTX_cleanup, OpenSSL_add_all_digests, EVP_get_digestbyname, EVP_MD_CTX_init, EVP_DigestInit_ex], [], [AC_MSG_ERROR([required library libcrypto (from openssl?) missing or incomplete])])
WOLPERTINGER_LIBS="$WOLPERTINGER_LIBS $LIBS"; WOLPERDRONE_LIBS="$WOLPERDRONE_LIBS $LIBS"; LIBS=""
AC_CHECK_LIB([sqlite3], [sqlite3_open, sqlite3_errmsg, sqlite3_close, sqlite3_exec,sqlite3_free], [], [AC_MSG_ERROR([required library libsqlite3 missing or incomplete])])
WOLPERTINGER_LIBS="$WOLPERTINGER_LIBS $LIBS"; LIBS=""
AC_CHECK_LIB([uuid], [uuid_generate], [], [AC_MSG_ERROR([required library libuuid missing or incomplete])])
WOLPERDRONE_LIBS="$WOLPERDRONE_LIBS $LIBS"; LIBS=""
AC_CHECK_LIB([dumbnet], [ip_close, ip_open, intf_open, intf_get, addr_ntoa, ip_send, eth_open, eth_pack_hdr, arp_pack_hdr_ethip, eth_send, eth_close, arp_open, arp_get, arp_close, route_open, route_get, route_close], [], [])
if test "x$LIBS" = "x"; then
  AC_CHECK_LIB([dnet], [ip_close, ip_open, intf_open, intf_get, addr_ntoa, ip_send, eth_open, eth_pack_hdr, arp_pack_hdr_ethip, eth_send, eth_close, arp_open, arp_get, arp_close, route_open, route_get, route_close], [], [])
  if test "x$LIBS" = "x"; then
    AC_MSG_ERROR([required library libdnet missing or incomplete])
  fi
fi
WOLPERDRONE_LIBS="$WOLPERDRONE_LIBS $LIBS"; LIBS=""
LIBS="$_CONF_LIB" dnl reset LIBS to previous value
dnl echo "LIBS:              " $LIBS
dnl echo "WOLPERTINGER_LIBS: " $WOLPERTINGER_LIBS
dnl echo "WOLPERDRONE_LIBS:  " $WOLPERDRONE_LIBS
AC_SUBST(WOLPERTINGER_LIBS)
AC_SUBST(WOLPERDRONE_LIBS)

AC_PROG_RANLIB

dnl no compiler optimization
CXXFLAGS=""

builddir="`pwd`"

dnl check system architecture
AC_CANONICAL_HOST
case "${host_cpu}" in
x86_64|sparc64)
    AC_DEFINE([CPU_64], [1], [64 Bit CPU])
    ;;
i386|i586|i686)
    AC_DEFINE([CPU_32], [1], [32 Bit CPU])
    ;;
*)
    AC_MSG_ERROR([unsupported build architecture. sorry...])
    ;;
esac


dnl check if database needs to be generated
AC_MSG_CHECKING(for wolpertinger.db)
if test -f "$builddir/data/wolpertinger.db"; then
	AC_MSG_RESULT(yes)
else
	AC_MSG_RESULT(no)
	echo -n "generating wolpertinger.db... "
	"$builddir/data/create_db.py" "$builddir/data" &> /dev/null
	if test -f "$builddir/data/wolpertinger.db"; then
		echo "done"
	else
		AC_MSG_ERROR([generation of wolpertinger.db failed in data/create_db.py])
	fi
fi

AC_CONFIG_FILES([
Makefile
data/Makefile
docs/Makefile
scripts/Makefile
scripts/modules/Makefile
src/Makefile
test/Makefile
])
AC_OUTPUT
