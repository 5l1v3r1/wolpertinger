 ## Process this file with automake to produce Makefile.in

AUTOMAKE_OPTIONS        = foreign subdir-objects

if DEBUG
    AM_CFLAGS = -Wall -g3 -O0
    AM_CXXFLAGS = -Wall -g3 -O0
    AM_CPPFLAGS = -Wall -g3 -O0
else
    AM_CFLAGS = -Wall -O2
    AM_CXXFLAGS = -Wall -O2
    AM_CPPFLAGS = -Wall -O2
endif

check_PROGRAMS = \
	drone_test \
	metaipc_test \
	net_test \
    time_test
# TODO \ and add others...

drone_testdir = $(top_srcdir)/test

drone_test_SOURCES = \
	drone_test.cc \
    cute/cute.h

drone_test_LDADD = \
	libwolpertinger.a \
	-lcrypto \
	-lsqlite3

metaipc_testdir = $(top_srcdir)/test

metaipc_test_SOURCES = \
	metaipc_test.cc \
    cute/cute.h

metaipc_test_LDADD = \
	libwolpertinger.a \
	-lcrypto \
	-lsqlite3

net_testdir = $(top_srcdir)/test

net_test_SOURCES = \
	net_test.cc \
    cute/cute.h

net_test_LDADD = \
	libwolpertinger.a \
	-lsqlite3 \
	$(WOLPERDRONE_LIBS)

time_testdir = $(top_srcdir)/test

time_test_SOURCES = \
	time_test.cc

time_test_LDADD = \
	libwolpertinger.a \
	-lcrypto \
	-lsqlite3

check_LIBRARIES = \
	libwolpertinger.a

#LIBS = \
#	libwolpertinger.a \
##	libwolperdrone.a
#	@LIBS@

libwolpertinger_a_SOURCES = \
	../src/ipc.h \
	../src/shared.cc \
	../src/ipc.cc \
	../src/shared.h \
	../src/main.cc \
	../src/main.h \
	../src/drone.cc \
	../src/drone.h \
	../src/database.h \
	../src/database.cc \
	../src/net.h \
	../src/net.cc

AM_CXXFLAGS = \
	-DPACKAGE_DATA_DIR=\"$(pkgdatadir)\" \
	-DPREFIX_DIR=\"$(prefix)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DSYSCONFDIR=\"${sysconfdir}\" \
	-DNOMAINFUNCTION \
	-fno-access-control \
    -I./cute -I$(top_srcdir)/src

check: $(check_PROGRAMS)
	./drone_test
	./metaipc_test
	./net_test
	./time_test
