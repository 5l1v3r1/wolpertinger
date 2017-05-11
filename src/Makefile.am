## Process this file with automake to produce Makefile.in

## Created by Anjuta

if DEBUG
    AM_CFLAGS = -Wall -g3 -O0
    AM_CXXFLAGS = -Wall -g3 -O0
    AM_CPPFLAGS = -Wall -g3 -O0
else
    AM_CFLAGS = -Wall -O2
    AM_CXXFLAGS = -Wall -O2
    AM_CPPFLAGS = -Wall -O2
endif

bin_PROGRAMS = \
	wolpertinger\
	wolperdrone

wolperdrone_SOURCES = \
	gitversion.h \
	ipc.cc       \
	ipc.h       \
	shared.cc       \
	shared.h       \
	wolperdrone.cc       \
	wolperdrone.h \
	net.cc \
	net.h

wolperdrone_LDADD = $(WOLPERDRONE_LIBS)

wolperdrone_CXXFLAGS = \
	-DPREFIX_DIR=\"$(prefix)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DSYSCONFDIR=\"${sysconfdir}\"

wolpertinger_SOURCES = \
	gitversion.h \
	ipc.h \
	shared.cc \
	ipc.cc \
	shared.h \
	main.cc \
	main.h \
	drone.cc \
	drone.h \
	database.h \
	database.cc

wolpertinger_LDADD = $(WOLPERTINGER_LIBS)

wolpertinger_CXXFLAGS = \
	-DPACKAGE_DATA_DIR=\"$(pkgdatadir)\" \
	-DPREFIX_DIR=\"$(prefix)\" \
	-DLOCALSTATEDIR=\"$(localstatedir)\" \
	-DSYSCONFDIR=\"${sysconfdir}\"

