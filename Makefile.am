## Process this file with automake to produce Makefile.in

SUBDIRS = src \
	docs\
	data\
	scripts\
    test

# Copy all the spec files. Of cource, only one is actually used.
dist-hook:
	for specfile in *.spec; do \
		if test -f $$specfile; then \
			cp -p $$specfile $(distdir); \
		fi \
	done

