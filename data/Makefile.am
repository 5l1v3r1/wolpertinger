CLEANFILES = \
	wolpertinger.db

wolper_data_DATA = \
	create_db.py \
	wolper-services \
	wolpertinger.db

wolper_datadir = \
	$(pkgdatadir)

statedir_DATA = \
	KEEPTHIS

statedirdir = \
	$(localstatedir)/@PACKAGE@

wolpertinger.db:
	./create_db.py
