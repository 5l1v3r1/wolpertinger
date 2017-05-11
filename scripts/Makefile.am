CLEANFILES = wolper-mcp.py wolperctl wolper-init wolper.service

SUBDIRS = modules

wolper_init_SCRIPTS = \
	wolper-init

wolper_initdir = \
	$(sysconfdir)/init.d

wolper_systemd_DATA = \
	wolper.service

wolper_systemddir = \
	$(libdir)/systemd/system

wolper_script_SCRIPTS = \
	wolper-mcp.py \
	wolperctl

wolper_scriptdir = \
	$(bindir)

wolper-init:
	cat wolper-init.in | sed "s#__WOLPER_BIN_DIR__#$(bindir)#g" > wolper-init

wolper.service:
	cat wolper.service.in | sed "s#__WOLPER_BIN_DIR__#$(bindir)#g" > wolper.service

wolper-mcp.py:
	cat wolper-mcp.in | sed "s#__WOLPER_DATA_DIR__#$(pkgdatadir)#g" | sed "s#__WOLPER_VERSION__#$(PACKAGE_VERSION)#g" > wolper-mcp.py

wolperctl:
	cat wolperctl.in | sed "s#__WOLPER_STATE_DIR__#$(localstatedir)#g" | sed "s#__WOLPER_SYSCONF_DIR__#$(sysconfdir)#g" | sed "s#__WOLPER_VERSION__#$(PACKAGE_VERSION)#g" > wolperctl
