EXTRA_DIST = gdnsd.service.tmpl

if DO_SYSD_UNITFILE

gdnsd.service: gdnsd.service.tmpl
	$(AM_V_GEN)sed 's|@GDNSD_SBINDIR[@]|$(sbindir)|g' <$< >$@

clean-local:
	rm -f $(builddir)/gdnsd.service

systemdsystemunit_DATA = gdnsd.service

install-exec-hook:
	@echo
	@echo === READ ME ===
	@echo A systemd service unit file was installed at $(systemdsystemunitdir)/gdnsd.service
	@echo You may need to issue the following command to update systemd:
	@echo systemctl daemon-reload
	@echo You will also need to enable and/or start it via:
	@echo systemctl enable gdnsd
	@echo systemctl start gdnsd
	@echo

endif
