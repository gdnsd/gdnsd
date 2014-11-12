# dist + install simple docs
dist_doc_DATA = gdnsd_manual.txt

PODS_IN_1 = gdnsd_geoip_test.podin
PODS_IN_3 = gdnsd-plugin-api.podin
PODS_IN_5 = \
	gdnsd.config.podin \
	gdnsd.zonefile.podin \
	gdnsd.djbdns.podin
PODS_IN_8 = \
	gdnsd.podin \
	gdnsd-plugin-extfile.podin \
	gdnsd-plugin-extmon.podin \
	gdnsd-plugin-geoip.podin \
	gdnsd-plugin-http_status.podin \
	gdnsd-plugin-metafo.podin \
	gdnsd-plugin-multifo.podin \
	gdnsd-plugin-null.podin \
	gdnsd-plugin-reflect.podin \
	gdnsd-plugin-simplefo.podin \
	gdnsd-plugin-static.podin \
	gdnsd-plugin-tcp_connect.podin \
	gdnsd-plugin-weighted.podin

# This translates default path variables in the pod sources
MAN_SED = $(SED) \
	-e 's|@GDNSD_DEFPATH_CONFIG[@]|$(GDNSD_DEFPATH_CONFIG)|g' \
	-e 's|@GDNSD_DEFPATH_STATE[@]|$(GDNSD_DEFPATH_STATE)|g' \
	-e 's|@GDNSD_DEFPATH_RUN[@]|$(GDNSD_DEFPATH_RUN)|g' \
	-e 's|@GDNSD_DEFPATH_LIB[@]|$(GDNSD_DEFPATH_LIB)|g' \
	-e 's|@GDNSD_DEFPATH_LIBEXEC[@]|$(GDNSD_DEFPATH_LIBEXEC)|g' \
	-e 's|@GDNSD_SBINDIR[@]|$(sbindir)|g'

# Gather up the .podin files (which are distributed but not installed)
ALL_PODS = $(PODS_IN_1) $(PODS_IN_3) $(PODS_IN_5) $(PODS_IN_8)
EXTRA_DIST = $(ALL_PODS)

# Manpages for installation, generated via sed templating then pod2man
#  (the Makefile dep is for the sed command on change of --prefix, etc)
nodist_man_MANS = $(PODS_IN_1:.podin=.1) $(PODS_IN_3:.podin=.3) $(PODS_IN_5:.podin=.5) $(PODS_IN_8:.podin=.8)
$(nodist_man_MANS): Makefile
clean-local:
	rm -f $(nodist_man_MANS)
.podin.pod:
	$(AM_V_GEN)$(MAN_SED) <$< >$@
.pod.8:
	$(AM_V_GEN)$(POD2MAN) --section=8 --release="$(PACKAGE_NAME) $(VERSION)" --center=$(PACKAGE_NAME) $< $@
.pod.5:
	$(AM_V_GEN)$(POD2MAN) --section=5 --release="$(PACKAGE_NAME) $(VERSION)" --center=$(PACKAGE_NAME) $< $@
.pod.3:
	$(AM_V_GEN)$(POD2MAN) --section=3 --release="$(PACKAGE_NAME) $(VERSION)" --center=$(PACKAGE_NAME) $< $@
.pod.1:
	$(AM_V_GEN)$(POD2MAN) --section=1 --release="$(PACKAGE_NAME) $(VERSION)" --center=$(PACKAGE_NAME) $< $@

# "make wikidocs" ->
# Basically it renames all the podfiles from e.g. gdnsd-plugin-geoip.pod
#   to GdnsdPluginGeoip.pod and stuffs them all in a new top-level build
#   directory "wikidocs" at the top.  From there I copy them to the gollum
#   repo for GitHub, wherever I happen to have that checked out at.  It's
#   a manual step on new stable releases to push these docs through to
#   the Github wiki.
WIKI_DIR = $(abs_top_builddir)/wikidocs
wikidocs:
	@if [ ! -d $(WIKI_DIR) ]; then \
		$(MKDIR_P) $(WIKI_DIR); \
	fi
	@for podsrc in $(ALL_PODS); do \
		wikifn=`echo $$podsrc | $(PERL) -pe 's/^([a-z])/uc($$1)/e; s/[_.-]([a-zA-Z0-9])/uc($$1)/ge; s/Podin$$/.pod/'`; \
		echo Copying $$podsrc to $(WIKI_DIR)/$$wikifn ...; \
		$(MAN_SED) <$$podsrc >$(WIKI_DIR)/$$wikifn; \
	done
