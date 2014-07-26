# dist + install simple docs
dist_doc_DATA = gdnsd_manual.txt

PODS_1 = gdnsd_geoip_test.pod
PODS_3 = gdnsd-plugin-api.pod
PODS_5 = \
	gdnsd.config.pod \
	gdnsd.zonefile.pod \
	gdnsd.djbdns.pod
PODS_8 = \
	gdnsd.pod \
	gdnsd-plugin-extfile.pod \
	gdnsd-plugin-extmon.pod \
	gdnsd-plugin-geoip.pod \
	gdnsd-plugin-http_status.pod \
	gdnsd-plugin-metafo.pod \
	gdnsd-plugin-multifo.pod \
	gdnsd-plugin-null.pod \
	gdnsd-plugin-reflect.pod \
	gdnsd-plugin-simplefo.pod \
	gdnsd-plugin-static.pod \
	gdnsd-plugin-tcp_connect.pod \
	gdnsd-plugin-weighted.pod

# This translates default path variables in the pod sources
MAN_SED = $(SED) \
	-e 's|@GDNSD_DEFPATH_CONFIG[@]|$(GDNSD_DEFPATH_CONFIG)|g' \
	-e 's|@GDNSD_DEFPATH_STATE[@]|$(GDNSD_DEFPATH_STATE)|g' \
	-e 's|@GDNSD_DEFPATH_RUN[@]|$(GDNSD_DEFPATH_RUN)|g' \
	-e 's|@GDNSD_DEFPATH_LIB[@]|$(GDNSD_DEFPATH_LIB)|g' \
	-e 's|@GDNSD_DEFPATH_LIBEXEC[@]|$(GDNSD_DEFPATH_LIBEXEC)|g'

# Gather up the .pod files (which are distributed but not installed)
ALL_PODS = $(PODS_1) $(PODS_3) $(PODS_5) $(PODS_8)
EXTRA_DIST = $(ALL_PODS)

# Manpages for installation, generated via sed templating then pod2man
#  (the Makefile dep is for the sed command on change of --prefix, etc)
nodist_man_MANS = $(PODS_1:.pod=.1) $(PODS_3:.pod=.3) $(PODS_5:.pod=.5) $(PODS_8:.pod=.8)
$(nodist_man_MANS): Makefile
clean-local:
	rm -f $(nodist_man_MANS)
.pod.8:
	$(AM_V_GEN)$(MAN_SED) <$< | $(POD2MAN) --section=8 --release="$(PACKAGE_NAME) $(VERSION)" --center=$(PACKAGE_NAME) >$@
.pod.5:
	$(AM_V_GEN)$(MAN_SED) <$< | $(POD2MAN) --section=5 --release="$(PACKAGE_NAME) $(VERSION)" --center=$(PACKAGE_NAME) >$@
.pod.3:
	$(AM_V_GEN)$(MAN_SED) <$< | $(POD2MAN) --section=3 --release="$(PACKAGE_NAME) $(VERSION)" --center=$(PACKAGE_NAME) >$@
.pod.1:
	$(AM_V_GEN)$(MAN_SED) <$< | $(POD2MAN) --section=1 --release="$(PACKAGE_NAME) $(VERSION)" --center=$(PACKAGE_NAME) >$@

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
		wikifn=`echo $$podsrc | $(PERL) -pe 's/^([a-z])/uc($$1)/e; s/[_.-]([a-zA-Z0-9])/uc($$1)/ge; s/Pod$$/.pod/'`; \
		echo Copying $$podsrc to $(WIKI_DIR)/$$wikifn ...; \
		cp $$podsrc $(WIKI_DIR)/$$wikifn; \
	done
