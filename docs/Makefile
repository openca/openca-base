# file: src/docs/Makefile
#
# © 2001 OpenCA Group

TOP	= ..
include $(TOP)/Makefile.global-vars

P2M_FLAGS	= --center="OpenCA Documentation" --release="OpenCA $(VERSION)"

MANDIRS	= \
	man3

PODS	= \
	man3/base.3.pod

POD_MANS	= $(PODS:%.pod=%)
MANS		= $(POD_MANS)

DEST_MANDIRS	= $(DEST_DIR)$(MANDIRS:%=$(DEST_MANDIR)/%)
DEST_MANS	= $(DEST_DIR)$(MANS:%=$(DEST_MANDIR)/%)

#---- variable settings above, rules below ----

.PHONY:	default test install install-ca install-ldap install-node install-ra install-pub install-scep install-modules install-batch clean distclean

default::	man

install-batch::
test::

install::	install-man
	$(MAKE) $(SUBDIRS) SUBTARGET=install

$(SUBDIRS)::
	cd $@ && make $(SUBTARGET)

##### BEGIN MAN AREA #####

man::		$(MANS)

.SUFFIXES:	.pod

.pod:
		section=`echo $< | sed -n -e 's/man\(.\).*/\1/p'`; \
		$(POD2MAN) $(P2M_FLAGS) --section=$$section $< > $@

$(DEST_MANDIR) $(DEST_MANDIRS):
		$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=755 DIR=$@

install-man::	$(DEST_MANS)

$(DEST_MANS)::	$(DEST_MANDIR) $(DEST_MANDIRS)
$(DEST_MANS)::
		$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $(@:$(DEST_MANDIR)/%=%) $@

##### END MAN AREA #####

# software is decoupled from the documentation, so do nothing here:
install-ca install-common install-ldap install-node install-ra install-pub install-scep install-modules:

clean::
#		$(RM) $(POD_MANS)

distclean::	clean
distclean::
		#$(RM)
