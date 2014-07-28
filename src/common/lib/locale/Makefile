# file: src/common/lib/locale/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../../..
include $(TOP)/Makefile.global-vars

DEST_MO_DIR		= ${lib_prefix}/locale

MO_FILE		= openca.mo
DEST_MO_FILES	= $(DEST_LOCALE_DIRS:%=%/$(MO_FILE))

#---- variable settings above, rules below ----

.PHONY:	default test install clean clean.local distclean openca.pot

default::

install::	$(TRANSLATIONS)

$(TRANSLATIONS)::
		$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} DIR=$(DEST_MO_DIR)/$@
		$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} DIR=$(DEST_MO_DIR)/$@/LC_MESSAGES
		$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $@/$(MO_FILE) $(DEST_MO_DIR)/$@/LC_MESSAGES/$(MO_FILE)

.SUFFIXES: .mo .po

.po.mo:
	msgfmt -o $@ $<

test install clean distclean::

distclean::
		#$(RM)
