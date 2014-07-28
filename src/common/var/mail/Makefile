# file: src/common/var/mail/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../../..
include $(TOP)/Makefile.global-vars

DEST_MAIL_DIR = $(var_prefix)

DIRS = \
	mail

SUBDIRS = \
	mail/crins	\
	mail/default

#---- variable settings above, rules below ----

.PHONY:	default test install clean distclean

default::

test::

install::	$(SUBDIRS)

$(SUBDIRS):: $(DIRS)
	$(MAKE) __install_dir USER=${httpd_user} GROUP=${httpd_group} MODE=750 DIR=$(DEST_MAIL_DIR)/$@

$(DIRS)::
	$(MAKE) __install_dir USER=${httpd_user} GROUP=${httpd_group} MODE=750 DIR=$(DEST_MAIL_DIR)/$@

clean::
distclean::
		#$(RM)
