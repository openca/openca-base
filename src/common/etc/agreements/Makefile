# file: src/common/etc/rbac/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../../..
include $(TOP)/Makefile.global-vars

DEST_CONFAGREEMENTSDIR	= ${etc_prefix}/agreements

SUBDIRS	= 

FILES = 

TEMPLATES = \
	low.html \
	general.html

#---- variable settings above, rules below ----

.PHONY:	default install clean distclean

default::

install::	$(FILES) $(TEMPLATES)
install clean distclean::
		$(MAKE) $(SUBDIRS) SUBTARGET=$@

$(SUBDIRS)::
		cd $@ && $(MAKE) $(SUBTARGET)

$(FILES)::
	$(INSTALL) -g ${httpd_group} -o ${httpd_user} -m 644 $@ $(DEST_CONFAGREEMENTSDIR)/$@

$(TEMPLATES)::
	$(INSTALL) -g ${httpd_group} -o ${httpd_user} -m 644 $@ $(DEST_CONFAGREEMENTSDIR)/$@.template
