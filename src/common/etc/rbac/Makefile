# file: src/common/etc/rbac/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../../..
include $(TOP)/Makefile.global-vars

DEST_CONFRBACDIR	= ${etc_prefix}/rbac

SUBDIRS	= \
	cmds

FILES = \
	modules.xml	\
	roles.xml

TEMPLATES = \
	acl.xml

#---- variable settings above, rules below ----

.PHONY:	default install clean distclean

default::

install::	$(FILES) $(TEMPLATES)
install clean distclean::
		$(MAKE) $(SUBDIRS) SUBTARGET=$@

$(SUBDIRS)::
		cd $@ && $(MAKE) $(SUBTARGET)

$(FILES)::
	$(INSTALL) -g ${httpd_group} -o ${httpd_user} -m 644 $@ $(DEST_CONFRBACDIR)/$@

$(TEMPLATES)::
	$(INSTALL) -g ${httpd_group} -o ${httpd_user} -m 644 $@ $(DEST_CONFRBACDIR)/$@.template
