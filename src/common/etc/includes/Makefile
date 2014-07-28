# file: src/common/etc/rbac/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../../..
include $(TOP)/Makefile.global-vars

DEST_CONF_INC_DIR	= ${etc_prefix}/includes

SUBDIRS	= 

FILES = \
	home_body.inc \
	home_body.inc.it_IT \
	home_body.inc.es_ES \
	home_body.inc.pl_PL \
	home_body.inc.de_DE \
	home_body.inc.ro_RO

TEMPLATES = \

#---- variable settings above, rules below ----

.PHONY:	default install clean distclean

default::

install::	$(FILES) $(TEMPLATES)
install clean distclean::
		$(MAKE) $(SUBDIRS) SUBTARGET=$@

$(SUBDIRS)::
		cd $@ && $(MAKE) $(SUBTARGET)

$(FILES)::
	$(INSTALL) -g ${httpd_group} -o ${httpd_user} -m 644 $@ $(DEST_CONF_INC_DIR)/$@

$(TEMPLATES)::
	$(INSTALL) -g ${httpd_group} -o ${httpd_user} -m 644 $@ $(DEST_CONF_INC_DIR)/$@.template

