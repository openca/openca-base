# file: src/common/etc/database/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../../..
include $(TOP)/Makefile.global-vars

DEST_CGI_CONFDIR	= ${etc_prefix}/database

# files derived from .in files:
AC_FILES	= 

TEMPLATE_FILES	= \
	DBI.conf.template

FILES		= $(AC_FILES)

#---- variable settings above, rules below ----

.PHONY:	default install install clean distclean

default::

install::	$(FILES) $(TEMPLATE_FILES)

$(FILES)::
		$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $@ $(DEST_CGI_CONFDIR)/$@

$(TEMPLATE_FILES)::
		$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $@ $(DEST_CGI_CONFDIR)/$@

clean distclean::
	@for i in $(AC_FILES) ; do \
		if test -e $$i ; then $(RM) "$$i" ; fi ;\
	done

