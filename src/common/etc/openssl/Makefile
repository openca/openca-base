# file: src/common/etc/openssl/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../../..
include $(TOP)/Makefile.global-vars

DEST_ETCOPENSSLDIR	= ${etc_prefix}/openssl

SUBDIRS	= \
	openssl \
	extfiles

# files generated from .in files:
AC_CONFOPENSSLFILES	= \
	openssl.cnf		\
	sample-openssl.conf

STATIC_CONFOPENSSLFILES	= \
	sample-openssl.ext

#---- variable settings above, rules below ----

.PHONY:	default install clean distclean

default::	$(SUBDIRS)

install::	$(AC_CONFOPENSSLFILES) $(STATIC_CONFOPENSSLFILES)

install clean distclean::
		$(MAKE) $(SUBDIRS) SUBTARGET=$@

$(SUBDIRS)::
		cd $@ && $(MAKE) $(SUBTARGET)

$(AC_CONFOPENSSLFILES)::
	$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $@ $(DEST_ETCOPENSSLDIR)/$@.template

$(STATIC_CONFOPENSSLFILES)::
	$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $@.in $(DEST_ETCOPENSSLDIR)/$@.template

distclean::
		for i in $(AC_CONFOPENSSLFILES) ; do \
			if test -e $$i ; then $(RM) "$$i" ; fi ;\
		done

		# $(RM) $(AC_CONFOPENSSLFILES)
