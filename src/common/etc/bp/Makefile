# file: src/common/etc/bp/Makefile
#
# © 2001-2004 OpenCA Group

TOP	= ../../../..
include $(TOP)/Makefile.global-vars

DEST_ETCBPDIR	= ${etc_prefix}/bp

SUBDIRS	= \
	functions

# files generated from .in files:
AC_CONFFILES	= \
	bp.xml

STATIC_CONFFILES	= \
	functions.txt	\
	states.txt

#---- variable settings above, rules below ----

.PHONY:	default install clean distclean

default::	$(SUBDIRS)

install::	$(AC_CONFFILES) $(STATIC_CONFFILES)

install clean distclean::
		$(MAKE) $(SUBDIRS) SUBTARGET=$@

$(SUBDIRS)::
		cd $@ && $(MAKE) $(SUBTARGET)

$(STATIC_CONFFILES) $(AC_CONFFILES)::
	$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $@ $(DEST_ETCBPDIR)/$@

distclean::
		for i in $(AC_CONFFILES) ; do \
			if test -e $$i ; then $(RM) "$$i" ; fi ;\
		done

