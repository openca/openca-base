# file: src/common/lib/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../..
include $(TOP)/Makefile.global-vars

SUBDIRS	= \
	bp		\
	cmds		\
	functions	\
	locale		\
	mails		\
	stylesheets

#---- variable settings above, rules below ----

.PHONY:	default test install clean clean.local distclean

default::	$(SUBDIRS)

install::	$(SUBDIRS)

$(SUBDIRS)::
		cd $@ && $(MAKE) $(SUBTARGET)

test install clean distclean::
		$(MAKE) $(SUBDIRS) SUBTARGET=$@

distclean::
		#$(RM)
