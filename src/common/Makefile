# file: src/common/Makefile
#
# © 2001 OpenCA Group

TOP	= ../..
include $(TOP)/Makefile.global-vars

COMMON_DIRS = \
	etc	\
	lib	\
	var	\

#---- variable settings above, rules below ----

.PHONY:	default test install install-common

default::	$(COMMON_DIRS)

install-common::	install

$(COMMON_DIRS)::
		cd $@ && $(MAKE) $(SUBTARGET)

test install clean distclean::
		$(MAKE) $(COMMON_DIRS) SUBTARGET=$@

distclean::
		#$(RM)
