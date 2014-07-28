# file: src/web-interfaces/node/htdocs/scripts/Makefile
#
# © 2002 OpenCA Group

TOP	= ../../../../..
include $(TOP)/Makefile.global-vars

DEST_HTDOCS_SCRIPTDIR	= ${node_htdocs_fs_prefix}/scripts
SCRIPTSRC		= $(TOP)/src/common/lib/javascript

# DEST_FILES	= \
# 	signForm.js	\
# 	openca-menu.js  \
# 	tools.js	\
# 	general.js	\
# 	signForm.vbs

#---- variable settings above, rules below ----

.PHONY:	default install clean distclean

default::

$(DEST_HTDOCS_SCRIPTDIR):
		$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=755 DIR=$@

install::	$(LOCALES)

# $(DEST_FILES)::	$(DEST_HTDOCS_SCRIPTDIR)
# $(DEST_FILES)::
# 		@for i in $@ ; do \
# 			[ -f "$(SCRIPTSRC)/$@/$$i" ] && $(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $(SCRIPTSRC)/$@/$$i $(DEST_HTDOCS_SCRIPTDIR)/$@/$$i ; \
# 		done

$(LOCALES)::	$(DEST_HTDOCS_SCRIPTDIR)
		$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=711 DIR=$(DEST_HTDOCS_SCRIPTDIR)/$@
		@files=`cd "$(SCRIPTSRC)/$@" && ls *.js *.vbs` ; \
		 for i in $$files ; do \
			[ -f "$(SCRIPTSRC)/$@/$$i" ] && $(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $(SCRIPTSRC)/$@/$$i $(DEST_HTDOCS_SCRIPTDIR)/$@/$$i ; \
		done

clean::
distclean::
		#$(RM)
