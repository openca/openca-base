# file: src/web-interfaces/pub/htdocs/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../../..
include $(TOP)/Makefile.global-vars

DEST_HTDOCS_DIR	= $(pub_htdocs_fs_prefix)
DEST_LIB_STYLESHEET_DIR	= ${lib_prefix}/stylesheets
SRC_LIB_STYLESHEET_DIR	= $(TOP)/src/common/lib/stylesheets

SUBDIRS	= \
	cacert	\
	crl	\
	images	\
	scripts

STATIC_FILES	= \
	index.html

STYLESHEETS	= \
	default.css \
	dynmenu-openca.css \
	openca-home-2.css \
	main-openca.css \
	menu-openca.css

FILES		= $(STATIC_FILES)

#---- variable settings above, rules below ----

.PHONY:	default install clean distclean

default::	$(SUBDIRS)

$(DEST_HTDOCS_DIR):
		$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=755 DIR=$@

install::	$(FILES) $(STYLESHEETS)

$(FILES)::	$(DEST_HTDOCS_DIR)
$(FILES)::
		$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $@ $(DEST_HTDOCS_DIR)/$@.template

$(STYLESHEETS)::		$(DEST_HTDOCS_DIR)
$(STYLESHEETS)::
		@if [ -e $(DEST_HTDOCS_DIR)/$@ ]; then \
			echo "software update detected, removing old files"; \
	                $(RM) $(DEST_HTDOCS_DIR)/$@; \
		fi
		$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $(SRC_LIB_STYLESHEET_DIR)/$@ $(DEST_HTDOCS_DIR)


distclean::
		#$(RM)

install clean distclean::
		$(MAKE) $(SUBDIRS) SUBTARGET=$@

$(SUBDIRS)::
		cd $@ && $(MAKE) $(SUBTARGET)
