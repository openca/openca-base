# file: src/web-interfaces/pub/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../..
include $(TOP)/Makefile.global-vars

DEST_CGIDIR	= $(pub_cgi_fs_prefix)

SUBDIRS	= \
	htdocs

COOKIE_DIR = $(var_prefix)/session/cookie/$(pub_prefix)

SERVER	= pki

PROGS	= \
	$(SERVER)

AC_PROGS = $(PROGS)

AC_FILES = \
	pub.conf \
	access_control.xml

CONF_FILE = \
	pub.conf

DEST_CGI_CONFDIR = ${etc_prefix}/servers

DOWNLOAD = download.cer

AC_CONF_SRC	= access_control.xml
AC_CONF		= $(etc_prefix)/access_control/$(pub_prefix).xml.template
AC_DIRS		= access_control servers

MENU_CONFDIR	= ${etc_prefix}
MENU_DIR	= menus
# MENU_FILE	= ${pub_prefix}-menu.xml
MENU_FILE	= pub-menu.xml

#---- variable settings above, rules below ----

.PHONY:	default install clean distclean

default::

$(DEST_CGIDIR):
		$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=755 DIR=$@

install::	$(PROGS) $(AC_CONF) $(CONF_FILE) $(COOKIE_DIR) $(DOWNLOAD) $(MENU_FILE)

$(MENU_DIR)::
	$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=755 DIR=$(etc_prefix)/$@

$(MENU_FILE):: $(MENU_DIR)
	@if [ -e "$(MENU_CONFDIR)/$(MENU_DIR)/$@.template" ]; then \
		mv "$(MENU_CONFDIR)/$(MENU_DIR)/$@.template" "$(MENU_CONFDIR)/$(MENU_DIR)/$@.template.bak" ; \
	fi ; \
	set -x; \
	$(INSTALL) -o ${openca_user} -g ${httpd_group} -m 640 $@ $(MENU_CONFDIR)/$(MENU_DIR)/$@.template

$(PROGS)::	$(DEST_CGIDIR)
$(PROGS)::
		$(INSTALL) -o ${openca_user} -g ${openca_group} -m 755 $@ $(DEST_CGIDIR)/$@

$(AC_CONF):: $(AC_DIRS)
	@if [ -e $@ ]; then \
		echo "$@ already exists, skipping configuration"; \
	else \
		set -x; \
		$(INSTALL) -o ${openca_user} -g ${httpd_group} -m 640 $(AC_CONF_SRC) $@; \
	fi

$(AC_DIRS)::
	$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=644 DIR=$(etc_prefix)/$@

$(CONF_FILE)::
	@if [ -e "$(DEST_CGI_CONFDIR)/$@.template" ]; then \
		echo "$@ exists, moving old file to $@.template.old"; \
		$(MV) "$(DEST_CGI_CONFDIR)/$@.template" \
				"$(DEST_CGI_CONFDIR)/$@.template.old" ; \
		$(INSTALL) -o ${openca_user} -g ${httpd_group} -m 640 $@ \
				"$(DEST_CGI_CONFDIR)/$@.template"; \
	else \
		set -x; \
		$(INSTALL) -o ${openca_user} -g ${httpd_group} -m 640 $@ \
			"$(DEST_CGI_CONFDIR)/$@.template"; \
	fi

$(COOKIE_DIR)::
	@if [ -e $@ ]; then \
		echo "$@ already exists, skipping configuration"; \
	else \
		set -x; \
		$(MAKE) __install_dir USER=${httpd_user} GROUP=${httpd_group} MODE=750 DIR=$@; \
	fi

$(DOWNLOAD)::	$(PROGS)
		@if [ -e $(DEST_CGIDIR)/$@ ]; then \
			echo "software update detected, removing old link"; \
			$(RM) $(DEST_CGIDIR)/$@; \
		fi
		$(MAKE) __install_ln_s TARGET=$(DEST_CGIDIR)/$(SERVER) LINK=$(DEST_CGIDIR)/$@

install clean::
	$(MAKE) $(SUBDIRS) SUBTARGET=$@

$(SUBDIRS)::
	cd $@ && $(MAKE) $(SUBTARGET)

distclean::
	@$(MAKE) $(SUBDIRS) SUBTARGET=$@
	@echo -n "Cleaning up pub web interface ... "
	@for i in $(AC_PROGS) $(AC_FILES); do \
		if test -e $$i ; then rm $$i ; fi \
		done
	@echo "Done."
