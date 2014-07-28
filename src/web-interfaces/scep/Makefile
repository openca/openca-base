# file: src/web-interfaces/scep/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../..
include $(TOP)/Makefile.global-vars

DEST_CGIDIR	= $(scep_cgi_fs_prefix)

COOKIE_DIR = $(var_prefix)/session/cookie/$(scep_prefix)

PROGS	= scep

AC_PROGS = $(PROGS)

AC_FILES = \
	scep.conf \
	access_control.xml

SCEPLINKS = pkiclient.exe

AC_CONF_SRC	= access_control.xml
AC_CONF		= $(etc_prefix)/access_control/$(scep_prefix).xml.template
AC_DIRS		= access_control servers

CONF_FILE	=	scep.conf
DEST_CGI_CONFDIR = $(etc_prefix)/servers

#---- variable settings above, rules below ----

.PHONY:	default install clean distclean

default::

$(DEST_CGIDIR):
		$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=755 DIR=$@

install::	$(PROGS) $(AC_CONF) $(COOKIE_DIR) $(CONF_FILE) $(SCEPLINKS)

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
		$(INSTALL) -o ${openca_user} -g ${httpd_group} -m 640 $@ $(DEST_CGI_CONFDIR)/${scep_prefix}.conf.template; \
	fi

$(COOKIE_DIR)::
	@if [ -e $@ ]; then \
		echo "$@ already exists, skipping configuration"; \
	else \
		set -x; \
		$(MAKE) __install_dir USER=${httpd_user} GROUP=${httpd_group} MODE=750 DIR=$@; \
	fi

$(SCEPLINKS)::
		@if [ -e $(DEST_CGIDIR)/$@ ]; then \
			echo "software update detected, removing old link"; \
			$(RM) $(DEST_CGIDIR)/$@; \
		fi
		$(MAKE) __install_ln_s TARGET=$(DEST_CGIDIR)/$(PROGS) LINK=$(DEST_CGIDIR)/$@

clean::

distclean::
	@echo -n "Cleaning up scep web interface ... "
	@for i in $(AC_PROGS) $(AC_FILES); do \
		if test -e $$i ; then rm $$i ; fi \
		done
	@echo "Done."
