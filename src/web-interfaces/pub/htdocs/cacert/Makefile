# file: src/web-interfaces/pub/htdocs/cacert/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../../../..
include $(TOP)/Makefile.global-vars

DEST_HTDOCS_DIR	= ${pub_htdocs_fs_prefix}/cacert
DEST_CACERT_DIR	= ${var_prefix}/crypto/cacerts

LINKS	=\
	cacert.cer	\
	cacert.crt	\
	cacert.der	\
	cacert.pem	\
	cacert.txt

#---- variable settings above, rules below ----

.PHONY:	default install clean distclean

default::

$(DEST_HTDOCS_DIR):
		$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=755 DIR=$@

install::	$(LINKS)

$(LINKS)::	$(DEST_HTDOCS_DIR)
$(LINKS)::
		@if [ -h "$(DEST_HTDOCS_DIR)/$@" ]; then \
			echo "software update detected, removing old link"; \
			$(RM) "$(DEST_HTDOCS_DIR)/$@"; \
		fi
		$(MAKE) __install_ln_s TARGET="$(DEST_CACERT_DIR)/$@" LINK="$(DEST_HTDOCS_DIR)/$@"

clean::
distclean::
		#$(RM)
