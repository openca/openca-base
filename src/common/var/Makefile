# file: src/common/var/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../..
include $(TOP)/Makefile.global-vars

DEST_VAR_DIR = $(var_prefix)

SUBDIRS	= \
	crypto	\
	mail

VAR_DIRS = \
	bp			\
	bp/dataexchange		\
	bp/dataexchange/pkcs12	\
	bp/users		\
	db			\
	log			\
	log/enroll		\
	log/download		\
	log/receive		\
	log/upload		\
	log/xml			\
	log/xml/class		\
	log/xml/level		\
	log/xml/session		\
	log/xml/time		\
	session			\
	session/cookie		\
	tmp

HTTPD_FILES = \
	log/xml_cache.log

#---- variable settings above, rules below ----

.PHONY:	default test install clean clean.local distclean

default::	$(SUBDIRS)

install::	$(VAR_DIRS) $(HTTPD_FILES)

$(VAR_DIRS):
		$(MAKE) __install_dir USER=${httpd_user} GROUP=${httpd_group} MODE=750 DIR=$(DEST_VAR_DIR)/$@

$(HTTPD_FILES):	$(VAR_DIRS)
	## this is permission handling only
	@if [ -e $(DEST_VAR_DIR)/$@ ]; then \
		echo "$(DEST_VAR_DIR)/$@ already exists, skipping"; \
	else \
		set -x; \
		touch empty.txt; \
		$(INSTALL) -o ${httpd_user} -g ${httpd_group} -m 644 empty.txt $(DEST_VAR_DIR)/$@; \
	fi

$(SUBDIRS)::
		cd $@ && $(MAKE) $(SUBTARGET)

test install clean distclean::
		$(MAKE) $(SUBDIRS) SUBTARGET=$@

distclean::
		#$(RM)
