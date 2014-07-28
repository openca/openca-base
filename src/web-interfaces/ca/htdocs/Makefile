# file: src/web-interfaces/ca/htdocs/Makefile
#
# © 2001-2004 OpenCA Group

TOP	= ../../../..
include $(TOP)/Makefile.global-vars

DEST_HTDOCS_DIR	= $(ca_htdocs_fs_prefix)
DEST_CRYPTO_DIR = "$(var_prefix)/crypto"

DEST_LIB_STYLESHEET_DIR	= ${lib_prefix}/stylesheets
SRC_LIB_STYLESHEET_DIR	= $(TOP)/src/common/lib/stylesheets

SUBDIRS	= \
	images	\
	scripts

STATIC_FILES	= \
	index.html

STYLESHEETS	= \
	default.css \
	dynmenu-openca.css \
	openca-home-2.css \
	main-openca.css \
	menu-openca.css \

FILES		= $(STATIC_FILES)

EXTRA_DIRS	= \
	crl \
	cacert

CRL_LINKS 	= \
	crl.pem \
	crl.crl \
	crl.der \
	crl.txt

CACERT_LINKS	= \
	cacert.der \
	cacert.pem \
	cacert.cer \
	cacert.crt \
	cacert.txt

#---- variable settings above, rules below ----

.PHONY:	default install clean distclean

default::	$(SUBDIRS)

$(DEST_HTDOCS_DIR):
		$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=755 DIR=$@

install::	$(FILES) $(STYLESHEETS) $(EXTRA_DIRS) $(CRL_LINKS) $(CACERT_LINKS)

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

$(EXTRA_DIRS)::
	@if ! [ -d "$(DEST_HTDOCS_DIR)/$@" ] ; then \
		$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=755 DIR="$(DEST_HTDOCS_DIR)/$@" ; \
	fi

$(CRL_LINKS)::
	if ! [ -L "$(DEST_HTDOCS_DIR)/crl/$@" ] ; then \
		$(MAKE) __install_ln_s TARGET="$(DEST_CRYPTO_DIR)/crls/$@" LINK="$(DEST_HTDOCS_DIR)/crl/$@" ; \
	fi

$(CACERT_LINKS)::
	if ! [ -L "$(DEST_HTDOCS_DIR)/cacert/$@" ] ; then \
		$(MAKE) __install_ln_s TARGET="$(DEST_CRYPTO_DIR)/cacerts/$@" LINK="$(DEST_HTDOCS_DIR)/cacert/$@" ; \
	fi


distclean::
		#$(RM)

install clean distclean::
		$(MAKE) $(SUBDIRS) SUBTARGET=$@

$(SUBDIRS)::
		cd $@ && $(MAKE) $(SUBTARGET)
