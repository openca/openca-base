# file: src/common/var/crypto/Makefile
#
# © 2002 OpenCA Group

TOP	= ../../../..
include $(TOP)/Makefile.global-vars

DEST_VAROPENSSLDIR	= ${var_prefix}/crypto

DIRS = \
	crypto

SUBDIRS = \
	crypto/cacerts	\
	crypto/certs	\
	crypto/chain	\
	crypto/crls	\
	crypto/keys	\
	crypto/reqs

DEST_VAR_CRYPTO_CACERTDIR	= ${var_prefix}/crypto/cacerts
DEST_VAR_CRYPTO_KEYDIR		= ${var_prefix}/crypto/keys

# files not generated from .in files and used by openssl in rw-mode:
OPENSSL_CONFOPENSSLFILES	= \
	index.txt		\
	index.txt.attr		\
	crlnumber		\
	serial

MAKECHAIN	= \
	Makefile.crt

EXTRA_KEYS	= \
	bp_key.pem		\
	keybackup_key.pem	\
	log_key.pem

EXTRA_CERTS	= \
	bp_cert.pem		\
	keybackup_cert.pem	\
	log_cert.pem

CACERT_CER_LINK = cacert.cer
CACERT_CRT_LINK	= cacert.crt

CACERT_LINKS = \
	$(CACERT_CER_LINK)	\
	$(CACERT_CRT_LINK)

#---- variable settings above, rules below ----

.PHONY:	default test install clean distclean

default::

test::

install::	$(OPENSSL_CONFOPENSSLFILES) $(MAKECHAIN) $(EXTRA_KEYS) $(EXTRA_CERTS) $(CACERT_LINKS)

$(OPENSSL_CONFOPENSSLFILES):: $(DIRS)
	@if [ -e $(DEST_VAROPENSSLDIR)/$@ ]; then \
		echo "$@ already exists, skipping"; \
	else \
		set -x; \
		$(INSTALL) -g ${httpd_group} -o ${httpd_user} -m 640 $@ $(DEST_VAROPENSSLDIR)/$@; \
	fi

$(MAKECHAIN)::	$(SUBDIRS)
	$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 Makefile.crt ${var_prefix}/crypto/chain/Makefile

$(EXTRA_KEYS)::	$(SUBDIRS)
	@if [ -h "$(DEST_VAR_CRYPTO_KEYDIR)/$@" ] || [ -e "$(DEST_VAR_CRYPTO_KEYDIR)/$@" ]; then \
		echo "$@ already exists, skipping"; \
	else \
		set -x; \
		$(MAKE) __install_ln_s TARGET=$(DEST_VAR_CRYPTO_KEYDIR)/cakey.pem LINK=$(DEST_VAR_CRYPTO_KEYDIR)/$@; \
	fi

$(EXTRA_CERTS) $(CACERT_CRT_LINK)::
	@if [ -h $(DEST_VAR_CRYPTO_CACERTDIR)/$@ ] || [ -e $(DEST_VAR_CRYPTO_CACERTDIR)/$@ ]; then \
		echo "$@ already exists, skipping"; \
	else \
		set -x; \
		$(MAKE) __install_ln_s TARGET=$(DEST_VAR_CRYPTO_CACERTDIR)/cacert.pem LINK=$(DEST_VAR_CRYPTO_CACERTDIR)/$@; \
	fi

$(CACERT_CER_LINK)::
	@if [ -h $(DEST_VAR_CRYPTO_CACERTDIR)/$@ ] || [ -e $(DEST_VAR_CRYPTO_CACERTDIR)/$@ ]; then \
		echo "$@ already exists, skipping"; \
	else \
		set -x; \
		$(MAKE) __install_ln_s TARGET=$(DEST_VAR_CRYPTO_CACERTDIR)/cacert.der LINK=$(DEST_VAR_CRYPTO_CACERTDIR)/$@; \
	fi

$(SUBDIRS):: $(DIRS)
	$(MAKE) __install_dir USER=${httpd_user} GROUP=${httpd_group} MODE=750 DIR=$(var_prefix)/$@

$(DIRS)::
	$(MAKE) __install_dir USER=${httpd_user} GROUP=${httpd_group} MODE=750 DIR=$(var_prefix)/$@

clean::
distclean::
	$(RM) -f Makefile.crt

