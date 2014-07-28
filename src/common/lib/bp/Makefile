# file: src/common/lib/bp/Makefile
#
# (c) Copyright 2004 The OpenCA Project. All rights reserved.

TOP	= ../../../..
include $(TOP)/Makefile.global-vars

DEST_CGI_BPDIR		= ${lib_prefix}/bp

# commands derived from .in files:
AC_SUBS	= \

# commands not derived from .in files:
STATIC_SUBS	= \
	backup_key.sub		\
	check_csr.sub		\
	check_csr_params.sub	\
	check_key.sub		\
	check_key_params.sub	\
	check_pin.sub		\
	complete_csr.sub	\
	create_cert.sub		\
	create_csr.sub		\
	create_key.sub		\
	create_pin.sub		\
	enroll_pkcs12.sub	\
	enroll_pin.sub

SUBS	= $(AC_SUBS) $(STATIC_SUBS)

#---- variable settings above, rules below ----

.PHONY:	default test install clean distclean

default::

test ::
	@PERL5OPT=""; \
	for file in `ls ../../../modules`; do \
		if [ -d ../../../modules/$$file ]; then \
			PERL5OPT="$$PERL5OPT -I../../../modules/$$file/blib/lib"; \
		fi; \
	done; \
	PERL5LIB=""; \
	for file in `ls ../../../modules`; do \
		if [ -d ../../../modules/$$file ]; then \
			PERL5LIB="$$PERL5LIB:../../../modules/$$file/blib/arch"; \
		fi; \
	done; \
	export PERL5OPT=$$PERL5OPT; \
	export PERL5LIB=$$PERL5LIB; \
	for sub in $(SUBS); do \
		$(PERL) -c $$PERL5OPT $$sub; \
	done;

$(DEST_CGI_BPDIR):
		$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=755 DIR=$@

install::	$(SUBS)

$(SUBS)::		$(DEST_CGI_BPDIR)
$(SUBS)::
		$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $@ $(DEST_CGI_BPDIR)/$@

clean::
distclean::
		@if ! [ -z $(AC_SUBS) ] ; then \
			$(RM) $(AC_SUBS) ; \
		 fi
