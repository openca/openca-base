# file: src/common/lib/functions/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../../..
include $(TOP)/Makefile.global-vars

DEST_CGI_LIBDIR	= ${lib_prefix}/functions

LIBS	= \
	crypto-utils.lib	\
	export-import.lib	\
	initCGI			\
	initDB			\
	initDBI			\
	initLDAP		\
	initRBAC		\
	initServer		\
	ldap-utils.lib		\
	log-utils.lib		\
	mail-utils.lib		\
	misc-utils.lib		\
	request-utils.lib	\
	datasource-utils.lib	\
	daemon-utils.lib \
	rbac-utils.lib

#---- variable settings above, rules below ----

.PHONY:	default test install clean distclean

default::

test::
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
	for lib in $(LIBS); do \
		$(PERL) -c $$PERL5OPT $$lib; \
	done;

# common for both CA and external server:

$(DEST_CGI_LIBDIR):
		$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=755 DIR=$@

install::	$(LIBS)

$(LIBS)::	$(DEST_CGI_LIBDIR)
$(LIBS)::
		$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $@ $(DEST_CGI_LIBDIR)/$@

clean::
distclean::
		#$(RM)
