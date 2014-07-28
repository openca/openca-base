# file: src/modules/Makefile
#
# © 2001 OpenCA Group

TOP	= ../..
include $(TOP)/Makefile.global-vars

MODULES.pm.openca	= \
	openca-ac		\
	openca-configuration	\
	openca-crl		\
	openca-crypto		\
	openca-dbi		\
	openca-ldap		\
	openca-log		\
	openca-openssl		\
	openca-pkcs7		\
	openca-req		\
	openca-session		\
	openca-statemachine	\
	openca-tools		\
	openca-tristatecgi	\
	openca-ui-html		\
	openca-x509		\
	openca-xml-cache 	\
	openca-user

MODULES	= \
	$(MODULES.pm.openca)

MODULE	= dummy

#---- variable settings above, rules below ----

# .PHONY:	modules test install install-common install-scep clean distclean
.PHONY:	modules test install install-common clean distclean

default: modules

modules::
	@echo ; \
	echo "Build::External PERL modules" ; \
	echo ; \
	$(MAKE) $(MODULES); \
	echo

$(MODULES)::
	@o=`echo $@ | sed -e "s|-[0-9].*||g" | sed "s|-|::|g"` ; \
	if [ -d "$@" ]; then \
		if [ -z "$(OPENSSL_PREFIX)" ] ; then \
			SSL_PREFIX=`type -path openssl | sed -e "s|/openssl||" | sed -e "s|/bin||" ` ; \
		else \
			SSL_PREFIX="$(OPENSSL_PREFIX)" ; \
		fi ; \
		echo -n "Building ($$o) ... " ; \
		cd $@ && CC="$(CC)" CPP="$(CPP)" LD="$(LD)" \
			OPENSSL_PREFIX="$$SSL_PREFIX" \
			PERLREQ="$(PERLREQ)" PERL5LIB="$(PERL5LIB)" \
			PERL_MM_USE_DEFAULT=1 $(PERL) Makefile.PL $$SSLOPTS \
				$(PERL_MAKEFILE_OPTS) $$EXTRAOPTS \
				 2>log.err >log; \
		$(MAKE) 2>/dev/null >/dev/null; \
		if [ $$? -gt 0 ] ; then \
			echo "ERROR::Can not build module" ; \
			exit 1; \
		else \
			echo "Ok." ; \
		fi ; \
	fi


# common for both CA and external server:
install-common:	install

test install::
	@echo ; \
	echo "Install::OpenCA PERL modules" ; \
	echo
	@for i in $(MODULES) ; do \
		o=`echo $$i | sed -e "s|-[0-9].*||g" | sed "s|-|::|g"` ; \
		if [ -d "$$i" ] ; then \
			echo -n "Installing ($$o) ... " ; \
			( cd "$$i" && $(MAKE) install 2>/dev/null >/dev/null); \
			echo "Ok." ; \
		fi ; \
	done ; \
	echo

clean.local:	clean

clean distclean:
	@echo ; \
	echo "Cleaning::OpenCA PERL modules" ; \
	echo
	@for module in $(MODULES.pm.openca); do \
		o=`echo $$module | sed -e "s|-[0-9].*||g" | sed "s|-|::|g"` ; \
		echo -n "Cleaning ($$o) ... " ; \
		if [ -e $$module/Makefile ]; then \
			cd $$module; make clean 2>/dev/null >log; \
			rm -f Makefile; \
			cd ..; \
		fi; \
		if [ -d $$module ] ; then \
			if [ -d $$module/tmp ] ; then \
				cd $$module; rm -rf tmp; \
				cd ..; \
			fi ; \
		fi ; \
		echo "Ok"; \
	done ; \
	echo

