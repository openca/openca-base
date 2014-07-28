#file: src/modules/Makefile
#
# © 2001 OpenCA Group

TOP	= ../..
include $(TOP)/Makefile.global-vars

MODULES.pm.3rd-party	= \
	Authen-SASL-2.15	\
	Convert-ASN1-0.22 \
	CGI-Session-4.48	\
	Bit-Vector-7.3		\
	MIME-Base64-3.14	\
	DB_File-1.830			\
	DBI-1.628					\
	DBD-mysql-4.023		\
	DBD-Pg-2.19.2			\
	Digest-SHA-5.71		\
	Digest-HMAC-1.03	\
	Digest-SHA1-2.13	\
	Digest-MD5-2.51 	\
	libintl-perl-1.20	\
	Net-SSLeay-1.40		\
	IO-Socket-SSL-1.31	\
	IO-stringy-2.110	\
	File-Temp-0.22		\
	MIME-tools-5.502	\
	MailTools-2.09		\
	MIME-Lite-3.027		\
	Net-Server-2.007	\
	URI-1.52					\
	XML-Parser-2.41		\
	Parse-RecDescent-1.94   \
	X500-DN-0.29			\
	XML-SAX-Base-1.08	\
	perl-ldap-0.43		\
	FCGI-0.74					\
	CGI.pm-3.59				\
	XML-Twig-3.39-1

MODULES	= \
	$(MODULES.pm.3rd-party)

EXTRA_OPTS=

#---- variable settings above, rules below ----

# .PHONY:	modules test install install-common install-scep clean distclean
.PHONY:	modules test install install-common clean distclean

default: modules

#		PERL5OPT="$$PERL5OPT -I$$PWD/$$i/blib/lib"; \

modules::
	@PWD=`pwd`
	@echo ; \
	echo "Build::External PERL modules" ; \
	echo ; \
	for mod in $(MODULES.pm.3rd-party) ; do \
		$(MAKE) $$mod PERLREQ="$$PERLREQ" \
			PERL5OPT="$$PERL5OPT" PERL5LIB="$$PERL5LIB" ; \
		if [ $$? -gt 0 ] ; then \
			exit 1; \
		fi; \
	done ; \
	echo

#	@for i in $(MODULES.pm.3rd-party) ; do \
#		PERLREQ="$$PERLREQ -I$$PWD/$$i/blib/lib" ; \
#		PERL5LIB="$$PERL5LIB:$$PWD/$$i/blib/arch"; \
#	done ; \
#	export PERL5OPT=$$PERL5OPT; \
#	export PERL5LIB=$$PERL5LIB; \

# @echo "BUILD OS => $(DIST_NAME) - $(DIST_VERSION) ::=> $@ [DESTDIR = $(DEST_DIR)]" ; \
#	echo "$$name $$ver (installed $$installed)" ; \
# installed=`$(SHELL) $(TOP)/src/scripts/modver $$o` ;

$(MODULES.pm.3rd-party)::
	@o=`echo $@ | sed -e "s|-[0-9].*||g" | sed "s|-|::|g"` ; \
	name=`echo $@ | sed -e "s|-[0-9].*||g"` ; \
	ver=`echo $@000 | sed -e "s|$$name-||" | sed "s|\.||g" | cut -c 1-3` ; \
	installed=`perl -M$mod -e "print ( \$$mod::VERSION =~ /(\d)\.(\d\d)/ )" 2>/dev/null || echo "000"` ; \
	if ! [ -z `echo $@ | grep -i "mysql"` ] ; then \
		if [ -z "$(enable_mysql)" ] ; then \
			echo "MySQL is DISABLED" ; \
			exit 0; \
		fi; \
	fi; \
	if ! [ -z `echo $@ | grep -i "pg"` ] ; then \
		if [ -z "$(enable_pg)" ] ; then \
			echo "PostgeSQL is DISABLED" ; \
			exit 0; \
		fi; \
	fi; \
	if ! [ -e "$@.tar.gz" ] ; then \
		echo "ERROR::Missing Module $@.tar.gz!" ; \
		exit 1; \
	fi ; \
	if [ "x$@" = "xXML-Parser-2.41" ] ; then \
		if [ "x$(DIST_NAME)" = "xUbuntu" ] ; then \
			exit 0; \
		fi ; \
		if [ $$installed -gt 000 ] ; then \
			exit 0; \
		fi ; \
	fi; \
	if [ "x$@" = "xDB_File-1.826" ] ; then \
		if [ "x$(DIST_NAME)" = "xUbuntu" ] ; then \
			exit 0; \
		fi ; \
	fi; \
	if [ 0 = 1 ] ; then \
		echo "Building ($$o::$$ver) ... already installed ($$installed), skipping." ; \
		exit 0 ; \
	else \
		echo -n "Building ($$o::$$ver) ... " ; \
	fi ; \
	$(GZIP) -d -c $@.tar.gz | $(TAR) Bxvf - 2>/dev/null > /dev/null ; \
	EXTRAOPTS="" ; \
	SSLOPTS="" ; \
	SSL_PREFIX=""; \
	if [ "$@" = "perl-ldap-0.43" ] ; then \
		EXTRAOPTS=" --skip "; \
	fi; \
	if [ "$@" = "MIME-tools-5.502" ] ; then \
		EXTRAOPTS=" --skip "; \
	fi; \
	if [ "$@" = "MIME-Lite-3.027" ] ; then \
		SSLOPTS=" -n "; \
	fi; \
	if [ "$@" = "XML-Twig-3.39" ] ; then \
		SSLOPTS=" -n "; \
	fi ; \
	if [ -z "$(OPENSSL_PREFIX)" ] ; then \
		SSL_PREFIX=`type -path openssl | sed -e "s|/openssl||" | sed -e "s|/bin||" ` ; \
	else \
		SSL_PREFIX="$(OPENSSL_PREFIX)" ; \
	fi ; \
	if [ -d "$@" ]; then \
		cd $@ && CC="$(CC)" CPP="$(CPP)" \
			OPENSSL_PREFIX="$$SSL_PREFIX" \
			PERLREQ="$(PERLREQ)" PERL5LIB="$(PERL5LIB)" \
			PERL_MM_USE_DEFAULT=1 $(PERL) Makefile.PL $$SSLOPTS \
				$(PERL_MAKEFILE_OPTS) $$EXTRAOPTS \
				CC="$(CC)" 2>log.err \
					 >log; \
		$(MAKE) 2>/dev/null >/dev/null; \
		if [ $$? -gt 0 ] ; then \
			echo "ERROR::Can not build module" ; \
			exit 1; \
		else \
			echo "Ok." ; \
		fi ; \
	fi


## LC_ALL=de_AT is a hack to compensate a bug in the testscript of libintl-perl
## it must me exported after the export of PERL5OPT
## export LC_ALL=de_AT; \

# common for both CA and external server:
install-common:	install

install::
	@echo ; \
	echo "Install::External PERL modules" ; \
	echo
	@for i in $(MODULES.pm.3rd-party) ; do \
		o=`echo $$i | sed -e "s|-[0-9].*||g" | sed "s|-|::|g"` ; \
		if [ -d "$$i" ] ; then \
			echo -n "Installing ($$o) ... " ; \
			( cd "$$i" && $(MAKE) install 2>log.err >log ); \
			echo "Ok." ; \
		fi ; \
	done ; \
	echo

test::
	@echo ; \
	echo "Install::External PERL modules" ; \
	echo
	@for i in $(MODULES.pm.3rd-party) ; do \
		o=`echo $$i | sed -e "s|-[0-9].*||g" | sed "s|-|::|g"` ; \
		if [ -d "$$i" ] ; then \
			echo -n "Testing ($$o) ... " ; \
			( cd "$$i" && $(MAKE) tests 2>log.err >log ); \
			echo "Ok." ; \
		fi ; \
	done ; \
	echo

clean distclean::	clean.local

clean.local::
	@echo -n "Cleaning up 3rd Party Modules ... "
	@$(RM) -rf $(MODULES.pm.3rd-party)
	@echo "Done."



