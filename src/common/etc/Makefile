# file: src/common/etc/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../..
include $(TOP)/Makefile.global-vars

SUBDIRS	= \
	bp		\
	database	\
	openssl		\
	agreements	\
	includes	\
	rbac

ETC_DIRS = \
	access_control/		\
	bp/			\
	database/		\
	openssl/		\
	openssl/openssl/	\
	openssl/extfiles/	\
	rbac/			\
	rbac/cmds/		\
	scep/			\
	agreements/		\
	servers/		\
	contrib/		\
	includes/		\
	contrib/apache		\
	contrib/openldap

STATIC_FILES	= 

AC_FILES	= \
	config.xml			\
	log.xml				\
	token.xml			\
	loa.xml				\
	utf8_latin1_selector.sh.template \
	configure_etc.sh 		\
	openca_start.template 		\
	openca_stop.template

INIT_FILE = openca

INIT_DIR	= \
	$(init_dir)
	
TEMPLATE_FILES = \
	backup.xml.template		\
	browser_req.xml.template	\
	auth_browser_req.xml.template	\
	server_req.xml.template	\
	datasources.xml.template	\
	ldap.xml.template \
	common.conf.template

APACHE_FILES = \
	offline.conf 			\
	online.conf			\
	common.conf

OPENLDAP_FILES = \
	openca.schema \
	slapd.conf
	

FILES = $(STATIC_FILES) $(AC_FILES) $(TEMPLATE_FILES) 

PROGS	= \
	configure_etc.sh	\
	openca_start.template	\
	openca_stop.template	\
	utf8_latin1_selector.sh.template

#---- variable settings above, rules below ----

.PHONY:	default test install install-conf clean distclean

default::	openssl

test::

install::	$(etc_prefix)

install-conf:: $(ETC_DIRS) 

install-conf::	$(FILES) $(PROGS) $(INIT_FILE) $(APACHE_FILES) $(OPENLDAP_FILES)

install-conf::
		$(MAKE) $(SUBDIRS) SUBTARGET=install

$(etc_prefix)::
	set -x ; \
	MODE=755 $(MAKE) __install_dir USER=${httpd_user} GROUP=${httpd_group} DIR=$@; \
	$(MAKE) install-conf; \

$(ETC_DIRS)::
	$(MAKE) __install_dir USER=${httpd_user} GROUP=${httpd_group} DIR=$(etc_prefix)/$@

$(SUBDIRS)::
		cd $@ && $(MAKE) $(SUBTARGET)

$(INIT_FILE): $(INIT_DIR) $(INIT_DIR)/$(INIT_FILE)

#	if [ -d "/etc/init.d" ] ; then \
#		if [ -h "/etc/init.d/$(INIT_FILE)" ] ; then \
#			$(MV) -f "/etc/init.d/$(INIT_FILE)" \
#					"/etc/init.d/$(INIT_FILE).backup" ; \
#		fi ; \
#		$(LN_S) "$(INIT_DIR)/$(INIT_FILE)" "/etc/init.d/$(INIT_FILE)";\
#	fi


$(INIT_DIR)/$(INIT_FILE)::
	$(INSTALL) -o ${openca_user} -g ${openca_group} -m 755 \
				"$(INIT_FILE)" "$(INIT_DIR)/$(INIT_FILE)"
	
$(INIT_DIR)::
	MODE=755 $(MAKE) __install_dir USER=${httpd_user} GROUP=${httpd_group} DIR="$@"

$(FILES)::
	$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $@ $(etc_prefix)/$@

$(APACHE_FILES)::
	$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 ../../../contrib/apache/$@ $(etc_prefix)/contrib/apache/$@

$(OPENLDAP_FILES)::
	$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 ../../../contrib/openldap/$@ $(etc_prefix)/contrib/openldap/$@

$(PROGS)::
	$(INSTALL) -o ${openca_user} -g ${openca_group} -m 755 $@ $(etc_prefix)/$@

clean::
distclean::
	$(MAKE) $(SUBDIRS) SUBTARGET=$@
	@for i in $(AC_FILES) $(INIT_FILES); do \
		if test -e $$i ; then $(RM) "$$i" ; fi ;\
	done

