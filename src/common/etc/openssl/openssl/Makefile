# file: src/common/etc/openssl/openssl/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../../../..
include $(TOP)/Makefile.global-vars

DEST_CONFOPENSSLOPENSSLDIR	= ${etc_prefix}/openssl/openssl

AC_FILES	= \
	CA_Operator.conf	\
	Cross_CA.conf		\
	Domain_Controller.conf	\
	Mail_Server.conf	\
	RA_Operator.conf	\
	Sub-CA.conf		\
	User.conf		\
	VPN_User.conf		\
	VPN_Server.conf		\
	PRQP_Server.conf	\
	OCSP_Server.conf	\
	Web_Server.conf

#---- variable settings above, rules below ----

.PHONY:	default install clean distclean

default::

install::	$(AC_FILES)

$(AC_FILES)::
	$(INSTALL) -g ${httpd_group} -o ${httpd_user} -m 644 $@ $(DEST_CONFOPENSSLOPENSSLDIR)/$@.template

distclean::
		for i in $(AC_FILES) ; do \
			if test -e $$i ; then $(RM) "$$i" ; fi ;\
		done

		# $(RM) $(AC_FILES)
