# file: src/common/etc/openssl/extfiles/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../../../..
include $(TOP)/Makefile.global-vars

DEST_CONFOPENSSLEXTFILESDIR	= ${etc_prefix}/openssl/extfiles

AC_FILES	= \
	CA_Operator.ext		\
	Self_Signed_CA.ext	\
	Cross_CA.ext		\
	PRQP_Server.ext		\
	Domain_Controller.ext	\
	Mail_Server.ext		\
	RA_Operator.ext		\
	Sub-CA.ext		\
	User.ext		\
	VPN_Server.ext		\
	OCSP_Server.ext		\
	Web_Server.ext

#---- variable settings above, rules below ----

.PHONY:	default install clean distclean

default::

install::	$(AC_FILES)

$(AC_FILES)::
	$(INSTALL) -g ${httpd_group} -o ${httpd_user} -m 644 $@.in $(DEST_CONFOPENSSLEXTFILESDIR)/$@.template

distclean::
	@for i in $(AC_FILES) ; do \
		if test -f $$i ; then $(RM) $$i ; fi \
	done

	# $(RM) $(AC_FILES)

