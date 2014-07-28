# file: src/common/lib/functions/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../../..
include $(TOP)/Makefile.global-vars

DEST_MAIL_DIR	= ${lib_prefix}/mails
MAILSRC			= $(TOP)/src/common/lib/mails

MAILS	= \
	certsMail.msg		\
	verifyMail.msg		\
	confirm_cert_sign.msg	\
	expiringMail.msg	\
	request_pin_mail.msg	\
	secure_pin_mail.msg

#---- variable settings above, rules below ----

.PHONY:	default test install clean distclean

default::

test::

$(DEST_MAIL_DIR)::
		$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=755 DIR=$@

install::	$(LOCALES)

$(LOCALES):: $(DEST_MAIL_DIR)
		@$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=711 DIR=$(DEST_MAIL_DIR)/$@ ; \
		$(MAKE) $(MAILS) LANG=$@

$(MAILS)::	$(DEST_MAIL_DIR)
		$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $(MAILSRC)/$(LANG)/$@ $(DEST_MAIL_DIR)/$(LANG)/$@.template

clean::
distclean::
		#$(RM)
