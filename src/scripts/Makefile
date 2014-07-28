# file: src/scripts/Makefile
#
# © 2001 OpenCA Group

TOP	= ../..
include $(TOP)/Makefile.global-vars

# scripts derived from .in files:
AC_SCRIPTS	= \
	openca-addcert		\
	openca-backup		\
	openca-configure	\
	openca-dblist		\
	openca-digest		\
	openca-importcerts	\
	openca-browserexp	\
	openca-dbview		\
	openca-importreqs	\
	openca-dbbuild		\
	openca-getcert		\
	openca-newcert		\
	openca-dbcreate		\
	openca-getitem		\
	openca-unrevoke         \
	openca-addreq		\
	openca-setpasswd	\
	openca-menu-translate	\
	modver			\
        openssl-setopt          

SCRIPTS		= $(AC_SCRIPTS)

#---- variable settings above, rules below ----

.PHONY:	default test install install-ca install-common install-ldap install-node install-pub install-ra clean distclean

default::

test::

# here is nothing to do
install-ca:
install-ra:
install-ldap:
install-pub:
install-scep:

install-common:
install-node:
install:: $(DEST_BINDIR)
	@for i in $(SCRIPTS) ; do \
		echo "* $$i .." ; \
		echo "$(INSTALL) -o ${openca_user} -g ${openca_group} -m 755 $$i $(DEST_BINDIR)/$$i" ; \
		$(INSTALL) -o ${openca_user} -g ${openca_group} -m 755 $$i $(DEST_BINDIR)/$$i ; \
	done

$(SCRIPTS)::	$(DEST_BINDIR)
		$(INSTALL) -o ${openca_user} -g ${openca_group} -m 755 $@ $(DEST_BINDIR)/$@

$(DEST_BINDIR)::
	$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=755 DIR=$@

clean::

distclean::
	for i in $(AC_SCRIPTS) ; do \
		if test -e $$i ; then $(RM) "$$i" ; fi ;\
	done

	#$(RM) $(AC_SCRIPTS)
