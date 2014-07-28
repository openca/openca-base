# file: src/cgi-bin/Makefile
#
# © 2001 OpenCA Group

TOP	= ../..
include $(TOP)/Makefile.global-vars

BATCH_SUBDIRS	= \
	batch

CA_SUBDIRS	= \
	ca

LDAP_SUBDIRS	= \
	ldap

NODE_SUBDIRS	= \
	node

PUB_SUBDIRS	= \
	pub

RA_SUBDIRS	= \
	ra

SCEP_SUBDIRS	= \
	scep

SUBDIRS	= \
	$(BATCH_SUBDIRS)	\
	$(CA_SUBDIRS)		\
	$(LDAP_SUBDIRS)		\
	$(NODE_SUBDIRS)		\
	$(PUB_SUBDIRS)		\
	$(RA_SUBDIRS)		\
	$(SCEP_SUBDIRS)

#---- variable settings above, rules below ----

.PHONY:	default test install-batch install-ca install-ldap install-node install-pub install-ra clean distclean

default::
		$(MAKE) $(SUBDIRS)

test::

clean distclean::
		$(MAKE) $(SUBDIRS) SUBTARGET=$@

install-common::
		$(MAKE) $(COMMON_SUBDIRS) SUBTARGET=install

install-batch::
		$(MAKE) $(BATCH_SUBDIRS) SUBTARGET=install

install-ca::
		$(MAKE) $(CA_SUBDIRS) SUBTARGET=install

install-ldap::
		$(MAKE) $(LDAP_SUBDIRS) SUBTARGET=install

install-node::
		$(MAKE) $(NODE_SUBDIRS) SUBTARGET=install

install-pub::
		$(MAKE) $(PUB_SUBDIRS) SUBTARGET=install

install-ra::
		$(MAKE) $(RA_SUBDIRS) SUBTARGET=install

install-scep::
		$(MAKE) $(SCEP_SUBDIRS) SUBTARGET=install

$(SUBDIRS)::
		cd $@ && $(MAKE) $(SUBTARGET)

