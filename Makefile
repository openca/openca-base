# file: src/Makefile
#
# © 2001-2004 OpenCA Group
# $Revision: 1.12 $

TOP	= .
include $(TOP)/Makefile.global-vars

SNAP	= SNAP-$(TODAY)
VER	= $(VERSION)
C_DIR	= `$(ECHO) "$(PWD)" | $(SED) "s|/.*/||g"`
G_DIR   = `$(ECHO) "$(PWD)"`

SUBDIRS	= \
	src \
	docs

#---- variable settings above, rules below ----

.PHONY:	default info help ca ext test install-ca install-common install-ext install-ldap install-node install-offline install-pub install-ra install-doc clean clean.local distclean install-modules

default::	$(SUBDIRS)

info help::
		@$(ECHO) "Targets:"
		@$(ECHO) ""
		@$(ECHO) "  []                make everything"
		@$(ECHO) "  [ca]              make everything CA server related"
		@$(ECHO) "  [ext]             make everything RA and public server related"
		@$(ECHO) "  [doc]             make everything documentation related"
		@$(ECHO) ""
		@$(ECHO) "Install Target:"
		@$(ECHO) ""
		@$(ECHO) "  [install-mini] install minimun required components (common, modules, ca, ra, pub)"
		@$(ECHO) "  [install-offline] install all offline components (common, modules, ca, batch and node)"
		@$(ECHO) "  [install-online]  install all online components (common, modules, ra, pub, ldap and node)"
		@$(ECHO) "  [install-ext]     install RA and public server components"
		@$(ECHO) ""
		@$(ECHO) "Install Target:"
		@$(ECHO) ""
		@$(ECHO) "  [install-batch]   install batch system components"
		@$(ECHO) "  [install-ca]      install CA components"
		@$(ECHO) "  [install-common]  install all common components (for package builds)"
		@$(ECHO) "  [install-modules] install all perl modules (for package builds)"
		@$(ECHO) "  [install-ldap]    install LDAP components"
		@$(ECHO) "  [install-node]    install aministration components"
		@$(ECHO) "  [install-pub]     install public server components"
		@$(ECHO) "  [install-ra]      install RA server components"
		@$(ECHO) "  [install-scep]    install scep server components"
		@$(ECHO) "  [install-doc]     install documentation"
		@$(ECHO) "  [clean]           remove everything created by make"
		@$(ECHO) "  [distclean]       like clean, plus remove everything created by ./configure"
		@$(ECHO) ""
		@$(ECHO) "Development:"
		@$(ECHO) ""
		@$(ECHO) "  [dist]            build distribution package"
		@$(ECHO) "  [rpm]             build rpm"
		@$(ECHO) ""

ca ext::	default

doc::
		$(MAKE) docs SUBTARGET=

install-doc::
		$(MAKE) docs SUBTARGET=install

install-mini:: install-common install-ca install-ra install-pub

install-offline::	install-common install-batch install-ca install-node

install-online::	install-common install-ra install-pub install-ldap install-node install-scep

# install-ext::		install-online
# 
# install-batch::		install-common
# 
# install-ca::		install-common
# 
# install-node::		install-common
# 
# install-pub::		install-common
# 
# install-ra::		install-common
# 
# install-ldap::		install-common
# 
# install-scep::		install-common
# 
# install-modules::	install-common

# test install-ca install-ext clean distclean install-scep::
test install-batch install-ca install-common install-modules install-ldap install-node install-pub install-ra install-scep clean distclean::
	$(MAKE) $(SUBDIRS) SUBTARGET=$@

# we don't install the common components if we build packages
install-common-parts::
	@if [ $(package_build) != "yes" ]; then \
		echo installing common components because it is not a package build; \
		$(MAKE) install-common; \
	else \
		echo installing common components because it is a package build; \
		$(MAKE) install-common; \
	fi 

$(SUBDIRS)::
	cd $@ && $(MAKE) $(SUBTARGET)

########################################################
##               BEGIN CLEANUP STUFF                  ##
########################################################

clean distclean::	clean.local

clean.local::
	@for i in .ca* .ra* .install* .ssl* tmp ; do \
		if test -e $i ; then rm -rf $i ; fi; \
	done

distclean::
	@for i in config.status config.cache config.log ; do\
		if test -e $i ; then rm -rf $i ; fi; \
	done ; \
	$(RM) -f contrib/apache/*.conf ; \
	$(RM) -f config.status config.cache config.log ; \
	$(RM) -rf autom4te.cache

########################################################
##                END CLEANUP STUFF                   ##
########################################################

dist snap rpm online offline common pkgconfig bin pkgbuild source::
	@$(MAKE) -s -f Makefile.devel $@

