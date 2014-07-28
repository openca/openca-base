# file: src/Makefile
#
# © 2001 OpenCA Group

TOP	= ..
include $(TOP)/Makefile.global-vars

COMMON_DIR = common
MODULE_DIR = modules
EXT_MODULE_DIR = ext-modules
OCSPD_DIR  = ocspd
SCEP_DIR   = scep
OPENCA_SV  = openca-sv
SCRIPT_DIR = scripts
WEB_DIR    = web-interfaces

SUBDIRS = \
	$(COMMON_DIR)	\
	$(MODULE_DIR)	\
	$(EXT_MODULE_DIR) \
	$(SCRIPT_DIR)	\
	$(WEB_DIR)

#	$(OPTIONAL_C_MODULES)
#	$(OCSPD_DIR)	\
#	$(OPENCA_SV)	

## MODULES.c = \
##	openca-sv \
##	$(OPTIONAL_C_MODULES)

#---- variable settings above, rules below ----

.PHONY:	default test install-batch install-ca install-node install-ra install-ldap install-common install-modules install-pub install-scep clean clean.local distclean

default::	$(SUBDIRS)

$(SUBDIRS)::
		cd $@ && $(MAKE) $(SUBTARGET)

install-common::
	@echo "Script dir... "
	@echo $(MAKE) $(SCRIPT_DIR) SUBTARGET=install
	@$(MAKE) $(SCRIPT_DIR) SUBTARGET=install
	@echo "Done with Scripts... "
	@$(MAKE) $(COMMON_DIR) SUBTARGET=install
	@## the modules have their own spec-files
	@if [ $(package_build) != "yes" ]; then \
		echo installing modules because it is not a package build; \
		$(MAKE) $(MODULE_DIR) SUBTARGET=install; \
		$(MAKE) $(EXT_MODULE_DIR) SUBTARGET=install; \
	else \
		echo not installing modules because it is a package build; \
		$(MAKE) $(MODULE_DIR) SUBTARGET=install; \
		$(MAKE) $(EXT_MODULE_DIR) SUBTARGET=install; \
	fi

#			$(MAKE) $(OPENCA_SV) SUBTARGET=install; \
#			if [ x"$(OPTIONAL_C_MODULES)" != x ]; then \
#			   $(MAKE) $(OPTIONAL_C_MODULES) SUBTARGET=install; \
#			fi

install-bin::
	@$(MAKE) $(SCRIPT_DIR) SUBTARGET=install

install-batch install-ca install-node install-ra install-ldap install-pub install-scep::
		$(MAKE) $(WEB_DIR) SUBTARGET=$@

install-modules:
	@$(MAKE) $(MODULE_DIR) SUBTARGET=install
	@$(MAKE) $(EXT_MODULE_DIR) SUBTARGET=install

test clean distclean::
		$(MAKE) $(SUBDIRS) SUBTARGET=$@

distclean::
		#$(RM)
