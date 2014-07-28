# file: src/common/etc/bp/functions/Makefile
#
# © 2001-2004 OpenCA Group

TOP	= ../../../../..
include $(TOP)/Makefile.global-vars

FUNC_DEST_DIR	= ${etc_prefix}/bp/functions

FILES	= \
	backup_key.txt		\
	check_csr.txt		\
	check_csr_params.txt	\
	check_key.txt		\
	check_key_params.txt	\
	check_pin.txt		\
	complete_csr.txt	\
	create_cert.txt		\
	create_csr.txt		\
	create_key.txt		\
	create_pin.txt		\
	enroll_pkcs12.txt	\
	enroll_pin.txt		\
	postproc_cert.txt	\
	receive_csr.txt		\
	upload_csr.txt

#---- variable settings above, rules below ----

.PHONY:	default install clean distclean

default::

install::	$(FILES)

$(FILES):: $(FUNC_DEST_DIR)
		$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $@ $(FUNC_DEST_DIR)/$@

$(FUNC_DEST_DIR)::
		$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=755 DIR=$@

distclean::
		#$(RM)
