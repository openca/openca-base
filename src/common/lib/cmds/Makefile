# file: src/common/lib/cmds/Makefile
#
# (c) Copyright 2001-2004 The OpenCA Project

TOP	= ../../../..
include $(TOP)/Makefile.global-vars

DEST_CGI_CMDDIR		= ${lib_prefix}/cmds

# commands derived from .in files:
AC_CMDS	= \

# commands not derived from .in files:
STATIC_CMDS	= \
	addCRR				\
	add_module			\
	add_right			\
	add_role			\
	approveCRR			\
	approveCRRnotSigned		\
	approveCSR			\
	approveCSRnotSigned		\
	basic_csr			\
	advanced_csr			\
	authenticated_csr		\
	bpDoFunction			\
	bpDoStep			\
	bpExportPIN			\
	bpImportNewUser			\
	bpImportNewProcess		\
	bpImportProcessData		\
	bpImportProcessDataCompact      \
	bpIssueCertificate		\
	bpListProcess			\
	bpListUser			\
	bpRecoverCert			\
	bpRecoverKey			\
	bpRevokeCertificate		\
	bpSetState			\
	bpUnsetState			\
	bpViewProcess			\
	changeCRR			\
	changeCSR			\
	changePasswd			\
	cleanupSessions			\
	confirm_revreq			\
	crlList				\
	deleteCRR			\
	deleteCSR			\
	deleteListCSR			\
	deletePasswd			\
	delete_module			\
	delete_right			\
	editCRR				\
	editCSR				\
	exportCAReqCert			\
	exportDB			\
	genCACert			\
	genCAReq			\
	genCRL				\
	genCRLfromFile			\
	genDB				\
	genMenu				\
	getMenu				\
	genSKey				\
	getParams			\
	getStaticPage			\
	getcert				\
	hsmLogin			\
	hsmLogout			\
	importCACert			\
	importDB			\
	issueCertificate		\
	ldapAddCert			\
	ldapAddCertByName		\
	ldapAddCerts			\
	ldapAddCRL			\
	ldapAddCRLbyName		\
	ldapCreateCSR			\
	ldapDeleteCert			\
	ldapDeleteCertByName		\
	ldapImportCerts			\
	ldapUpdate			\
	ldapUpdateCA			\
	ldapUpdateCRL			\
	ldapUpdateCerts			\
	listCRR				\
	listCSR				\
	listCerts			\
	lists				\
	logRecovery			\
	new_module			\
	new_right			\
	new_role			\
	nodeDownloadAll			\
	nodeDownloadBP			\
	nodeDownloadCRL			\
	nodeDownloadCert		\
	nodeDownloadConfig		\
	nodeEnrollAll			\
	nodeEnrollBP			\
	nodeEnrollCACert		\
	nodeEnrollCRL			\
	nodeEnrollCert			\
	nodeEnrollConfig		\
	nodeReceiveAll			\
	nodeReceiveCRR			\
	nodeReceiveCSR			\
	nodeUploadAll			\
	nodeUploadCRR			\
	nodeUploadCSR			\
	pkcs10_req			\
	raList				\
	rebuildChain			\
	rebuildOpenSSLindexDB		\
	removeFiles			\
	removeKey			\
	renewCSR			\
	revokeCertificate		\
	revoke_req			\
	scepGetCACert			\
	scepPKIOperation		\
	search				\
	search_rights			\
	sendCRINMail			\
	sendMail			\
	send_cert_key			\
	send_cert_key_openssl		\
	send_cert_key_pkcs12		\
	send_cert_key_pkcs8		\
	send_email_cert			\
	sendcert						\
	serverInfo					\
	setLanguage					\
	setPasswd						\
	setupInitialCert		\
	show_modules				\
	show_prepared_module\
	show_prepared_right	\
	show_prepared_role	\
	show_rights					\
	show_roles					\
	signConfig					\
	stats								\
	stopDaemon					\
	submit_revreq				\
	test_cert						\
	updateOCSPindexDB		\
	updateSearchAttributes	\
	upgradeDB						\
	verifyPIN						\
	verifySignature			\
	verifyEmail					\
	viewLoas						\
	viewCRL							\
	viewCRR							\
	viewCSR							\
	viewCert						\
	viewCertFull				\
	viewLog							\
	viewSignature				\
	warnExpiring				\
	writeCertMail				\
	statusAutoCA				\
	startAutoCA					\
	stopAutoCA					\
	statusAutoRevoke		\
	startAutoRevoke			\
	stopAutoRevoke			\
	statusAutoEmail			\
	startAutoEmail			\
	stopAutoEmail				\
	statusAutoCRL				\
	startAutoCRL				\
	stopAutoCRL					\
	newUser

#	confirm_revreq			\
#	bpDeletePIN			\
#	bpImportUpdateUser		\

CMDS	= $(AC_CMDS) $(STATIC_CMDS)

#---- variable settings above, rules below ----

.PHONY:	default test install clean distclean

default::

test::
	@PERL5OPT=""; \
	for file in `ls ../../../modules`; do \
		if [ -d ../../../modules/$$file ]; then \
			PERL5OPT="$$PERL5OPT -I../../../modules/$$file/blib/lib"; \
		fi; \
	done; \
	PERL5LIB=""; \
	for file in `ls ../../../modules`; do \
		if [ -d ../../../modules/$$file ]; then \
			PERL5LIB="$$PERL5LIB:../../../modules/$$file/blib/arch"; \
		fi; \
	done; \
	export PERL5OPT=$$PERL5OPT; \
	export PERL5LIB=$$PERL5LIB; \
	for cmd in $(CMDS); do \
		$(PERL) -c $$PERL5OPT $$cmd; \
	done;

$(DEST_CGI_CMDDIR):
		$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=755 DIR=$@

install::	$(CMDS)

$(CMDS)::		$(DEST_CGI_CMDDIR)
$(CMDS)::
		$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $@ $(DEST_CGI_CMDDIR)/$@

clean::
distclean::
		@if ! [ -z $(AC_CMDS) ] ; then \
			$(RM) $(AC_CMDS) ; \
		 fi
