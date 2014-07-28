# file: src/common/etc/rbac/cmds/Makefile
#
# © 2001-2004 OpenCA Group

TOP	= ../../../../..
include $(TOP)/Makefile.global-vars

DEST_CONFRBACCMDSDIR	= ${etc_prefix}/rbac/cmds

FILES	= \
	addCRR.xml			\
	add_module.xml			\
	add_right.xml			\
	add_role.xml			\
	add_script.xml			\
	approveCRR.xml			\
	approveCRRnotSigned.xml		\
	approveCSR.xml			\
	approveCSRnotSigned.xml		\
	basic_csr.xml			\
	advanced_csr.xml		\
	authenticated_csr.xml		\
	bpDoFunction.xml		\
	bpDoStep.xml			\
	bpExportPIN.xml			\
	bpIssueCertificate.xml		\
	bpImportNewProcess.xml		\
	bpImportNewUser.xml		\
	bpImportProcessData.xml		\
	bpImportProcessDataCompact.xml	\
	bpListProcess.xml		\
	bpListUser.xml			\
	bpRecoverCert.xml		\
	bpRecoverKey.xml		\
	bpRevokeCertificate.xml		\
	bpSetState.xml			\
	bpUnsetState.xml		\
	bpViewProcess.xml		\
	changeCRR.xml			\
	changeCSR.xml			\
	changePasswd.xml		\
	crlList.xml			\
	cleanupSessions.xml		\
	confirm_revreq.xml		\
	deleteCRR.xml			\
	deleteCSR.xml			\
	deleteListCSR.xml		\
	deletePasswd.xml		\
	delete_module.xml		\
	delete_right.xml		\
	delete_script.xml		\
	editCRR.xml			\
	editCSR.xml			\
	exportCAReqCert.xml		\
	exportDB.xml			\
	genCACert.xml			\
	genCAReq.xml			\
	genCRL.xml			\
	genCRLfromFile.xml		\
	genDB.xml			\
	genMenu.xml			\
	getMenu.xml			\
	genSKey.xml			\
	getParams.xml			\
	getStaticPage.xml		\
	getcert.xml			\
	getcacert.xml			\
	hsmLogin.xml			\
	hsmLogout.xml			\
	importCACert.xml		\
	importDB.xml			\
	issueCertificate.xml		\
	ldapAddCert.xml			\
	ldapAddCertByName.xml		\
	ldapAddCerts.xml		\
	ldapAddCRL.xml			\
	ldapAddCRLbyName.xml		\
	ldapCreateCSR.xml		\
	ldapDeleteCert.xml		\
	ldapDeleteCertByName.xml	\
	ldapImportCerts.xml		\
	ldapUpdate.xml			\
	ldapUpdateCA.xml		\
	ldapUpdateCRL.xml		\
	ldapUpdateCerts.xml		\
	listCRR.xml			\
	listCSR.xml			\
	listCerts.xml			\
	lists.xml			\
	logRecovery.xml			\
	new_module.xml			\
	new_right.xml			\
	new_role.xml			\
	new_script.xml			\
	nodeDownloadAll.xml		\
	nodeDownloadBP.xml		\
	nodeDownloadCRL.xml		\
	nodeDownloadCert.xml		\
	nodeDownloadConfig.xml		\
	nodeEnrollAll.xml		\
	nodeEnrollBP.xml		\
	nodeEnrollCACert.xml		\
	nodeEnrollCRL.xml		\
	nodeEnrollCert.xml		\
	nodeEnrollConfig.xml		\
	nodeReceiveAll.xml		\
	nodeReceiveCRR.xml		\
	nodeReceiveCSR.xml		\
	nodeUploadAll.xml		\
	nodeUploadCRR.xml		\
	nodeUploadCSR.xml		\
	pkcs10_req.xml			\
	raList.xml			\
	rebuildChain.xml		\
	rebuildOpenSSLindexDB.xml	\
	removeFiles.xml			\
	removeItem.xml			\
	removeKey.xml			\
	renewCSR.xml			\
	replayLog.xml			\
	revokeCertificate.xml		\
	revoke_req.xml			\
	scepGetCACert.xml		\
	scepPKIOperation.xml		\
	search.xml			\
	searchCert.xml			\
	search_rights.xml		\
	sendCRINMail.xml		\
	sendMail.xml			\
	send_cert_key.xml		\
	send_cert_key_openssl.xml	\
	send_cert_key_pkcs12.xml	\
	send_cert_key_pkcs8.xml		\
	send_email_cert.xml		\
	sendcert.xml			\
	serverInfo.xml			\
	setLanguage.xml			\
	setPasswd.xml			\
	setupInitialCert.xml		\
	show_modules.xml		\
	show_prepared_module.xml	\
	show_prepared_right.xml		\
	show_prepared_role.xml		\
	show_prepared_script.xml	\
	show_rights.xml			\
	show_roles.xml			\
	show_script.xml			\
	show_scripts.xml		\
	signConfig.xml			\
	stopDaemon.xml			\
	submit_revreq.xml		\
	test_cert.xml			\
	updateOCSPindexDB.xml		\
	updateSearchAttributes.xml	\
	upgradeDB.xml			\
	verifyEmail.xml			\
	verifyPIN.xml			\
	verifySignature.xml		\
	viewLoas.xml			\
	viewCRL.xml			\
	viewCRR.xml			\
	viewCSR.xml			\
	viewCert.xml			\
	viewCertFull.xml		\
	viewLog.xml			\
	viewSignature.xml		\
	warnExpiring.xml		\
	writeCertMail.xml		\
	stats.xml			\
	startAutoEmail.xml		\
	stopAutoEmail.xml		\
	statusAutoEmail.xml		\
	startAutoCA.xml			\
	stopAutoCA.xml			\
	statusAutoCA.xml		\
	startAutoRevoke.xml	\
	stopAutoRevoke.xml	\
	statusAutoRevoke.xml\
	startAutoCRL.xml		\
	stopAutoCRL.xml			\
	statusAutoCRL.xml		\
	newUser.xml			\
	find_undef_cmds.pl

#	bpDeletePIN.xml			\
#	bpImportUpdateUser.xml		\

#---- variable settings above, rules below ----

.PHONY:	default install clean distclean

default::

install::		$(FILES)

$(FILES)::
	$(INSTALL) -g ${httpd_group} -o ${httpd_user} -m 644 $@ $(DEST_CONFRBACCMDSDIR)/$@

distclean::
