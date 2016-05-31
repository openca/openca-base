# AC_INIT(FULL-PACKAGE-NAME, VERSION, BUG-REPORT-ADDRESS)
AC_REVISION($Revision: 1.1 $)
AC_INIT(openca, 1.5.2, openca-users@lists.sf.net)

AC_PREREQ(2.50)
AC_COPYRIGHT(Copyright 1999-2013 by Massimiliano Pala and OpenCA Labs)
AC_CONFIG_AUX_DIR(build)
AC_CONFIG_MACRO_DIR([m4])

CPU=`uname -p`
AC_SUBST(CPU)

AC_CANONICAL_SYSTEM

dnl AC_CONFIG_SRCDIR([src/drivers/openssl/pki_x509.c])

dnl ifdef ([LT_INIT], [LT_INIT],[AC_PROG_LIBTOOL])
AC_PROG_LIBTOOL

AC_PROG_EGREP

AM_INIT_AUTOMAKE

AM_PROG_CC_C_O

AM_MAINTAINER_MODE

myhome=${HOME}
AC_SUBST(myhome)

myarch=

dnl Select OS specific versions of source files.
shlext=so
case "${build_os}" in
 *linux*)       myarch=linux
		shlext=so
		;;
 *bsd*)         myarch=bsd
		shlext=so
		;;
 *iphone*)      myarch=iphone
		shlext=dylib
		;;
 *darwin*)      myarch=darwin
		shlext=dylib
		;;
 *sun*)         myarch=solaris
		shlext=so
		;;
 *solaris*)     myarch=solaris
		enable_shared=yes
		shlext=so
		;;
 *hpux*)        myarch=hpux
		shlext=so
		;;
 *) AC_MSG_ERROR([Operating system ${build_os} not supported]) ;;
esac

AC_SUBST(myarch)

mybits=""
if [[ `uname -p` = "x86_64" ]] ; then
	mybits="64";
fi
AC_SUBST(mybits)

arch_target=

case "$target" in
	i*86-*)          
		 arch_target=x86 ;;
	sparc*-*)         
		arch_target=Sparc ;;
	powerpc*-*)       
		arch_target=PowerPC ;;
	*sparc*solaris*)  
		arch_target=Sparc ;;
	*arm*)  	  	
		arch_target=armv6 ;;
	*)                
		[ `uname -p` ] && arch_target=`uname -p` || \
			arch_target="Unknown" ;;
esac

AC_SUBST(arch_target)

build_os=$myarch;
AC_SUBST(build_os)

if [[ "x$myarch" = "xsolaris" ]] ; then
   dnl Strange OpenSolaris behavior with GCC - switch to cc
   dnl for correctly building DBI-mysql
   AC_PATH_PROG( CC, cc, cc,
      /opt/SUNWspro/bin:/opt/SUNWspro/sbin:$PATH:/bin:/usr/bin:/usr/local/sbin)
fi

dnl Set Version Numbers
VERSION=`cat VERSION | sed -e "s|-[[0-9]]*||"`
AC_SUBST(VERSION)

RC=`cat VERSION | sed -e "s|[[0-9.]]*-||"`
AC_SUBST(RC)

TODAY=`/bin/date +%Y%m%d`
AC_SUBST(TODAY)

# if ! [[ -f "/etc/issue" ]] ; then
# 	AC_CANONICAL_SYSTEM
# 	AC_PROG_LIBTOOL
# fi

# AC_PROG_EGREP

# if [[ -f "/etc/issue" ]] ; then
#    DIST_VERSION=`$EGREP -o [[0-9.]]+ /etc/issue | head -n 1`
# else
#    DIST_VERSION=`echo ${build_os} | $EGREP -o [[0-9.]]+`
# fi
# 
# AC_SUBST(DIST_VERSION)

if [[ -f "/etc/issue" ]] ; then
   DIST_NAME=`head -n 1 /etc/issue | cut -f 1,1 -d ' '`
else
   DIST_NAME=`echo ${build_os} | $EGREP -o [[A-Za-z]]+`
fi

AC_SUBST(DIST_NAME)

# DIST_VERSION=`bash -c 'grep -o [0-9] /etc/issue'`
# DIST_VERSION=`cat /etc/issue | /bin/sed -e 's/[a-zA-Z ()\\]*//g'`

if [[ "x$myarch" = "xsolaris" ]] ; then
	DIST_VERSION=`uname -r`
else
	if [[ -f "/etc/issue" ]] ; then
	   DIST_VERSION=`$EGREP -o [[0-9.]]+ /etc/issue | head -n 1`
	else
	   DIST_VERSION=`echo ${build_os} | $EGREP -o [[0-9.]]+`
	fi
fi

AC_SUBST(DIST_VERSION)

dnl Check for install program
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_AWK
# AC_PROG_CXX
dnl AC_PROG_CC
# AC_PROG_CPP
AC_PROG_MAKE_SET
# AC_PROG_RANLIB
# AC_PATH_PROG( GRPS, groups, groups,
# 		/usr/xpg4/bin/id:$PATH:/sbin:/usr/sbin:/usr/local/sbin)

dnl Check for needed commands (for default users)
AC_PATH_PROG( WHOAMI, whoami, whoami,
		/usr/xpg4/bin:$PATH:/sbin:/usr/sbin:/usr/local/sbin)

AC_PATH_PROG( ID, id, id,
		/usr/xpg4/bin:$PATH:/sbin:/usr/sbin:/usr/local/sbin)

dnl Defaults
def_openca_user=`$ID -un`
# def_openca_group=`$GRPS | $EGREP -o [[^ ]]+`
def_openca_group=`$ID -gn`
def_prefix=/opt/openca

# this is a big ToDo for the future

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lIOKit':
# AC_CHECK_LIB([IOKit], [main])
# FIXME: Replace `main' with a function in `-lcrypto':
# AC_CHECK_LIB([crypto], [main])
# FIXME: Replace `main' with a function in `-ldl':
# AC_CHECK_LIB([dl], [main])
# FIXME: Replace `main' with a function in `-lfl':
# AC_CHECK_LIB([fl], [main])
# FIXME: Replace `main' with a function in `-ll':
# AC_CHECK_LIB([l], [main])
# FIXME: Replace `main' with a function in `-lnsl':
# AC_CHECK_LIB([nsl], [main])
# FIXME: Replace `main' with a function in `-lposix4':
# AC_CHECK_LIB([posix4], [main])
# FIXME: Replace `main' with a function in `-lsocket':
# AC_CHECK_LIB([socket], [main])
# FIXME: Replace `main' with a function in `-lssl':
# AC_CHECK_LIB([ssl], [main])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([stdlib.h string.h sys/socket.h syslog.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_STRUCT_TM

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([bzero memset setenv socket strcasecmp strchr strrchr strstr])

NODE=`uname -n`

dnl ========================== Install Builder Path Search ===================

builder_path=$default_path:$HOME/installbuilder/bin:$HOME/installbuilder-5.4.10/bin:$HOME/installbuilder/bin/Builder.app/Contents/MacOS/

ibuilder="builder"

if [[ "x$DIST_NAME" = "xdarwin" ]] ; then
	ibuilder="installbuilder.sh"
fi

AC_PATH_PROG( INSTALL_BUILDER, $ibuilder, , $builder_path )
AC_SUBST(INSTALL_BUILDER)

dnl AC_MSG_ERROR( [****** ($DIST_NAME) IBUILDER is : $ibuilder and INSTALL_BUILDER is $INSTALL_BUILDER] );

######################################################
## The following code is complety generated by hand ##
##                       BEGIN                      ##
######################################################

	## this is a really dirty hack to avoid NONE in paths
	if test x"$prefix" = xNONE; then prefix=${ac_default_prefix}; fi
	if test x"$exec_prefix" = xNONE; then exec_prefix=${prefix}; fi

	## this is a hack to get a real exec_prefix path and not
	## something like ${prefix}
	EXEC_PREFIX=$exec_prefix
	AC_SUBST(EXEC_PREFIX)

	dnl ############################## BEGIN #############################
	dnl                         openssl configuration


	dnl OpenSSL prefix
	dnl If this is not specified, configure will try to use
	dnl pkg-config if it is found, and openssl.pic is found
	dnl on the user's system for openssl v. 0.9.7 or greater.
	dnl If not specified and pkg-config information is not
	dnl available, we try reasonable defaults.
	AC_ARG_WITH( openssl-prefix,
		AC_HELP_STRING( [--with-openssl-prefix=DIR], [openssl prefix]),
		openssl_prefix=$withval, openssl_prefix= )

	dnl                        openssl configuration
	dnl ############################### END ##############################

	dnl ############################## BEGIN #############################
	dnl                       module configuration

	dnl deactivation of external modules to support package maintainers

	EXTERNAL_MODULES="yes"
	AC_ARG_ENABLE( external-modules,
		AC_HELP_STRING( [--disable-external-modules],
				[disable the installation of external modules]),
		[EXTERNAL_MODULES=$enableval],
		[EXTERNAL_MODULES="yes"])
	AC_SUBST(EXTERNAL_MODULES)

	dnl optional modules

	dnl OCSP daemon
	dnl AC_ARG_ENABLE( ocspd,
	dnl 	AC_HELP_STRING( [--enable-ocspd], [enable OCSP daemon]),
	dnl 	[OCSPD_MODULE="ocspd"
	dnl 	AC_CONFIG_SUBDIRS( src/ocspd)],
	dnl 	[OCSPD_MODULE=""])

	dnl OPTIONAL_C_MODULES="$OPTIONAL_C_MODULES $OCSPD_MODULE"

	dnl SCEP daemon
	dnl AC_ARG_ENABLE( scep,
	dnl 	AC_HELP_STRING( [--enable-scep], [enable SCEP daemon]),
	dnl 	[SCEP_MODULE="scep"
	dnl 	AC_CONFIG_SUBDIRS( src/scep)],
	dnl 	[SCEP_MODULE=""])
	AC_ARG_ENABLE( scep,
		AC_HELP_STRING( [--enable-scep], [enable SCEP daemon]),
		[SCEP_MODULE="scep"],
		[SCEP_MODULE=""])

	dnl OPTIONAL_C_MODULES="$OPTIONAL_C_MODULES $SCEP_MODULE"

	dnl AC_SUBST(OPTIONAL_C_MODULES)

	AC_ARG_WITH( build-dir,
		AC_HELP_STRING( [--with-build-dir=DIR], [package building dir]),
		build_dir=$withval, build_dir=)

	if [[ "x${DESTDIR}" == "x" ]] ; then
		DESTDIR="${build_dir}"
	fi

	if [[ "x${build_dir}" == "x" ]] ; then
		build_dir="${DESTDIR}"
	fi

	AC_SUBST(DESTDIR)
	AC_SUBST(build_dir)

	AC_ARG_WITH( service-mail-account,
		AC_HELP_STRING( [--with-service-mail-account=ARG], [sets the default email support account (default is admin@pki.openca.org))]),
		service_mail_account=$withval, service_mail_account=admin@pki.openca.org )
	AC_SUBST(service_mail_account)

	AC_ARG_WITH( support-mail-address,
		AC_HELP_STRING( [--with-support-mail-address=ARG], [default email support address in web UI (default is support@pki.openca.org))]),
		support_mail_address=$withval, support_mail_address=support@pki.openca.org )
	AC_SUBST(support_mail_address)

	AC_ARG_WITH( cert-chars,
		AC_HELP_STRING( [--with-cert-chars=ARG], [sets the default chars for certs (default is UTF8))]),
		cert_chars=$withval, cert_chars=UTF8 )
	AC_SUBST(cert_chars)

	AC_ARG_WITH( ca-organization,
		AC_HELP_STRING( [--with-ca-organization=ARG], [sets the default organization for the config.xml file]),
		ca_organization=$withval, ca_organization="OpenCA Labs" )
	AC_SUBST(ca_organization)

	AC_ARG_WITH( ca-locality,
		AC_HELP_STRING( [--with-ca-locality=ARG], [sets the default locality for the config.xml file]),
		ca_locality=$withval, ca_locality="" )
	AC_SUBST(ca_locality)

	AC_ARG_WITH( ca-state,
		AC_HELP_STRING( [--with-ca-state=ARG], [sets the default state for the config.xml file]),
		ca_state=$withval, ca_state="" )
	AC_SUBST(ca_state)

	AC_ARG_WITH( ca-country,
		AC_HELP_STRING( [--with-ca-country=ARG], [sets the default country for the config.xml file]),
		ca_country=$withval, ca_country="" )
	AC_SUBST(ca_country)

	dnl                       module configuration
	dnl ############################## END #############################

	dnl ############################## BEGIN #############################
	dnl                     use and group of base files

	AC_ARG_WITH( openca-user,
		AC_HELP_STRING( [--with-openca-user=ARG], [sets the OpenCA's user id (default is $def_openca_user)]),
		openca_user=$withval, openca_user=$def_openca_user )
	AC_SUBST(openca_user)

	AC_ARG_WITH( openca-group,
		AC_HELP_STRING( [--with-openca-group=ARG], [sets the OpenCA's group id (default is $def_openca_group)]),
		openca_group=$withval, openca_group=$def_openca_group )
	AC_SUBST(openca_group)

	dnl                     use and group of base files
	dnl ############################## END #############################

	dnl ############################## BEGIN #############################
	dnl                   directory-structure of OpenCA

	dnl general OpenCA directory
	AC_ARG_WITH( openca-prefix,
		AC_HELP_STRING( [--with-openca-prefix=OPENCAPREFIX], [sets OpenCA install prefix (default is PREFIX)]),
		openca_prefix=$withval, openca_prefix=${prefix})
	AC_SUBST(openca_prefix)

	dnl static directories
	AC_ARG_WITH( etc-prefix,
		AC_HELP_STRING( [--with-etc-prefix=CONFPREFIX], [sets configuration prefix (default is OPENCAPREFIX/etc)]),
		etc_prefix=$withval, etc_prefix=${openca_prefix}/etc/openca)
	AC_SUBST(etc_prefix)

	init_prefix=${openca_prefix}/etc/init.d
	AC_SUBST(init_prefix)

	dnl libs, cmds, servers - simply all code
	AC_ARG_WITH( lib-prefix,
		AC_HELP_STRING( [--with-lib-prefix=LIBPREFIX], [sets library prefix (default is OPENCAPREFIX/lib)]),
		lib_prefix=$withval, lib_prefix=${openca_prefix}/lib/openca)
	AC_SUBST(lib_prefix)

	dnl databases, tmp, crypto, mails
	AC_ARG_WITH( var-prefix,
		AC_HELP_STRING( [--with-var-prefix=VARPREFIX], [sets variable data prefix (default is OPENCAPREFIX/var)]),
		var_prefix=$withval, var_prefix=${openca_prefix}/var/openca)
	AC_SUBST(var_prefix)

	AC_ARG_WITH( batch-prefix,
		AC_HELP_STRING( [--with-batch-prefix=DIR], [sets batch system prefix (default is batch)]),
		batch_prefix=$withval, batch_prefix=batch)
	AC_SUBST(batch_prefix)

	AC_ARG_WITH( ca-prefix,
		AC_HELP_STRING( [--with-ca-prefix=DIR], [sets CA prefix (default is ca)]),
		ca_prefix=$withval, ca_prefix=ca)
	AC_SUBST(ca_prefix)

	AC_ARG_WITH( node-prefix,
		AC_HELP_STRING( [--with-node-prefix=NODEPREFIX], [sets Node management prefix (default is node)]),
		node_prefix=$withval, node_prefix=node)
	AC_SUBST(node_prefix)

	AC_ARG_WITH( ra-prefix,
		AC_HELP_STRING( [--with-ra-prefix=DIR], [sets RA prefix (default is ra)]),
		ra_prefix=$withval, ra_prefix=ra)
	AC_SUBST(ra_prefix)

	AC_ARG_WITH( ldap-prefix,
		AC_HELP_STRING( [--with-ldap-prefix=DIR], [sets LDAP prefix (default is ldap)]),
		ldap_prefix=$withval, ldap_prefix=ldap)
	AC_SUBST(ldap_prefix)

	AC_ARG_WITH( pub-prefix,
		AC_HELP_STRING( [--with-pub-prefix=DIR], [sets public gateway prefix (default is pub)]),
		pub_prefix=$withval, pub_prefix=pub)
	AC_SUBST(pub_prefix)

	AC_ARG_WITH( scep-prefix,
		AC_HELP_STRING( [--with-scep-prefix=DIR], [sets SCEP prefix (default is scep)]),
		scep_prefix=$withval, scep_prefix=scep)
	AC_SUBST(scep_prefix)

	dnl                   directory-structure of OpenCA
	dnl ############################## END #############################

	dnl ############################## BEGIN #############################
	dnl                       configuration for apache

	dnl only used to prepare src/common/etc/config.xml
	dnl never use this variable except of config.xml or the system will be inconsistent

	dnl default_web_user=nobody
	dnl default_web_group=nobody

	dnl if [[ -f "/etc/redhat-release" ]] ; then
	dnl 	default_web_user=apache
	dnl 	default_web_group=apache
	dnl fi

	AC_ARG_WITH( openca-tools-prefix,
		AC_HELP_STRING( [--with-openca-tools-prefix=PREFIX], [Prefix for openca-sv and openca-scep commands (this will search PREFIX/bin)]),
		openca_tools_prefix=$withval, openca_tools_prefix= )
	AC_SUBST(openca_tools_prefix)

	dnl Check for OpenCA Tools Installed
	eval openca_tools_path="${bindir}:${exec_prefix}/bin:${prefix}/bin:${PATH}:/bin:/usr/bin"
	if [[ "x${openca_tools_prefix}" != "x" ]]; then
		openca_tools_path="${openca_tools_prefix}/bin"
	fi

	AC_PATH_PROG( OPENCA_SV, openca-sv, openca-sv,
		${openca_tools_path} )

	if [[ "x$OPENCA_SV" = "xopenca-sv" ]] ; then
		AC_MSG_ERROR([**** ERROR: can not find the openca-sv command, please install openca-tools] [package or use --with-openca-tools-prefix option])
	fi

	AC_PATH_PROG( OPENCA_SCEP, openca-scep, openca-scep,
		${openca_tools_path} )

	AC_ARG_WITH( web-host,
		AC_HELP_STRING( [--with-web-host=WEBHOST], [sets web hostname (http, ldap, ...)]),
		web_host=$withval, web_host=$NODE)
	AC_SUBST(web_host)

	AC_ARG_WITH( prqp-server,
		AC_HELP_STRING( [--with-prqp-server=URI], [sets the PRQP server URI (default is http://WEBHOST:830/)]),
		prqp_server_uri=$withval, prqp_server_uri=http://$NODE:830/ )
	AC_SUBST(prqp_server_uri)

	AC_ARG_WITH( ocsp-server,
		AC_HELP_STRING( [--with-ocsp-server=URI], [sets the OCSP server URI (default is http://WEBHOST:2560/)]),
		ocsp_server_uri=$withval, ocsp_server_uri=http://$NODE:2560/ )
	AC_SUBST(ocsp_server_uri)

dnl WEB Configuration --- very specific for different systems

def_httpd_user=$def_openca_user
def_httpd_group=$def_openca_group
def_httpd_fs_prefix=${openca_prefix}/var/www

case "${DIST_NAME}" in
	*bsd*)
		def_httpd_user=www;
		def_httpd_group=www;
		def_openca_user=root;
		def_openca_group=wheel;
		;;
	*edora*)
		def_httpd_user=apache;
		def_httpd_group=apache;
		def_httpd_fs_prefix=/var/www;
		;;
	*CentOS*)
		def_httpd_user=apache;
		def_httpd_group=apache;
		def_httpd_fs_prefix=/var/www;
		;;
	*buntu*)
		def_httpd_user=www-data;
		def_httpd_group=www-data;
		def_httpd_fs_prefix=/var/www
		;;
	*olaris*)
		def_httpd_user=webservd;
		def_httpd_group=webservd;
		;;
	*ebian*)
		def_httpd_user=www-data;
		def_httpd_group=www-data;
		def_httpd_fs_prefix=/var/www
		;;
	*arwin*)
		def_httpd_user=www;
		def_httpd_group=www;
		def_httpd_fs_prefix=/opt/local/var/www
		;;
	*)
		def_httpd_user=nobody;
		;;
esac

dnl fi
	AC_ARG_WITH( httpd-user,
		AC_HELP_STRING( [--with-httpd-user=ARG], [sets the httpd's user id (default is nobody)]),
		httpd_user=$withval, httpd_user=$def_httpd_user )
	AC_SUBST(httpd_user)

	AC_ARG_WITH( httpd-group,
		AC_HELP_STRING( [--with-httpd-group=ARG], [sets the httpd's group id (default is nobody)]),
		httpd_group=$withval, httpd_group=$def_httpd_group )
	AC_SUBST(httpd_group)

	AC_ARG_WITH( httpd-main-dir,
		AC_HELP_STRING( [--with-httpd-main-dir=pki], [sets httpd main dir (default is 'pki')]),
		httpd_main_dir=$withval, httpd_main_dir=pki )

	AC_ARG_WITH( httpd-fs-prefix,
		AC_HELP_STRING( [--with-httpd-fs-prefix=HTTPDFSPREFIX], [sets httpd filesystem prefix (default is ${def_httpd_fs_prefix})]),
		httpd_fs_prefix=$withval, httpd_fs_prefix=${def_httpd_fs_prefix})
	AC_SUBST(httpd_fs_prefix)

	AC_ARG_WITH( httpd-url-prefix,
		AC_HELP_STRING( [--with-httpd-url-prefix=HTTPDURLPREFIX], [sets httpd URL prefix (default is empty)]),
		httpd_url_prefix=$withval, httpd_url_prefix=)
	dnl (*internal use only*) AC_SUBST(httpd_url_prefix)

	AC_ARG_WITH( htdocs-fs-prefix,
		AC_HELP_STRING( [--with-htdocs-fs-prefix=HTDOCSFSPREFIX], [sets htdocs filesystem prefix (default is HTTPDFSPREFIX/html/${httpd_main_dir})]),
		htdocs_fs_prefix=$withval, htdocs_fs_prefix=${httpd_fs_prefix}/html/${httpd_main_dir})
	AC_SUBST(htdocs_fs_prefix)

	AC_ARG_WITH( htdocs-url-prefix,
		AC_HELP_STRING( [--with-htdocs-url-prefix=HTDOCSURLPREFIX], [sets htdocs URL prefix (default is HTTPDURLPREFIX)]),
		htdocs_url_prefix=$withval, htdocs_url_prefix="${httpd_url_prefix}/${httpd_main_dir}")
	AC_SUBST(htdocs_url_prefix)

	batch_htdocs_url_prefix=$htdocs_url_prefix/batch
	AC_SUBST(batch_htdocs_url_prefix)

	pub_htdocs_url_prefix=$htdocs_url_prefix/pub
	AC_SUBST(pub_htdocs_url_prefix)

	ldap_htdocs_url_prefix=$htdocs_url_prefix/ldap
	AC_SUBST(ldap_htdocs_url_prefix)

	scep_htdocs_url_prefix=$htdocs_url_prefix/scep
	AC_SUBST(scep_htdocs_url_prefix)

	node_htdocs_url_prefix=$htdocs_url_prefix/node
	AC_SUBST(node_htdocs_url_prefix)

	ra_htdocs_url_prefix=$htdocs_url_prefix/ra
	AC_SUBST(ra_htdocs_url_prefix)

	ca_htdocs_url_prefix=$htdocs_url_prefix/ca
	AC_SUBST(ca_htdocs_url_prefix)

	AC_ARG_WITH( cgi-fs-prefix,
		AC_HELP_STRING( [--with-cgi-fs-prefix=CGIFSPREFIX], [sets CGI filesystem prefix (default is HTTPDFSPREFIX/cgi-bin/${httpd_main_dir})]),
		cgi_fs_prefix=$withval, cgi_fs_prefix=$httpd_fs_prefix/cgi-bin/${httpd_main_dir})
	AC_SUBST(cgi_fs_prefix)

	AC_ARG_WITH( cgi-url-prefix,
		AC_HELP_STRING( [--with-cgi-url-prefix=CGIURLPREFIX], [sets CGI URL prefix (default is HTTPDURLPREFIX/cgi-bin/${httpd_main_dir})]),
		cgi_url_prefix=$withval, cgi_url_prefix=/cgi-bin/${httpd_main_dir} )
	AC_SUBST(cgi_url_prefix)

	batch_cgi_url_prefix=$cgi_url_prefix/batch
	AC_SUBST(batch_cgi_url_prefix)
	pub_cgi_url_prefix=$cgi_url_prefix/pub
	AC_SUBST(pub_cgi_url_prefix)
	ldap_cgi_url_prefix=$cgi_url_prefix/ldap
	AC_SUBST(ldap_cgi_url_prefix)
	scep_cgi_url_prefix=$cgi_url_prefix/scep
	AC_SUBST(scep_cgi_url_prefix)
	node_cgi_url_prefix=$cgi_url_prefix/node
	AC_SUBST(node_cgi_url_prefix)
	ra_cgi_url_prefix=$cgi_url_prefix/ra
	AC_SUBST(ra_cgi_url_prefix)
	ca_cgi_url_prefix=$cgi_url_prefix/ca
	AC_SUBST(ca_cgi_url_prefix)

	AC_ARG_WITH( batch-htdocs-fs-prefix,
		AC_HELP_STRING( [--with-batch-htdocs-fs-prefix=DIR], [sets batch system htdocs directory (default is HTDOCSFSPREFIX/batch)]),
		batch_htdocs_fs_prefix=$withval, batch_htdocs_fs_prefix=$htdocs_fs_prefix/$batch_prefix)
	AC_SUBST(batch_htdocs_fs_prefix)

	AC_ARG_WITH( batch-cgi-fs-prefix,
		AC_HELP_STRING( [--with-batch-cgi-fs-prefix=DIR], [sets batch system cgi directory (default is CGIFSPREFIX/batch)]),
		batch_cgi_fs_prefix=$withval, batch_cgi_fs_prefix=$cgi_fs_prefix/$batch_prefix)
	AC_SUBST(batch_cgi_fs_prefix)

	AC_ARG_WITH( ca-htdocs-fs-prefix,
		AC_HELP_STRING( [--with-ca-htdocs-fs-prefix=DIR], [sets CA htdocs directory (default is HTDOCSFSPREFIX/ca)]),
		ca_htdocs_fs_prefix=$withval, ca_htdocs_fs_prefix=$htdocs_fs_prefix/$ca_prefix)
	AC_SUBST(ca_htdocs_fs_prefix)

	AC_ARG_WITH( ca-cgi-fs-prefix,
		AC_HELP_STRING( [--with-ca-cgi-fs-prefix=DIR], [sets CA cgi directory (default is CGIFSPREFIX/ca)]),
		ca_cgi_fs_prefix=$withval, ca_cgi_fs_prefix=$cgi_fs_prefix/$ca_prefix)
	AC_SUBST(ca_cgi_fs_prefix)

	AC_ARG_WITH( node-htdocs-fs-prefix,
		AC_HELP_STRING( [--with-node-htdocs-fs-prefix=DIR], [sets Node management htdocs directory (default is HTDOCSFSPREFIX/NODEPREFIX)]),
		node_htdocs_fs_prefix=$withval, node_htdocs_fs_prefix=$htdocs_fs_prefix/$node_prefix)
	AC_SUBST(node_htdocs_fs_prefix)

	AC_ARG_WITH( node-cgi-fs-prefix,
		AC_HELP_STRING( [--with-node-cgi-fs-prefix=DIR], [sets Node management cgi directory (default is CGIFSPREFIX/NODEPREFIX)]),
		node_cgi_fs_prefix=$withval, node_cgi_fs_prefix=$cgi_fs_prefix/$node_prefix)
	AC_SUBST(node_cgi_fs_prefix)

	AC_ARG_WITH( ra-htdocs-fs-prefix,
		AC_HELP_STRING( [--with-ra-htdocs-fs-prefix=DIR], [sets RA htdocs directory (default is HTDOCSFSPREFIX/ra)]),
		ra_htdocs_fs_prefix=$withval, ra_htdocs_fs_prefix=$htdocs_fs_prefix/$ra_prefix)
	AC_SUBST(ra_htdocs_fs_prefix)

	AC_ARG_WITH( ra-cgi-fs-prefix,
		AC_HELP_STRING( [--with-ra-cgi-fs-prefix=DIR], [sets RA cgi directory (default is CGIFSPREFIX/ra)]),
		ra_cgi_fs_prefix=$withval, ra_cgi_fs_prefix=$cgi_fs_prefix/$ra_prefix)
	AC_SUBST(ra_cgi_fs_prefix)

	AC_ARG_WITH( ldap-htdocs-fs-prefix,
		AC_HELP_STRING( [--with-ldap-htdocs-fs-prefix=DIR], [sets LDAP htdocs directory (default is HTDOCSFSPREFIX/ldap)]),
		ldap_htdocs_fs_prefix=$withval, ldap_htdocs_fs_prefix=$htdocs_fs_prefix/$ldap_prefix)
	AC_SUBST(ldap_htdocs_fs_prefix)

	AC_ARG_WITH( ldap-cgi-fs-prefix,
		AC_HELP_STRING( [--with-ldap-cgi-fs-prefix=DIR], [sets LDAP cgi directory (default is CGIFSPREFIX/ldap)]),
		ldap_cgi_fs_prefix=$withval, ldap_cgi_fs_prefix=$cgi_fs_prefix/$ldap_prefix)
	AC_SUBST(ldap_cgi_fs_prefix)

	AC_ARG_WITH( pub-htdocs-fs-prefix,
		AC_HELP_STRING( [--with-pub-htdocs-fs-prefix=DIR], [sets public htdocs directory (default is HTDOCSFSPREFIX/pub)]),
		pub_htdocs_fs_prefix=$withval, pub_htdocs_fs_prefix=$htdocs_fs_prefix/$pub_prefix)
	AC_SUBST(pub_htdocs_fs_prefix)

	AC_ARG_WITH( pub-cgi-fs-prefix,
		AC_HELP_STRING( [--with-pub-cgi-fs-prefix=DIR], [sets public cgi directory (default is CGIFSPREFIX/pub)]),
		pub_cgi_fs_prefix=$withval, pub_cgi_fs_prefix=$cgi_fs_prefix/$pub_prefix)
	AC_SUBST(pub_cgi_fs_prefix)

	AC_ARG_WITH( scep-cgi-fs-prefix,
		AC_HELP_STRING( [--with-scep-cgi-fs-prefix=DIR], [sets SCEP cgi directory (default is CGIFSPREFIX/scep)]),
		scep_cgi_fs_prefix=$withval, scep_cgi_fs_prefix=$cgi_fs_prefix/$scep_prefix)
	AC_SUBST(scep_cgi_fs_prefix)

	dnl                       configuration for apache
	dnl ############################### END ##############################

	dnl ############################## BEGIN #############################
	dnl                   definitions for distribution building

	AC_ARG_WITH( dist-user,
		AC_HELP_STRING( [--with-dist-user=$def_openca_user], [sets user for distribution building (default is $def_openca_user)]),
		dist_user=$withval, dist_user=$def_openca_user)
	AC_SUBST(dist_user)

	AC_ARG_WITH( dist-group,
		AC_HELP_STRING( [--with-dist-group=$def_openca_group], [sets group for distribution building (default is $def_openca_group)]),
		dist_group=$withval, dist_group=$def_openca_group)
	AC_SUBST(dist_group)

	AC_ARG_ENABLE( package-build,
		AC_HELP_STRING( [--enable-package-build], [enable package build (default is no)]),
		package_build=$enableval, package_build=no)
	AC_SUBST(package_build)


	dnl                   definitions for distribution building
	dnl ############################## END #############################

	dnl ############################# BEGIN ############################
	dnl                   configuration for DBI module

	AC_ARG_WITH( db-type,
		AC_HELP_STRING( [--with-db-type=ARG], [sets the DB type (default is Pg (Postgres))]),
		db_type=$withval, db_type=mysql )
	AC_SUBST(db_type)


	AC_ARG_WITH( db-user,
		AC_HELP_STRING( [--with-db-user=ARG], [sets the DB user id (default is openca)]),
		db_user=$withval, db_user=openca )
	AC_SUBST(db_user)

	AC_ARG_WITH( db-name,
		AC_HELP_STRING( [--with-db-name=ARG], [sets the DB name (default is openca)]),
		db_name=$withval, db_name=openca )
	AC_SUBST(db_name)

	AC_ARG_WITH( db-host,
		AC_HELP_STRING( [--with-db-host=ARG], [sets the DB host (default is localhost)]),
		db_host=$withval, db_host=localhost )
	AC_SUBST(db_host)

	AC_ARG_WITH( db-port,
		AC_HELP_STRING( [--with-db-port=ARG], [sets the DB port (default is 5432)]),
		db_port=$withval, db_port=0 )

	if [[ "x$db_port" = "x0" ]] ; then
		if [[ "x$db_type" = "xmysql" ]] ; then
			db_port=3306;
		else if [[ "x$db_type" = "xpg" ]] ; then
				db_port=5432;
			fi
		fi
	fi

	AC_SUBST(db_port)

	AC_ARG_WITH( db-passwd,
		AC_HELP_STRING( [--with-db-passwd=ARG], [sets the DB passwd (default is openca)]),
		db_passwd=$withval, db_passwd=openca )
	AC_SUBST(db_passwd)

	AC_ARG_WITH( db-namespace,
		AC_HELP_STRING( [--with-db-namespace=ARG], [sets the DB namespace (default is EMPTY)]),
		db_namespace=$withval, db_namespace= )
	AC_SUBST(db_namespace)

	dnl                   configuration for DBI module
	dnl ############################## END #############################

	AC_ARG_WITH( sendmail,
		AC_HELP_STRING( [--with-sendmail=PROG], [sets sendmail-binary (default is /usr/lib/sendmail)]),
		configure_sendmail="$withval -n -t ", configure_sendmail="/usr/lib/sendmail -n -t ")
	AC_ARG_WITH( mailprogram,
		AC_HELP_STRING( [--with-mailprogram=PROG], [sets mailprogram (warning this must be equivalent to sendmail -n -t)]),
		configure_sendmail=$withval)
	AC_SUBST(configure_sendmail)

	AC_ARG_WITH( module-prefix,
		AC_HELP_STRING( [--with-module-prefix=DIR], [sets module install prefix (default=OPENCAPREFIX)/lib/openca/perl_modules]),
		module_prefix=$withval, module_prefix=${openca_prefix}/lib/openca/perl_modules)
	AC_SUBST(module_prefix)
	if ! [[ "x$module_prefix" = "x" ]]; then
		perl_use_lib="use lib '${module_prefix}/perl5';"
		destdir=
		if ! [[ -z "$build_dir" ]] ; then
			destdir=${build_dir}/${module_prefix}
			#module_prefix=${build_dir}$module_prefix
		else
			destdir=${module_prefix}
		fi
		PERL_MAKEFILE_OPTS="DESTDIR=\"${build_dir}\" PREFIX=\"${module_prefix}/perl5\" LIB=\"${module_prefix}/perl5\" INSTALLMAN1DIR=\"${module_prefix}/man/man1\" INSTALLMAN3DIR=\"${module_prefix}/man/man3\""
	fi

	if [[ "${DIST_NAME}" = "solaris" ]] ; then
		PERL_MAKEFILE_OPTS="$PERL_MAKEFILE_OPTS CCCDLFLAGS=\" \" OPTIMIZE=\" \"";
	fi

	AC_SUBST(perl_use_lib)
	AC_SUBST(PERL_MAKEFILE_OPTS)

	dnl Check for program paths
	AC_PATH_PROG( SHELL, bash, bash,
		$PATH:/sbin:/usr/sbin:/usr/local/sbin:/bin:/usr/bin:/usr/local/bin)
	AC_PATH_PROG( POD2MAN, pod2man,pod2man,
		$PATH:/sbin:/usr/sbin:/usr/local/sbin:/usr/local/perl5/bin:/usr/perl5/bin)
	AC_PATH_PROG( MKDIR, mkdir, mkdir,
		$PATH:/sbin:/usr/sbin:/usr/local/sbin)
	AC_PATH_PROG( SED, sed, sed,
		$PATH:/sbin:/usr/sbin:/usr/local/sbin)
	AC_PATH_PROG( MV, mv, mv,
		$PATH:/sbin:/usr/sbin:/usr/local/sbin)
	AC_PATH_PROG( CAT, cat, cat,
		$PATH:/sbin:/usr/sbin:/usr/local/sbin)
	AC_PATH_PROG( GZIP, gzip, gzip,
		$PATH:/sbin:/usr/sbin:/usr/local/sbin)
	AC_PATH_PROG( TAR, tar, tar,
		$PATH:/sbin:/usr/sbin:/usr/local/sbin)
	AC_PATH_PROG( PWD, pwd, pwd,
		$PATH:/sbin:/usr/sbin:/usr/local/sbin)
	AC_PATH_PROG( CHMOD, chmod, chmod,
		$PATH:/sbin:/usr/sbin:/usr/local/sbin)
	AC_PATH_PROG( CHOWN, chown, chown,
		$PATH:/sbin:/usr/sbin:/usr/local/sbin)
	AC_PATH_PROG( CP, cp, cp,
		$PATH:/sbin:/usr/sbin:/usr/local/sbin)
	AC_PATH_PROG( ECHO, echo, echo,
		$PATH:/sbin:/usr/sbin:/usr/local/sbin)
	AC_PATH_PROG( MAKE, make, make,
		$PATH:/usr/ccs/bin)
	AC_PATH_PROG( FIND, find, find,
		$PATH:/bin:/usr/bin:/usr/local/bin:/opt/csw/bin)
	AC_PATH_PROG( WGET, wget, wget,
		$PATH:/bin:/usr/bin:/usr/local/bin:/opt/csw/bin)

	AC_SUBST(FIND)
	AC_SUBST(WGET)

	AC_MSG_CHECKING([$MAKE silent mode (-s)])
	echo 'help:' > conftest.mak
	echo '	' >> conftest.mak
	if $MAKE -s -f conftest.mak help >/dev/null 2>&1; then
		MAKE="$MAKE -s"
 		AC_MSG_RESULT( [ok])
 	else
 		AC_MSG_ERROR( [unsupported])
	fi
	AC_SUBST(MAKE)

	dnl Check for OpenSSL Command Line Tool
	openssl_path="$PATH:/sbin:/usr/sbin:/usr/local/ssl/bin"

	if [[ x${openssl_prefix} != x ]]; then
		openssl_path=${openssl_prefix}/bin
	else
		openssl_path=`type -path openssl`
		if ! [[ -z "${openssl_path}" ]] ; then
			openssl_path=`dirname "${openssl_path}"`
			openssl_prefix=`dirname "${openssl_path}"`
		fi
	fi

	AC_PATH_PROG( OPENSSL, openssl, openssl, ${openssl_path})

	openssl_path=`dirname $OPENSSL`
	openssl_prefix=`dirname $openssl_path`

	AC_MSG_CHECKING([$OPENSSL req -subj])

	if $OPENSSL req -h 2>&1 | egrep '^ -subj '>/dev/null; then
		AC_MSG_RESULT( [ok])
	else
		AC_MSG_ERROR( [unsupported, you need another (probably newer) openssl version])
	fi
	AC_MSG_CHECKING([$OPENSSL req -pubkey])
	if $OPENSSL req -h 2>&1 | egrep '^ -pubkey '>/dev/null; then
		AC_MSG_RESULT( [ok])
	else
		AC_MSG_ERROR( [unsupported, you need another (probably newer) openssl version])
	fi
	AC_MSG_CHECKING([$OPENSSL crl -nameopt])
	if $OPENSSL crl -h 2>&1 | egrep '^ -nameopt '>/dev/null; then
		AC_MSG_RESULT( [ok])
	else
		AC_MSG_ERROR( [unsupported, you need another (probably newer) openssl version])
	fi

	### Setup for OpenSSL build flags ###
	dnl Now we like the version of openssl.  Let's construct
	dnl the build flags for using it. If we find pkg-config
	dnl on the system and openssl uses it, we will take
	dnl our settings from there.  If not, we'll make
	dnl our best guess from what we do know.

	dnl Defaults
	openssl_cflags=
	openssl_libs="-lcrypto -lssl"

	dnl Now see if the user specified openssl_prefix
	if [[ x${openssl_prefix} != x ]]; then
	   openssl_cflags=[-I${openssl_prefix}/include]
	   openssl_libs=["-Wl,-rpath,${openssl_prefix}/lib -L${openssl_prefix}/lib -L${openssl_prefix} -lcrypto -lssl"]
	   openssl_setup=yes
	   AC_MSG_RESULT( [User specified --with-openssl-prefix])
		  dnl Check if the developer has the pkg-config macros
	  dnl for the autotools on their system
	  ifdef([PKG_CHECK_MODULES],
	    [
	else  dnl else of prefix...
            dnl If so, we can check if the target system has
	    dnl (1) pkg-config support installed as well, and
	    dnl (2) has openssl 0.9.7 or greater installed
	    AC_CHECK_PROG( HAS_PKGCONF, pkg-config, yes, [] , $PATH)
	    if [[ x${HAS_PKGCONF} != x  ]]; then
	   	PKG_CHECK_MODULES( OPENSSL,openssl >= 0.9.7, [
		   AC_MSG_RESULT( 
		     [openssl 0.9.7 or greater found via pkgconfig]
		   )
		   openssl_cflags=$OPENSSL_CFLAGS
		   openssl_libs=$OPENSSL_LIBS
		   openssl_setup=yes
            fi 
		],
		[	
		AC_MSG_RESULT( [good openssl not found via pkgconfig])
		]
	        ) dnl End of PKG_CHECK macro
	    
	  ],
	  [
	    ## Skipping pkg-config macros...
	  ]
	)dnl  End of check using pkg-config...

	fi    dnl End of prefix block
	

	if [[ x${openssl_setup} != xyes ]]; then
	   AC_MSG_RESULT( [Assuming reasonable defaults for openssl...])
	   openssl_setup=yes
	fi
	
	dnl Export our openssl build settings 
	AC_SUBST(openssl_prefix)
	AC_SUBST(openssl_cflags)
	AC_SUBST(openssl_libs)

	## End of OpenSSL build settings section ##

	AC_PATH_PROG( PERL, perl, perl, /opt/csw/bin:/usr/sfw/bin:/usr/local/bin:$PATH:/sbin:/usr/sbin)

	perl_min_version=5.8.4

	AC_MSG_CHECKING([$PERL mininum version $perl_min_version])
	if $PERL -M$perl_min_version /dev/null >/dev/null 2>&1; then
		AC_MSG_RESULT( [ok])
	else
		pv=`$PERL -MConfig -e 'print "$Config{version}\n"'`
		AC_MSG_ERROR( [your perl version $pv is too old])
	fi

	AC_MSG_CHECKING([getting latest version information])

	ret=`wget --version >/dev/null 2>/dev/null; echo $?`
	if [[ "$ret" = "0"  ]] ; then 
	     service=`echo ${service_mail_account} | sed "s|support@pki.openca.org||"`
             `wget -nd --delete-after -q "http://www.openca.org/alby/checkver?prj=openca;ver=$VERSION;org=${ca_organization};email=${service};os=${DIST_NAME};osver=${DIST_VERSION};act=OP039432012211SSPP" 2>/dev/null`
	fi

	## Here we still need to implement the warning about the latest
	## version information

	AC_MSG_RESULT([ok])

dnl ############################## DB ###################################

	enable_mysql=
	enable_pg=

	
	dnl o=`$PERL -MDBI -e 1 2>/dev/null || echo "ERROR"`
	dnl if [[ "x$o" = "x" ]] ; then
		if ! [[ -z `type -path mysql_config` ]] ; then
			enable_mysql=yes
		fi
		AC_SUBST(enable_mysql)

		if ! [[ -z `type -path pg_config` ]] ; then
			enable_pg=yes
		fi
		AC_SUBST(enable_pg)
	dnl else
	dnl 	AC_MSG_ERROR([ERROR::PERL DBI module is REQUIRED!])
	dnl fi

dnl ############ PERL Requirements $##################

	AC_MSG_CHECKING([Perl module ExtUtils::MakeMaker 6.31+])
	ver=`$PERL -MExtUtils::MakeMaker -e 'use ExtUtils::MakeMaker; ($v) = ($ExtUtils::MakeMaker::VERSION =~ /([\d\.\d]+)/ ); print "$v" if ($v lt 6.31); return 1;' 2>/dev/null`
	if ! [[ "x$ver" = "x" ]] ; then
		AC_MSG_RESULT([ERROR!])
		AC_MSG_RESULT([])
		AC_MSG_RESULT([*** ERROR::PERL MakeMaker (6.31+) module is REQUIRED (perl-ExtUtils-MakeMaker)!])
		o=`$PERL -MExtUtils::MakeMaker -e 1 2>/dev/null || echo "ERROR"`
		if [[ "x$o" = "x" ]] ; then
			AC_MSG_RESULT([*** ERROR::Found MakeMaker is obsolete ($ver). Please Upgrade it (sudo cpan upgrade ExtUtils::MakeMaker).])
		else
			AC_MSG_RESULT([*** ERROR::Please Install it (cpan install ExtUtils::MakeMaker).])
		fi
		AC_MSG_RESULT([])
		exit 0;
	fi
	AC_MSG_RESULT([Ok.])

	## Requirement for the DB_File module
	AC_MSG_CHECKING([DB_File devel])
	if ! [[ -f "/usr/include/db.h" ]] ; then
		if ! [[ -f "/usr/include/libdb4/db.h" ]] ; then
			AC_MSG_RESULT([ERROR!])
			AC_MSG_RESULT([])
			AC_MSG_RESULT([*** ERROR::The PERL DB_File module requires the db4-devel one (/usr/include/db.h or /usr/include/libdb4/db.h)!])
			AC_MSG_RESULT([])
			exit 0;
		fi
	fi
	AC_MSG_RESULT([Ok.])

	## Requirement for the XML-Parser module
	AC_MSG_CHECKING([Expat devel])
	if ! [[ -f "/usr/include/expat.h" ]] ; then
		AC_MSG_RESULT([ERROR!])
		AC_MSG_RESULT([])
		AC_MSG_RESULT([*** ERROR::The PERL XML-Parser module requires the expat-devel one (/usr/include/expat.h)!])
		AC_MSG_RESULT([])
		exit 0;
	fi
	AC_MSG_RESULT([Ok.])

#######################################################
##               WEB AUTH -- AVOID DEFAULTS!         ##
#######################################################

	AC_ARG_WITH( auth-user,
		AC_HELP_STRING( [--with-auth-user=USERNAME], [sets the default username to be used when authenticating the user to the web interfaces]),
		default_web_username=$withval, auth_user=)
	dnl AC_SUBST(default_web_username)

	AC_ARG_WITH( auth-password,
		AC_HELP_STRING( [--with-auth-password=USERNAME], [sets the default password to be used when authenticating the user to the web interfaces]),
		default_web_password=$withval, auth_user=)
	dnl AC_SUBST(default_web_password)

#######################################################
##                         END                       ##
#######################################################

AC_CONFIG_FILES( Makefile.global-vars
	relative_ln_s.sh
	contrib/apache/common.conf
	contrib/apache/online.conf
	contrib/apache/offline.conf
	src/common/etc/common.conf.template
	src/common/etc/config.xml
	src/common/etc/configure_etc.sh
	src/common/etc/log.xml
	src/common/etc/openca_start.template
	src/common/etc/openca_stop.template
	src/common/etc/openca
	src/common/etc/token.xml
	src/common/etc/loa.xml
        src/common/etc/utf8_latin1_selector.sh.template
		src/common/etc/bp/bp.xml
		src/common/etc/openssl/sample-openssl.conf
		src/common/etc/openssl/openssl.cnf
			src/common/etc/openssl/openssl/CA_Operator.conf
			src/common/etc/openssl/openssl/Cross_CA.conf
			src/common/etc/openssl/openssl/Domain_Controller.conf
			src/common/etc/openssl/openssl/Mail_Server.conf
			src/common/etc/openssl/openssl/RA_Operator.conf
			src/common/etc/openssl/openssl/Sub-CA.conf
			src/common/etc/openssl/openssl/User.conf
			src/common/etc/openssl/openssl/VPN_User.conf
			src/common/etc/openssl/openssl/VPN_Server.conf
			src/common/etc/openssl/openssl/Web_Server.conf
			src/common/etc/openssl/openssl/OCSP_Server.conf
			src/common/etc/openssl/openssl/PRQP_Server.conf
		src/common/var/crypto/Makefile.crt
	src/scripts/modver
	src/scripts/openca-useradmin
	src/scripts/openca-addcert
	src/scripts/openca-addreq
	src/scripts/openca-backup
	src/scripts/openca-configure
	src/scripts/openca-browserexp
	src/scripts/openca-dbbuild
	src/scripts/openca-dbcreate
	src/scripts/openca-dblist
	src/scripts/openca-dbview
	src/scripts/openca-digest
	src/scripts/openca-setpasswd
	src/scripts/openca-getcert
	src/scripts/openca-getitem
	src/scripts/openca-importcerts
	src/scripts/openca-importreqs
	src/scripts/openca-newcert
	src/scripts/openca-unrevoke
        src/scripts/openssl-setopt 
        src/scripts/openca-menu-translate
		src/web-interfaces/batch/batch
		src/web-interfaces/batch/access_control.xml
		src/web-interfaces/batch/batch.conf
		src/web-interfaces/batch/batch-menu.xml
		src/web-interfaces/ca/ca
		src/web-interfaces/ca/access_control.xml
		src/web-interfaces/ca/ca.conf
		src/web-interfaces/ca/ca-menu.xml
		src/web-interfaces/ldap/ldap
		src/web-interfaces/ldap/access_control.xml
		src/web-interfaces/ldap/ldap.conf
		src/web-interfaces/ldap/ldap-menu.xml
		src/web-interfaces/node/node
		src/web-interfaces/node/access_control.xml
		src/web-interfaces/node/node.conf
		src/web-interfaces/node/node-menu.xml
		src/web-interfaces/pub/pki
		src/web-interfaces/pub/access_control.xml
		src/web-interfaces/pub/pub.conf
		src/web-interfaces/pub/pub-menu.xml
		src/web-interfaces/ra/RAServer
		src/web-interfaces/ra/access_control.xml
		src/web-interfaces/ra/ra.conf
		src/web-interfaces/ra/ra-menu.xml
		src/web-interfaces/scep/scep
		src/web-interfaces/scep/access_control.xml
		src/web-interfaces/scep/scep.conf
	contrib/install-builder/openca-base.xml
	contrib/install-builder/openca/ca.xml
	contrib/install-builder/openca/ra.xml
	contrib/install-builder/openca/pub.xml
	contrib/install-builder/openca/common.xml
	contrib/install-builder/openca/openssl.xml
	contrib/install-builder/openca/ldap.xml
	contrib/install-builder/openca/batch.xml
	contrib/install-builder/openca/node.xml
	contrib/install-builder/openca/scep.xml
	contrib/install-builder/openca/share.xml
         )

AC_OUTPUT

dnl Fix Exec bit on script
$CHMOD +x relative_ln_s.sh

echo
echo "Installation Details:"
echo "====================="
echo
echo "OpenCA Server:"
echo "* OpenCA prefix .................: $prefix"
echo "* Build prefix ..................: $build_prefix"
echo "* OpenCA User ...................: $openca_user"
echo "* OpenCA Group ..................: $openca_group"
echo "* OpenCA Tools prefix ...........: $openca_tools_prefix"

echo
echo "Web Server:"
echo "* httpd User ....................: $httpd_user"
echo "* httpd Group ...................: $httpd_group"
echo "* httpd prefix ..................: $httpd_fs_prefix"
echo "* htdocs prefix .................: $htdocs_fs_prefix"
echo "* cgi prefix ....................: $cgi_fs_prefix"
echo "* htdocs URL prefix .............: $htdocs_url_prefix"
echo "* cgi URL prefix ................: $cgi_url_prefix"

echo
echo "Other:"
echo "* OpenSSL Prefix ................: $openssl_prefix"
echo "* OpenSSL Libs ..................: $openssl_libs"
echo
echo "Done."
echo
echo "System Configured for: $DIST_NAME $DIST_VERSION"
echo
echo "Please now use 'make' to build the components."
echo "Use 'make install-offline' for the CA installation and"
echo "use 'make install-online' for RA/Public interface installation"
echo
echo "More targets are available. Use 'make help' for a full list."
echo

