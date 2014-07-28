#!/bin/bash
#
# © 2001 by Massimiliano Pala and OpenCA Group

ECHO=echo
CHOWN=chown
RM=rm
MV=mv
TAR=tar
GZIP=gzip
SED=sed

VER=0.9.3
C_DIR=`pwd | ${SED} "s|/.*/||g"`
G_DIR=`pwd`

${ECHO}
${RM} -f OpenCA-Base-*${VER}.tar.gz
${ECHO} "Creating Distribution TAR archive ${C_DIR} ... ${G_DIR}"
${CHOWN} -R madwolf.openca *;
( cd ..; ${MV} ${C_DIR} OpenCA-Base-${VER} ; \
	${TAR} cpf OpenCA-Base-${VER}.tar --exclude "CVS" OpenCA-Base-${VER};\
	${GZIP} OpenCA-Base-${VER}.tar;\
	${MV} OpenCA-Base-${VER} ${C_DIR} );
${MV} ../OpenCA-Base-${VER}.tar.gz .;
${ECHO} "Done.";
${ECHO}

