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
DAY=`/bin/date +%Y%m%d`
C_DIR=`pwd | ${SED} "s|/.*/||g"`
G_DIR=`pwd`

${ECHO}
${RM} -f OpenCA-SNAP-*${DAY}.tar.gz
${ECHO} "Creating Distribution TAR archive ${C_DIR} ... ${G_DIR}"
${CHOWN} -R madwolf.openca *;
( cd ..; ${MV} ${C_DIR} OpenCA-SNAP-${DAY} ; \
	${TAR} cpf OpenCA-SNAP-${DAY}.tar --exclude "CVS" OpenCA-SNAP-${DAY};\
	${GZIP} OpenCA-SNAP-${DAY}.tar;\
	${MV} OpenCA-SNAP-${DAY} ${C_DIR} );
${MV} ../OpenCA-SNAP-${DAY}.tar.gz .;
${ECHO} "Done.";
${ECHO}

