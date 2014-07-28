#!/bin/sh

TOP=../../../../../

FILTER_DIR=grep -E "[^/]$$"
FILTER_CVS=grep -E "/[^\/]{4,}$$"
FILTER_MAKEFILE=grep -E "/(.{1,7}|[^M][^a][^k][^e][^f][^i][^l][^e]|[^/]{9,})$$"

##  WARNING
##  interfaces are NOT translateable !!!

LISTS =	\
	bp.list		\
	cmds.list	\
	menu.list	\
	functions.list	\
	modules.list

default:	openca.files

cmds.list:	$(TOP)/src/common/lib/cmds
	cd $(TOP)/src; find common/lib/cmds/ -print -maxdepth 1 | \
	$(FILTER_DIR) | $(FILTER_CVS) | $(FILTER_MAKEFILE) > common/lib/locale/files/tmp.list
	perl order_files.pl tmp.list > $@

openca.files:	$(LISTS)
	cat $(LISTS) > openca.list
	perl order_files.pl openca.list > openca.files
	rm openca.list
