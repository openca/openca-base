
POT_PARTS	= \
	bp		\
	cmds		\
	menu		\
	functions	\
	modules

TRANSLATIONS = de_DE el_GR en_GB es_ES fr_FR it_IT ja_JP pl_PL sl_SI ru_RU pt_PT

POT_FILES	= $(POT_PARTS:%=%.pot)

default:	$(TRANSLATIONS)

$(TRANSLATIONS):	../openca.pot
	msgmerge --update ../$@/openca.po ../openca.pot
	rm -f ../$@/openca.po~
	msgfmt -o ../$@/openca.mo ../$@/openca.po

../openca.pot:	../openca-xgettext.pot ../openca-extra.pot
	msgcat -o $@ ../openca-xgettext.pot ../openca-extra.pot

../openca-xgettext.pot:	$(POT_PARTS)
	msgcat -o $@ $(POT_FILES)

$(POT_PARTS):
	## cleanup exclude files
	perl remove_perl.pl exclude_$@.pot > clean_exclude_$@.pot
	mv clean_exclude_$@.pot exclude_$@.pot
	## extract strings
	xgettext --language=perl --extract-all --exclude-file=exclude_$@.pot -o $@.pot -D ../../../..  -f ../files/$@.list
	## fix extracted stuff
	perl remove_revision.pl $@.pot > tmp.pot
	perl remove_perl.pl tmp.pot > $@.pot
	rm tmp.pot

