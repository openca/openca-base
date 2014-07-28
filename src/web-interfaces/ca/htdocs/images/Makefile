# file: src/web-interfaces/ca/htdocs/images/Makefile
#
# © 2001-2004 OpenCA Group

TOP	= ../../../../..
include $(TOP)/Makefile.global-vars

DEST_HTDOCS_IMGDIR	= ${ca_htdocs_fs_prefix}/images
IMGSRC			= $(TOP)/src/common/lib/images

FILES	= \
	openca_main_back_big_col_logo.png \
	openca_main_back_col_1.png \
	openca_main_back_col_2.png \
	big_openca_logo2.jpg	\
	digid_logo.gif		\
	info.png		\
	info-big.png		\
	info-big-2.png		\
	info-key.png		\
	bulb.png		\
	cert-icon.png		\
	back_item.png		\
	menu_left.png		\
	menu_right.png		\
	menu_center.png		\
	home.png		\
	notice_new.png		\
	message_new.png		\
	profileicon.png		\
	search.png		\
	logout.png		\
	top_logo.png		\
	top_back.png		\
	bottom_back.png		\
	notice_new_off.png	\
	message_new_off.png	\
	profileicon_off.png	\
	logout_off.png		\
	certicon_med.png  	\
	certicon_small.png	\
	certicon_small_off.png  \
	email_link.png		\
	print_link.png		\
	notSigned.png		\
	openca_logo.jpg		\
	openca-logo.png		\
	openca_logo2.jpg	\
	back_item.png		\
	home_back_1.png		\
	panel_back.png		\
	step_1.png		\
	step_2.png		\
	step_3.png		\
	sigError.png		\
	validSig.png

#---- variable settings above, rules below ----

.PHONY:	default install clean distclean

default::

$(DEST_HTDOCS_IMGDIR):
		$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=755 DIR=$@

install::	$(FILES)

$(FILES)::	$(DEST_HTDOCS_IMGDIR)
$(FILES)::
		$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $(IMGSRC)/$@ $(DEST_HTDOCS_IMGDIR)/$@

clean::
distclean::
		#$(RM)
