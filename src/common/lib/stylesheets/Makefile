# file: src/common/lib/stylesheets/Makefile
#
# © 2001 OpenCA Group

TOP	= ../../../..
include $(TOP)/Makefile.global-vars

DEST_CGI_LIBDIR	= ${lib_prefix}/stylesheets

LIBS	= \
	default.css \
	openca-home-2.css \
	main-openca.css \
	menu-openca.css \
	dynmenu-openca.css

#---- variable settings above, rules below ----

.PHONY:	default test install clean distclean

default::

test::

$(DEST_CGI_LIBDIR):
		$(MAKE) __install_dir USER=${openca_user} GROUP=${openca_group} MODE=755 DIR=$@

install::	$(LIBS)

$(LIBS)::	$(DEST_CGI_LIBDIR)
$(LIBS)::
		$(INSTALL) -o ${openca_user} -g ${openca_group} -m 644 $@ $(DEST_CGI_LIBDIR)/$@

clean::
distclean::
		#$(RM)
