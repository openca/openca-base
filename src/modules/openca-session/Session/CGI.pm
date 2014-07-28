## OpenCA::Session.pm 
##
## Written by Massimiliano Pala for the OpenCA project 2012
## Copyright (C) 1998-2012 The OpenCA Labs
## All rights reserved.
##

use strict;
use utf8;

use CGI::Session qw/-ip-match/;
package OpenCA::Session::CGI;

our ($errno, $errval);

($OpenCA::Session::CGI::VERSION = '$Revision: 1.2 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

@OpenCA::Session::CGI::ISA = ( @OpenCA::Session::CGI::ISA, "CGI::Session" );
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
#
use FileHandle;
our ($STDERR, $STDOUT);
$STDOUT = \*STDOUT;
$STDERR = \*STDERR;


# Preloaded methods go here.
# sub new
# {
# 	my $that = shift;
# 
# 	return CGI::Session->new(@_);
# }

1;

