## OpenCA::Token::Empty.pm 
##
## Written by Michael Bell for the OpenCA project 2003
## Copyright (C) 2003-2004 The OpenCA Project
## All rights reserved.
##
##    This library is free software; you can redistribute it and/or
##    modify it under the terms of the GNU Lesser General Public
##    License as published by the Free Software Foundation; either
##    version 2.1 of the License, or (at your option) any later version.
##
##    This library is distributed in the hope that it will be useful,
##    but WITHOUT ANY WARRANTY; without even the implied warranty of
##    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
##    Lesser General Public License for more details.
##
##    You should have received a copy of the GNU Lesser General Public
##    License along with this library; if not, write to the Free Software
##    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
##

use strict;

###############################################################
##        ============    Empty Example    =============     ##
###############################################################

package OpenCA::Token::Empty;

our ($errno, $errval);

($OpenCA::Token::Empty::VERSION = '$Revision: 1.1.1.1 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

# Preloaded methods go here.

## Create an instance of the Class
sub new {
    my $that = shift;
    my $class = ref($that) || $that;

    my $self = {
                DEBUG     => 0,
               };

    bless $self, $class;

    my $keys = { @_ };
    $self->{CRYPTO} = $keys->{OPENCA_CRYPTO};
    return undef if (not $self->{CRYPTO});

    return $self;
}

sub setError {
    my $self = shift;

    if (scalar (@_) == 4) {
        my $keys = { @_ };
        $errval = $keys->{ERRVAL};
        $errno  = $keys->{ERRNO};
    } else {
        $errno  = $_[0];
        $errval = $_[1];
    }

    return undef if (not $errno);

    $self->debug ("setError: $errno: $errval");

    ## support for: return $self->setError (1234, "Something fails.") if (not $xyz);
    return undef;
}

sub debug {

    my $self = shift;

    return 1 if (not $self->{DEBUG});

    foreach my $msg (@_) {
        print STDERR "OpenCA::Crypto->$msg\n";
    }

    return 1;
}

## failover to default token
sub AUTOLOAD {
    my $self = shift;
    use vars qw($AUTOLOAD);

    $self->debug ("OpenCA::Token::EMPTY: AUTOLOAD => $AUTOLOAD");

    return 1 if ($AUTOLOAD eq 'OpenCA::Token::EMPTY::DESTROY');

    my $function = $AUTOLOAD;
    $function =~ s/.*:://g;
    my $ret = $self->{CRYPTO}->$function ( @_ );
    $self->setError ($OpenCA::OpenSSL::errno, $OpenCA::OpenSSL::errval) if (not defined $ret);
    return $ret;
}

1;
