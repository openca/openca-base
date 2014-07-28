## OpenCA::Token::OpenSSL.pm 
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
##        ============    OpenSSL Token    =============     ##
###############################################################

package OpenCA::Token::OpenSSL;

use OpenCA::OpenSSL;

our ($errno, $errval);

($OpenCA::Token::OpenSSL::VERSION = '$Revision: 1.2 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

# Errorcode prefix: 711*
# 71 token modules
# 1  first implemented token

# Preloaded methods go here.

## create a new OpenSSL tokens
sub new {
    my $that = shift;
    my $class = ref($that) || $that;

    my $self = {
                DEBUG     => 0,
               };

    bless $self, $class;

    $self->debug ("new: class instantiated");

    my $keys = { @_ };
    $self->{CRYPTO}       = $keys->{OPENCA_CRYPTO};
    $self->{gettext}      = $keys->{GETTEXT};
    $self->{NAME}         = $keys->{OPENCA_TOKEN};
    ## TOKEN_MODE will be ignored
    $self->{PASSWD_PARTS} = $keys->{PASSWD_PARTS};
    ## FIXME: I hope this fixes @_
    delete $keys->{OPENCA_CRYPTO};
    delete $keys->{OPENCA_TOKEN};
    delete $keys->{PASSWD_PARTS};
    return $self->setError (7111010,
               $self->{gettext} ("Crypto layer is not defined."))
        if (not $self->{CRYPTO});
    return $self->setError (7111012,
               $self->{gettext} ("The name of the token is not defined."))
        if (not $self->{NAME});

    $self->debug ("new: crypto and name present");

    $self->{OPENSSL} = OpenCA::OpenSSL->new ( %{$keys} );
    return $self->setError ($OpenCA::OpenSSL::errno, $OpenCA::OpenSSL::errval)
        if (not $self->{OPENSSL});

    $self->debug ("new: NAME ".$self->{NAME});
    $self->debug ("new: PASSWD_PARTS ".$self->{PASSWD_PARTS});

    return $self;
}

sub setError {
    my $self = shift;

    if (scalar (@_) == 4) {
        my $keys = { @_ };
        $self->{errval} = $keys->{ERRVAL};
        $self->{errno}  = $keys->{ERRNO};
    } else {
        $self->{errno}  = $_[0];
        $self->{errval} = $_[1];
    }
    $errno  = $self->{errno};
    $errval = $self->{errval};

    ## FIXME: this is usually a bug
    return undef if (not $self->{errno});

    $self->debug ("setError: errno $errno");
    $self->debug ("setError: errval $errval");

    ## support for: return $self->setError (1234, "Something fails.") if (not $xyz);
    return undef;
}

sub errno {
    my $self = shift;
    return $self->{errno};
}

sub errval {
    my $self = shift;
    return $self->{errval};
}

sub debug {

    my $self = shift;

    return 1 if (not $self->{DEBUG});

    foreach my $msg (@_) {
        print STDERR "OpenCA::Token::OpenSSL->$msg\n";
    }
}

sub login
{
	my $self = shift;

	$self->debug("login->started.");

	if ($_[0])
	{
		$self->debug("login->password is: " . $_[0]);
		$self->{PASSWD} = shift;
	}
	else
	{

		$self->debug("login()->getting Token Params");
		$self->debug("login()->CRYPTO => " . $self->{CRYPTO});

		my $ac = $self->{CRYPTO}->getAccessControl();
		$self->debug("login()->getAccessControl => $ac");

		my @result = $ac->getTokenParam($self->{NAME}, $self->{PASSWD_PARTS});
		$self->debug("login()->got password parts-> @result");
		$self->{PASSWD} = join '', @result;
	}

	$self->{OPENSSL}->{PASSWD} = $self->{PASSWD};

	$self->debug("login()->PASSWORD-> " . $self->{PASSWD});

	if (not $self->{OPENSSL}->dataConvert (DATATYPE => "KEY", OUTFORM=>"PKCS8"))
	{
		$self->debug("login()->Wrong passphrase for private key!");

		return $self->setError (7113050,
							$self->{gettext} ("Wrong passphrase for private key!"))
	};

	$self->debug("login()->All Ok, Token is Online!");

	$self->{ONLINE} = 1;
	return 1;
}

sub logout {
    my $self = shift;
    undef $self->{PASSWD};
    undef $self->{OPENSSL}->{PASSWD};
    $self->{ONLINE} = 0;
    return 1;
}

sub online {
    my $self = shift;
    return 1;
}

sub keyOnline {
    my $self = shift;
    return undef if (not $self->{ONLINE});
    return 1;
}

sub getMode {
    return "standby";
}

## map functions manually to avoid memeory leaks from Perl

sub getDigest
{
    my $self = shift;
    my $ret = return $self->{OPENSSL}->getDigest(@_);
    $self->setError ($self->{OPENSSL}->errno, $self->{OPENSSL}->errval)
        if (not defined $ret);
    return $ret;
}

sub getPIN
{
    my $self = shift;
    my $ret = return $self->{OPENSSL}->getPIN(@_);
    $self->setError ($self->{OPENSSL}->errno, $self->{OPENSSL}->errval)
        if (not defined $ret);
    return $ret;
}

sub encrypt
{
    my $self = shift;
    my $ret = return $self->{OPENSSL}->encrypt(@_);
    $self->setError ($self->{OPENSSL}->errno, $self->{OPENSSL}->errval)
        if (not defined $ret);
    return $ret;
}

## use OpenSSL by default but take care about the errorcodes
sub AUTOLOAD {
    my $self = shift;
    use vars qw($AUTOLOAD);

    if ($AUTOLOAD =~ /OpenCA::OpenSSL/)
    {
        print STDERR "PKI Master Alert: OpenCA::OpenSSL is missing a function\n";
        print STDERR "PKI Master Alert: $AUTOLOAD\n";
        $self->setError (666,
            $self->{gettext} ("OpenCA::OpenSSL is missing a function. __FUNCTION__",
                              "__FUNCTION__", $AUTOLOAD));
        return undef;
    }
    $self->debug ("OpenCA::Token::OpenSSL: AUTOLOAD => $AUTOLOAD");

    return 1 if ($AUTOLOAD eq 'OpenCA::Token::OpenSSL::DESTROY');

    my $function = $AUTOLOAD;
    $function =~ s/.*:://g;
    my $ret = $self->{OPENSSL}->$function ( @_ );
    $self->setError ($OpenCA::OpenSSL::errno, $OpenCA::OpenSSL::errval) if (not defined $ret);
    return $ret;
}

1;
