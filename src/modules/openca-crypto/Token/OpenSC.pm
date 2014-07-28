## OpenCA::Token::OpenSC.pm 
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
##        ============    LunaCA3 Token    =============     ##
###############################################################

## OpenCA::OpenSSL includes code to support the OpenSC token too
## errorcodes 714*  71 -> token ; 4 -> fourth implemented token

package OpenCA::Token::OpenSC;

use OpenCA::OpenSSL;

our ($errno, $errval);
our $AUTOLOAD;

($OpenCA::Token::OpenSC::VERSION = '$Revision: 1.1.1.1 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

# Preloaded methods go here.

## create a new OpenSC token
sub new {
    my $that = shift;
    my $class = ref($that) || $that;

    my $self = {
                DEBUG     => 0,
                ## debug_msg => ()
               };

    bless $self, $class;
    $self->{ONLINE} = 0;

    my $keys = { @_ };
    $self->{DEBUG}         = $keys->{DEBUG};
    $self->{gettext}       = $keys->{GETTEXT};
    $self->{CRYPTO}        = $keys->{OPENCA_CRYPTO};
    $self->{NAME}          = $keys->{OPENCA_TOKEN};
    $self->{PASSWD_PARTS}  = $keys->{PASSWD_PARTS};
    delete $keys->{OPENCA_CRYPTO};
    delete $keys->{OPENCA_TOKEN};
    delete $keys->{PASSWD_PARTS};

    ## daemon mode etc. is not supported for OpenSC until now
    #$self->{MODE}          = $keys->{TOKEN_MODE};

    ## this is the direct OpenSC stuff
    ## FIXME: pkcs11-tool is unusable because the keylength is hardcoded
    $self->{CARDDRIVER}     = $keys->{CARDDRIVER};
    $self->{CARDREADER}     = $keys->{CARDREADER};
    $self->{PKCS15_INIT}    = $keys->{PKCS15_INIT};
    $self->{PKCS15_TOOL}    = $keys->{PKCS15_TOOL};
    $self->{OPENSC_TOOL}    = $keys->{OPENSC_TOOL};

    return undef if (not $self->{CRYPTO});
    return undef if (not $self->{NAME});

    $keys->{DYNAMIC_ENGINE}   = 1;
    $keys->{GET_PIN_CALLBACK} = \&_get_pin_callback;
    $keys->{STDOUT_CALLBACK}  = \&_stdout_callback;
    $keys->{CALLBACK_HANDLER} = $self;

    ## create openssl object
    $self->debug ("new: initializing OpenCA::OpenSSL");
    $self->{OPENSSL}        = OpenCA::OpenSSL->new ( %{$keys} );
    if (not $self->{OPENSSL})
    {
        $self->setError ($OpenCA::OpenSSL::errno, $OpenCA::OpenSSL::errval);
        return undef;
    }
    $self->debug ("new: NAME ".$self->{NAME});
    $self->debug ("new: PASSWD_PARTS ".$self->{PASSWD_PARTS});
    $self->debug ("new: initialized OpenCA::OpenSSL");

    return $self;
}

sub setError {
    my $self = shift;

    if (scalar (@_) == 4) {
        my $keys = { @_ };
        $self->{errno}  = $keys->{ERRNO};
        $self->{errval} = $keys->{ERRVAL};
    } else {
        $self->{errno}  = $_[0];
        $self->{errval} = $_[1];
    }

    $errno  = $self->{errno};
    $errval = $self->{errval};

    return undef if (not $errno);

    print STDERR "PKI Master Alert: OpenCA::Token::OpenSC error\n";
    print STDERR "PKI Master Alert: Aborting all operations\n";
    print STDERR "PKI Master Alert: Error:   $errno\n";
    print STDERR "PKI Master Alert: Message: $errval\n";
    print STDERR "PKI Master Alert: debugging messages of empty token follow\n";

    ## support for: return $self->setError (1234, "Something fails.") if (not $xyz);
    return undef;
}

sub errno
{
    my $self = shift;
    return $self->{errno};
}

sub errval
{
    my $self = shift;
    return $self->{errval};
}

sub debug {
    my $self = shift;
    return 1 if (not $self->{DEBUG});
    print STDERR "OpenCA::Token::OpenSC->".$_[0]."\n";
    return 1;
}

## failover to default token OpenSSL which uses -engine
## see new to get an idea what is going on
sub AUTOLOAD {
    my $self = shift;

    if ($AUTOLOAD =~ /OpenCA::OpenSSL/)
    {
        print STDERR "PKI Master Alert: OpenCA::OpenSSL is missing a function\n";
        print STDERR "PKI Master Alert: $AUTOLOAD\n";
        $self->setError (666,
            $self->{gettext} ("OpenCA::OpenSSL is missing a function. __FUNCTION__",
                              "__FUNCTION__", $AUTOLOAD));
        return undef;
    }
    $self->debug ("OpenCA::Token::OpenSC: AUTOLOAD => $AUTOLOAD");

    return 1 if ($AUTOLOAD eq 'OpenCA::Token::OpenSC::DESTROY');

    my $function = $AUTOLOAD;
    $function =~ s/.*:://g;
    my $ret = $self->{OPENSSL}->$function ( @_ );
    $self->setError ($OpenCA::OpenSSL::errno, $OpenCA::OpenSSL::errval);
    return $ret;
}

sub login {
    my $self = shift;
    my @result = ($self->{CRYPTO}->getAccessControl())->getTokenParam (
                  $self->{NAME},
                  $self->{PASSWD_PARTS});
    $self->{PASSWD} = join '', @result;
    $self->{OPENSSL}->{PASSWD} = $self->{PASSWD};

    ## FIXME: I do not know how to verify a PIN with OpenSC :(

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

sub genKey {
    my $self = shift;

    my $keys = { @_ };
    my $command;
    my $ret;

    return $self->setError (7144012,
               $self->{gettext} ("You try to generate a key for an OpenSC token but you don't specify the number of bits."))
        if (not $keys->{BITS});
    return $self->setError (7144013,
               $self->{gettext} ("You must specify a passphrase."))
        if (not $self->{PASSWD});

    ## FIXME
    ##
    ## actually we cannot use PKCS#11 here because pkcs11-tool uses a fixed
    ## keylength what is inacceptable for OpenCA

    ## Let's describe what we are doing:
    ##   1. reader present
    ##   2. card ready and empty
    ##   3. erase card
    ##   4. init pkcs#15 stuff
    ##   5. generate private key

    ##   1. reader present

    $command = $self->{OPENSC_TOOL}." -l";
    $self->debug ("genReq: 1. step: $command");
    $ret = `$command`;
    if ($ret !~ /\n0\s+pcsc\s/)
    {
        $self->setError (7144020, $self->{gettext} ("No PCSC reader found."));
        return undef;
    }

    ##   2. card ready and empty

    $command = "$self->{PKCS15_TOOL} --list-keys --reader $self->{CARDREADER}";
    $self->debug ("genReq: 2. step: $command");
    $ret = `$command`;
    if ($ret =~ /Private RSA Key \[Private Key\]/)
    {
        $self->setError (7144030, $self->{gettext} ("Card is not empty."));
        return undef;
    }

    ##   3. erase card

    $command = "$self->{PKCS15_INIT} --erase-card -r $self->{CARDREADER} --use-default-transport-keys";
    $self->debug ("genReq: 3. step: $command");
    $ret = `$command`;
    if (not $ret)
    {
        $self->setError (7144035, $self->{gettext} ("Cannot erase card."));
        return undef;
    }
    
    ##   4. init pkcs#15 stuff

    $command = "$self->{PKCS15_INIT} --pin $self->{PASSWD} ".
                                    "--puk $self->{PASSWD} ".
                                    "--no-so-pin ".
                                    "--store-pin ".
                                    "--create-pkcs15 ".
                                    "--auth-id 0 ".
                                    "-r $self->{CARDREADER} ".
                                    "--use-default-transport-keys";
    $self->debug ("genReq: 4. step: $command");
    $ret = `$command`;
    if (not $ret)
    {
        $self->setError (7144040, $self->{gettext} ("Cannot initialize PKCS#15 struicture on card."));
        return undef;
    }

    ##   5. generate private key

    $command = "$self->{PKCS15_INIT} --generate-key rsa$keys->{BITS} ".
                                    "--auth-id 0 ".
                                    "-r $self->{CARDREADER} ".
                                    "--pin $self->{PASSWD} ".
                                    "--key-usage sign,decrypt";
    $self->debug ("genReq: 5. step: $command");
    $ret = `$command`;
    if (not $ret)
    {
        $self->setError (7144045, $self->{gettext} ("Keygeneration on card failed."));
        return undef;
    }

    return 1;
}

sub _get_pin_callback
{
    my $self = shift;

    ## if the user forget to ask for the PIN via login
    ## then we cannot handle it here

    if ($self->{PASSWD})
    {
        return "-pre PIN:".$self->{PASSWD};
    } else {
        return "";
    }
}

sub _stdout_callback
{
    my $self = shift;
    my $result = shift;

    ## remove leading OpenSSL> from engine call
    $result =~ s/^OpenSSL>\s//;
    ## remove all until OpenSSL>
    $result = substr $result, index $result, "OpenSSL> ";

    return $result
}

1;
