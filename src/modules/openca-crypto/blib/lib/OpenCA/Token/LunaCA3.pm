## OpenCA::Token::LunaCA3.pm 
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

## OpenCA::OpenSSL includes code to support the Chrysalis-ITS token too
## errorcodes 713*  71 -> token ; 3 -> third implemented token

package OpenCA::Token::LunaCA3;

use OpenCA::OpenSSL;

our ($errno, $errval, $AUTOLOAD, $STDERR);
$STDERR = \*STDERR;

($OpenCA::Token::LunaCA3::VERSION = '$Revision: 1.1.1.1 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

# Preloaded methods go here.

## create a new LunaCA3 token
sub new {

   $ENV{'LD_LIBRARY_PATH'}=$ENV{'LD_LIBRARY_PATH'}.":/apps/usr/luna/lib";	
    my $that = shift;
    my $class = ref($that) || $that;

    my $self = {
                DEBUG     => 0,
                debug_fd  => $STDOUT,
                ## debug_msg => ()
               };

    bless $self, $class;

    my $keys = { @_ };
    $self->{DEBUG}     = $keys->{DEBUG};
    $self->{CRYPTO}    = $keys->{OPENCA_CRYPTO};
    $self->{gettext}   = $keys->{GETTEXT};
    $self->{NAME}      = $keys->{OPENCA_TOKEN};
    $self->{MODE}      = $keys->{TOKEN_MODE};
    $self->{UTILITY}   = $keys->{UTILITY};
    $self->{SLOT}      = $keys->{SLOT};
    $self->{APPID}     = $keys->{APPID};
    $self->{LOCK_FILE} = $keys->{LOCK_FILE};
    $self->{KEY}       = $keys->{KEY};
    return undef if (not $self->{CRYPTO});
    return undef if (not $self->{NAME});
    
    $keys->{ENGINE}  = "LunaCA3";

    if ($self->{MODE}=~ /^(SESSION|DAEMON)$/i)
    {
    	my $lower=1000;
    	my $upper=50000;
    	my $HiRandom = int(rand( $upper-$lower + 10000 ) ) + $lower;
    	my $LoRandom = int(rand ($upper -$lower + 1)) + $lower ;

    	my $AppID = "$HiRandom:$LoRandom";
#print "\n AppID = $HiRandom:$LoRandom\n";
	#$self->{APPID} = $AppID;
	$self->{APPID} = $keys->{APPID};;
	if (not $self->login()){
		$errno  = 7134014;
	        $errval = i18nGettext ("Cannot use the private key of the CA (__ERRNO__). __ERRVAL__",
                        "__ERRNO__", $self->errno(),
			"__ERRVAL__", $self->errval());
       		return undef;
    	}
	print "                 OK";
	$keys->{PRE_ENGINE} = " ENGINE_INIT:".   $self->{SLOT}.":".$self->{APPID};	

		
    }



    ## create openssl object
    # Chrysalis changed the OpenSSL patch to be more compliant with OpenSSL
    # we have no longer to send the slot and application ID
    #$keys->{ENGINE} = "LunaCA3 -enginearg ".
    #                  $self->{SLOT}.":".$self->{APPID};
    $keys->{KEYFORM} = "PEM";
    $self->debug ("initing OpenSSL");
    $self->{OPENSSL} = OpenCA::OpenSSL->new ( %{$keys} );
    $errno  = $OpenCA::OpenSSL::errno;
    $errval = $OpenCA::OpenSSL::errval;

    return undef if not $self->{OPENSSL};

    $self->debug ("module ready");
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

    print $STDERR "PKI Master Alert: OpenCA::Token::LunaCA3 error\n";
    print $STDERR "PKI Master Alert: Aborting all operations\n";
    print $STDERR "PKI Master Alert: Error:   $errno\n";
    print $STDERR "PKI Master Alert: Message: $errval\n";
    print $STDERR "PKI Master Alert: debugging messages of empty token follow\n";
    $self->{debug_fd} = $STDERR;
    $self->debug ();
    $self->{debug_fd} = $STDOUT;

    ## support for: return $self->setError (1234, "Something fails.") if (not $xyz);
    return undef;
}

## failover to default token OpenSSL which uses -engine
## see new to get an idea what is going on
sub AUTOLOAD {
    my $self = shift;

    $self->debug ("starting autoloader");
    if ($AUTOLOAD =~ /OpenCA::OpenSSL/)
    {
        $self->debug ("even openssl cannot handle this function");
        print STDERR "PKI Master Alert: OpenCA::OpenSSL is missing a function\n";
        print STDERR "PKI Master Alert: $AUTOLOAD\n";
#        $self->setError (666,
#            $self->{gettext} ("OpenCA::OpenSSL is missing a function. __FUNCTION__",
#                              "__FUNCTION__", $AUTOLOAD));
        return undef;
    }
    $self->debug ("OpenCA::Token::LunaCA3: AUTOLOAD => $AUTOLOAD");

    return 1 if ($AUTOLOAD eq 'OpenCA::Token::LunaCA3::DESTROY');

    $self->debug ("starting openssl");
    my $function = $AUTOLOAD;
    $function =~ s/.*:://g;
    my $ret = $self->{OPENSSL}->$function ( @_ );
    $self->setError ($OpenCA::OpenSSL::errno, $OpenCA::OpenSSL::errval);
    $self->debug ("openssl called");
    return $ret;
}

sub login {
    my $self = shift;
    $self->debug ("entering fucntion");

    my $keys = { @_ };

   if ( -e $self->{LOCK_FILE}) {
        return 1;
   }


    my $command = $self->{UTILITY};
    $command .= " -o ";
    $command .= " -s ".$self->{SLOT};
    $command .= " -i ".$self->{APPID};

	
    $self->debug ("executing login");
    my $ret = `$command`;
    if ($? != 0)
    {
        $self->setError ($?, $ret);
        $self->debug ("login failed");
        return undef;
    } else {
        $self->{ONLINE} = 1;
        $self->debug ("login succeeded");
	if ($self->{MODE} =~ /^(SESSION|DAEMON)$/i)
        {
            $self->debug ("touching session file");
            my $command = "touch ".$self->{LOCK_FILE};
            `$command`;
        }
        return 1;
    }
}

sub logout {
    my $self = shift;

    my $keys = { @_ };

    my $command = $self->{UTILITY};
    $command .= " -c ";
    $command .= " -s ".$self->{SLOT};
    $command .= " -i ".$self->{APPID};

    my $ret = `$command`;
    if ($? != 0)
    {
        $self->setError ($?, $ret);
        return undef;
    } else {
        $self->{ONLINE} = 0;
	unlink $self->{LOCK_FILE} if (-e $self->{LOCK_FILE});
        return 1;
    }
}

sub online {
    ## FIXME: how we can test a HSM to be online?
    ## FIXME: while we cannot test this we have no chance to
    ## FIXME: run this HSM in mode session or daemon
    my $self = shift;

    if ($self->{ONLINE} or -e $self->{LOCK_FILE}) {
        return 1;
    } else {
        return undef;
    }
}

sub keyOnline {
    my $self = shift;
    return $self->online;
}

sub getMode {
    my $self =  shift;
    return $self->{MODE};
}

sub genKey {
    my $self = shift;

    my $keys = { @_ };

    return $self->setError (7134012,
               $self->{gettext} ("You try to generate a key for a Chrysalis-ITS Luna CA3 token but you don't specify the number of bits."))
        if (not $keys->{BITS});

    return $self->setError (7134014,
               $self->{gettext} ("You try to generate a key for a Chrysalis-ITS Luna CA3 token but you don't specify the filename where to store the keyreference."))
        if (not $self->{KEY});
    my $command = $self->{UTILITY};
    $command .= " -s ".$self->{SLOT};
    $command .= " -i ".$self->{APPID};
    $command .= " -g ".$keys->{BITS};
    $command .= " -f ".$self->{KEY};
    my $ret = `$command`;
    if ($? != 0)
    {
        $self->setError ($?, $ret);
        return undef;
    } else {
        return 1;
    }
}

sub debug
{
    my $self     = shift;
    return 1 if (not $self->{DEBUG});
    my $msg      = shift;

    my ($package, $filename, $line, $subroutine, $hasargs,
        $wantarray, $evaltext, $is_require, $hints, $bitmask) = caller(0);
    $msg = "(line $line): $msg";

    ($package, $filename, $line, $subroutine, $hasargs,
     $wantarray, $evaltext, $is_require, $hints, $bitmask) = caller(1);
    $msg = "$subroutine $msg\n";

    print STDERR $msg;
}

1;
