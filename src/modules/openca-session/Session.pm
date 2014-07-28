## OpenCA::Session.pm 
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
use utf8;

package OpenCA::Session;

use OpenCA::Session::CGI;
use OpenCA::Session::CLI;

use CGI::Session qw/-ip-match/;
use OpenCA::Log::Message;

use FileHandle;

our ($errno, $errval);

($OpenCA::Session::VERSION = '$Revision: 1.4 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

# Preloaded methods go here.

##
## supported functions
##
## new
##
## load
## update
## start
## stop
## clear
## getID
##
## getParam
## setParam
## loadParams
## saveParams
##

## Create an instance of the Class
sub new {
    my $that = shift;
    my $class = ref($that) || $that;

    my $self = {
                DEBUG     => 0,
                ## debug_msg => ()
               };

    bless $self, $class;

    my $keys = { @_ };

		$self->{session_type} = "CGI";
    $self->{cgi}         = $keys->{CGI};
    $self->{lifetime}    = 1200;
    $self->{lifetime}    = $keys->{LIFETIME} if ($keys->{LIFETIME});
    $self->{DEBUG}       = 1 if ($keys->{DEBUG});
    $self->{dir}         = $keys->{DIR};
    $self->{journal}     = $keys->{LOG};
    $self->{gettext}     = $keys->{GETTEXT};

		$self->{session_type} = $keys->{TYPE} if ($keys->{TYPE} ne "");

    $self->{printed_header} = 0;

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

    $self->{journal}->{errno}   = $self->{errno};
    $self->{journal}->{errval}  = $self->{errval};
    $self->{journal}->{message} = "";
    foreach my $msg (@{$self->{debug_msg}}) {
        $self->{journal}->{message} .= $msg."\n";
    }

    ## support for: return $self->setError (1234, "Something fails.") if (not $xyz);
    return undef;
}

#####################################
## operate on the complete session ##
#####################################

sub load
{
	my $self = shift;
	my @params = ();

	if ($self->{session_type} eq "CGI")
	{
		if ($self->{cgi}->param ("CGISESSID"))
		{
			## Use the Param
			$self->{session} = OpenCA::Session::CGI->new(undef,
			 																		$self->{cgi}->param ("CGISESSID"),
			 																		{Directory=>$self->{dir}});
		}
		else
		{
			## Use the COOKIE
	 		return undef if (not $self->{cgi}->cookie("CGISESSID"));

			$self->{session} = OpenCA::Session::CGI->new(undef,
			 																		$self->{cgi}->cookie("CGISESSID"),
	     																		{Directory=>$self->{dir}});
		}
	}
	else
	{
		## Generate the new session object
		$self->{session} = new OpenCA::Session::CLI (undef, undef, {Directory => $self->{dir}});
	}

	return 1 if ($self->{session});

	## this can happen if the session is timed out
	return undef;
}

sub start
{
  my $self = shift;
	my $class = "OpenCA::Session::" . $self->{session_type};

  ## destroy old session if present
  if ($self->{session}) 
	{
    $self->{session}->delete;
    undef ($self->{session});
  }

	if ($self->{session_type} eq "CGI")
	{
		$self->{session} = new OpenCA::Session::CGI(undef, undef, {Directory=>$self->{dir}});
	}
	else
	{
		$self->{session} = new OpenCA::Session::CLI(undef, undef, {Directory=>$self->{dir}});
	}

  ## set lifetime
  $self->{session}->expire($self->{lifetime});

  ## store cookie
  $self->{session}->flush;

  ## prepare header
	if ($self->{cgi})
	{
  	$self->{cookie} = $self->{cgi}->cookie(CGISESSID => $self->{session}->id);

		## send header without content-type
  	if (not $self->{printed_header})
  	{
  	 	my $header = $self->{cgi}->header( -cookie=>$self->{cookie} );
  	 	$header =~ s/\n*Content-Type:[^\n]*\n*//s;
  	 	print $header;
  	 	$self->{printed_header} = 1;
  	}
	}

  return 1;
}

sub update 
{
    my $self = shift;

    ## set lifetime
    $self->{session}->expire($self->{lifetime});

    ## prepare header
		if ($self->{cgi})
		{
    	$self->{cookie} = $self->{cgi}->cookie(CGISESSID => $self->{session}->id);

    	## send header without content-type
    	if (not $self->{printed_header})
    	{
        my $header = $self->{cgi}->header( -cookie=>$self->{cookie} );
        my @lines = split "\n", $header;
        $header = "";
        foreach my $line (@lines) {
            $line = substr ($line, 0, length($line)-1);
            next if (not $line);
            next if ($line =~ /content-type/i);
            $header .= $line."\n";
        }
        print $header;
        $self->{printed_header} = 1;
    	}
		}
    $self->{session}->flush;

    return 1;
}

sub stop
{
    my $self = shift;

    $self->{session}->delete;
    undef ($self->{session});

    return 1;
}

sub clear
{
    my $self = shift;
    $self->{session}->clear();
}

sub getID
{
    my $self = shift;
    $self->{session}->id;
}

sub getType
{
	my $self = shift;
	return $self->{session_type};
}

######################
## param operations ##
######################

sub saveParams
{
	my $self = shift;

  $self->{session}->save_param ($self->{cgi});
  $self->{session}->flush;
}

sub loadParams
{
  my $self = shift;

  $self->{session}->load_param ($self->{cgi});
  $self->{session}->flush;
}

sub setParam
{
	my $self = shift;

  return $self->setError ("You cannot set a session parameter if there is no session created or loaded.", 123456)
        if (not exists $self->{session});
  $self->{session}->param ($_[0], $_[1]);
  $self->{session}->flush;
}

sub getParam
{
	my $self = shift;

	$self->{session}->param ($_[0]);
}

1;
