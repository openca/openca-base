## OpenCA::Session.pm 
##
## Written by Massimiliano Pala for the OpenCA project 2012
## Copyright (C) 1998-2012 The OpenCA Labs
## All rights reserved.
##

use strict;
use utf8;

package OpenCA::Session::CLI;

our ($DEBUG, $errno, $errval);

($OpenCA::Session::CLI::VERSION = '$Revision: 1.3 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

# Preloaded methods go here.

##
## supported functions
##
## new
## id
## param
## param_hashref
## save_param
## load_param
## sync_param
## clear
## flush
## close
## atime
## ctime
## expire
## remote_addr
## delete
## error
## dump
## header

## Create an instance of the Class
sub new
{
    my $that = shift;
    my $class = ref($that) || $that;

    my $self = {
			DEBUG     => 0,
			## debug_msg => ()
		};

    bless $self, $class;

		$self->{DSN} = shift;
		$self->{SID} = shift;
		$self->{HASHREF} = shift;

		$self->{params} = {};
		$self->{id} = {1};

    return $self;
}

sub DESTROY
{
	my $self = shift;

	$self->flush();
	$self->close();
}

sub id
{
	my $self = shift;
	print STDERR "OpenCA::Session::CLI::id()\n";
	return $self->{id};
}

sub param
{
	my $self = shift;
	my $keys = { @_ };

	my $name = shift;
	my $value = shift;

	print STDERR "OpenCA::Session::CLI::param()\n";

	if ($keys->{'-name'} ne "")
	{
		$name = $keys->{'-name'};
	}

	if ($keys->{'-value'} ne "")
	{
		$value = $keys->{'-value'};
	}

	if (($name ne "") and ($value ne ""))
	{
		print STDERR "OpenCA::Session::CLI::Setting $name => $value\n";
		$self->{params}->{$name} = $value;
	}
	elsif (($name ne "") and ($value eq ""))
	{
		print STDERR "OpenCA::Session::CLI::Returning $name => " . $self->{params}->{$name} . "\n";
		return $self->{params}->{$name};
	}
	else
	{
		return undef;
	}
}

sub param_hashref
{
	my $self = shift;
	print STDERR "OpenCA::Session::CLI::param_hashref()\n";
}

sub save_param
{
	my $self = shift;
	my $cgi = shift;
	my @arrayref = shift;

	print STDERR "OpenCA::Session::CLI::save_param($cgi, @arrayref)\n";
	if ($cgi)
	{
		for my $i ($cgi->param)
		{
		  $self->{params}->{$i} = $cgi->param($i);
		}
	}

	return(1);
}

sub load_param
{
	my $self = shift;
	my $cgi = shift;
	my @arrayref = shift;

	print STDERR "OpenCA::Session::CLI::load_param($cgi, @arrayref)\n";
}

sub sync_param
{
	my $cgi = shift;
	my @arrayref = shift;
	print STDERR "OpenCA::Session::CLI::sync_param()\n";
}

sub clear
{
	my $self = shift;
	print STDERR "OpenCA::Session::CLI::clear()\n";
}

sub flush
{
	my $self = shift;
	print STDERR "OpenCA::Session::CLI::flush()\n";
}

sub close
{
	my $self = shift;
	print STDERR "OpenCA::Session::CLI::close()\n";
}

sub atime
{
	my $self = shift;
	print STDERR "OpenCA::Session::CLI::atime()\n";
}

sub ctime
{
	my $self = shift;
	print STDERR "OpenCA::Session::CLI::ctime()\n";
}

sub expire
{
	my $self = shift;
	print STDERR "OpenCA::Session::CLI::expire()\n";
}

sub remote_addr
{
	my $self = shift;
	print STDERR "OpenCA::Session::CLI::remote_addr()\n";
}

sub delete
{
	my $self = shift;
	print STDERR "OpenCA::Session::CLI::delete()\n";
}

sub error
{
	my $self = shift;
	print STDERR "OpenCA::Session::CLI::error()\n";
}

sub dump
{
	my $self = shift;
	print STDERR "OpenCA::Session::CLI::dump()\n";
}

sub header
{
	my $self = shift;
	print STDERR "OpenCA::Session::CLI::header()\n";
}


1;
