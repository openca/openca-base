## OpenCA::Configuration.pm 
##
## Copyright (C) 1998-1999 Massimiliano Pala (madwolf@openca.org)
## All rights reserved.
##
## This library is free for commercial and non-commercial use as long as
## the following conditions are aheared to.  The following conditions
## apply to all code found in this distribution, be it the RC4, RSA,
## lhash, DES, etc., code; not just the SSL code.  The documentation
## included with this distribution is covered by the same copyright terms
## 
## // Copyright remains Massimiliano Pala's, and as such any Copyright notices
## in the code are not to be removed.
## If this package is used in a product, Massimiliano Pala should be given
## attribution as the author of the parts of the library used.
## This can be in the form of a textual message at program startup or
## in documentation (online or textual) provided with the package.
## 
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions
## are met:
## 1. Redistributions of source code must retain the copyright
##    notice, this list of conditions and the following disclaimer.
## 2. Redistributions in binary form must reproduce the above copyright
##    notice, this list of conditions and the following disclaimer in the
##    documentation and/or other materials provided with the distribution.
## 3. All advertising materials mentioning features or use of this software
##    must display the following acknowledgement:
## //   "This product includes OpenCA software written by Massimiliano Pala
## //    (madwolf@openca.org) and the OpenCA Group (www.openca.org)"
## 4. If you include any Windows specific code (or a derivative thereof) from 
##    some directory (application code) you must include an acknowledgement:
##    "This product includes OpenCA software (www.openca.org)"
## 
## THIS SOFTWARE IS PROVIDED BY OPENCA DEVELOPERS ``AS IS'' AND
## ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
## ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
## FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
## DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
## OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
## HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
## LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
## OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
## SUCH DAMAGE.
## 
## The licence and distribution terms for any publically available version or
## derivative of this code cannot be changed.  i.e. this code cannot simply be
## copied and put under another distribution licence
## [including the GNU Public Licence.]
##
## Porpouse:
## =========
##
## Get easily configuration parameters passed into a config file
##
## Status:
## =======
##
##          Started: 10/11/1998
##    Last Modified: 28/04/1999
##

use strict;

package OpenCA::Configuration;

## $Revision: 1.2 $
$OpenCA::Configuration::VERSION = '1.5.3';

# Preloaded methods go here.

## Define Error Messages for the Configuration Manager Errors
my %params = {
	cnfLines => undef,
	cnfDB => undef,
};

## Create an instance of the Class
sub new {
	my $that = shift;
	my $class = ref($that) || $that;

	my $self = {
		%params,
	};

	bless $self, $class;

	my @keys = @_ ;
	my $fileName = $keys[0];

	if( defined $fileName and $fileName ne "" ) {
		my $ret = $self->loadCfg ( $fileName );
		return undef if ( not $ret );
	}

	return $self;
}

## Configuration Manager Functions
sub loadCfg {
	my $self = shift;
	my @keys = @_ ; 

	my $temp;
	my $temp2;
	my @configLines;
	my $sameLine;

	my $fileName = $keys[0];

	$sameLine = 0;
	$temp2 = "";
	open( FD, "$fileName" ) || return undef;
	while( $temp = <FD> ) {
		if( $temp =~ /\\\n$/ ) {
			$temp =~ s/\\\n$//;
			$temp2 .= $temp;
			$sameLine = 1;
		} else {
			if( $sameLine == 1 ) {
				$temp2 .= $temp;
				$temp = $temp2;
				$sameLine = 0;
				$temp2 = "";
			}

			$sameLine = 0;
			push ( @configLines, $temp);
		}
	}
	close(FD);

	if( $self->parsecfg( @configLines ) ) {
		$self->{cnfLines} = [ @configLines ];
		return 1;
	} else {
		return 0;
	}
}

## Parsing Function
sub parsecfg {
	my $self = shift;
	my @keys = @_;

	my @configDB = ();
	my $num = -1;
	my $line;
	
	foreach $line (@keys) {
		my $paramName;
		my %par;
		my @values;

		## Take count of Config Line Number
		$num++;

		## Trial line and discard Comments
		chop($line);
		## next if ($line =~ /\#.*/)||($line eq "")||($line =~ /HASH.*/);
		$line =~ s/([^\\]#.*)/$1/;
		# next if ($line =~ /^\#.*/)||($line =~ /^\s*[\n\r]*$/)||($line =~ /HASH.*/);
		next if ($line =~ /^\s*[\n\r]*$/)||($line =~ /HASH.*/);
		# $line =~ s/([^\\]#.*)/$1/;
		# $line =~ s/[^\\](#.*)//;
		$line =~ s/^[\s]*//;
		$line =~ s/(\r|\n)//g;

		## Get the Parameter Name
		( $paramName ) = 
			( $line =~ /([\S]+).*/ );

		## prepare the values to be parsed
		$line =~ s/$paramName// ; ## Erase the parameter Name from the Line
		$line =~ s/^[\s]*//;      ## Delete leading Spaces

		@values = ();

		## Start displacing command
		while ( length($line) > 0 ) {
			my ( $param, $match ); 

			if ( $line =~ /^\"/ ) {
			 	( $param ) = ( $line =~ /^\"(.*?)\"/ );
			 	$line =~ s/^\".*?\"//;
			} else {
			 	( $param ) = ( $line =~ /^([\S]+)/ );
			 	$line =~ s/^([\S]+)//;
			};

			@values = ( @values, $param );
			
			## Delete remaining Spaces
			$line =~ s/^[\s]*//;
		}

		## Get the parameter set up
		my $par = { NAME=>$paramName,
		 	 LINE_NUMBER=>$num,
		 	 VALUES=>[ @values ] };

		push ( @configDB, $par);
	}

	$self->{cnfDB} = [ @configDB ];
	return 1;
}

## Get Single Parameter
sub getParam {
	my $self = shift;
	my @keys = @_;

	return $self->getNextParam( NAME=>$keys[0],
		LINE_NUMBER=>-1 );
};

## Get next Parameter	 
sub getNextParam {
	my $self = shift;
        my $k = { @_ };
	my $par;

	return if( not ( $k->{NAME} ) );

	foreach $par ( @{$self->{cnfDB}} ) {
		my $tmp = $par->{NAME};

		if( (lc( $tmp ) eq lc($k->{NAME})) and
			( $par->{LINE_NUMBER} > $k->{LINE_NUMBER})  ) {
			return $par;
		};
	};

	return undef;
}

sub checkParam {
	my $self = shift;
	my $k = { @_ };
	my ( $par, $pnum );

	return unless ( exists $k->{NAME} );

	$par = $self->getParam( $k->{NAME} );
	return unless ( not ( keys %$par ));

	## $pnum = $#($par->{VALUES});

	if( ($k->{MIN}) && ($pnum < $k->{MIN}) ) {
		return $par->{LINE_NUMBER};
	}

 	if( ($k->{MAX}) && ($pnum > $k->{MAX}) ) {
		return $par->{LINE_NUMBER};
	}

	return 0;
}

sub checkConfig {
	my $self = shift;
	my @keys = @_;
	my ( $ret, $par );

	foreach $par ( @keys ) {
		$ret = $self->checkParam( $par );
		return if ( not $ret);
	}

	return 0;
}

sub getVersion {
	my $self = shift;

	return $OpenCA::Configuration::VERSION;
}

1;
