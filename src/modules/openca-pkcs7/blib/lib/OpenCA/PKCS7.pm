## OpenCA::PKCS7
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

## // the module's errorcode is 79
##
## functions
##
## new			11
## initSignature	12
## getParsed		21
## getSigner		22
## verifyChain		31
## parseDepth		32
## getSignature		23

use strict;
use Carp qw(cluck);
use X500::DN;

package OpenCA::PKCS7;

our ($errno, $errval);

($OpenCA::PKCS7::VERSION = '$Revision: 1.1.1.1 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

my %params = (
	 inFile => undef,
	 signature => undef,
	 dataFile => undef,
	 caCert => undef,
	 caDir => undef,
	 parsed => undef,
	 context => undef,
	 backend => undef,
	 status => undef,
	 statusStack => [],
	 nochain => undef,
         opaquesig => undef,
         ignoreErrors => undef,
         ignoreErrorsHash => undef,
);

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

## Create an instance of the Class
sub new {
	my $that = shift;
	my $class = ref($that) || $that;

        my $self = {
		%params,
	};

        bless $self, $class;

	my $keys = { @_ };
	my $tmp;

	$self->{gettext}    = $keys->{GETTEXT};
	return $self->setError (7911020, "OpenCA::PKCS7->new: The translation function must be specified.")
            if (not $self->{gettext});

        $self->{caCert}     = $keys->{CA_CERT};
        $self->{caDir}      = $keys->{CA_DIR};

        $self->{dataFile}   = $keys->{DATAFILE};
        $self->{data}       = $keys->{DATA};

	$self->{inFile}	    = $keys->{INFILE};
        $self->{signature}  = $keys->{SIGNATURE};

	$self->{backend}    = $keys->{SHELL};

	$self->{nochain}    = $keys->{NOCHAIN};
	$self->{opaquesig}  = $keys->{OPAQUESIGNATURE};

	$self->{ignoreErrors} = $keys->{IGNOREERRORS};


	# you can explicitly exclude certain error codes from being
	# returned. to use this features, call the constructor with the
	# error(s) to exclude:
	#
	# my $sig = new OpenCA::PKCS7(..., IGNOREERRORS => 26, ...)
	#
	# or to exclude more than one error:
	# my $sig = new OpenCA::PKCS7(..., IGNOREERRORS => [26, 18], ...)
	#

	# convert to arrayref if a scalar was passed in
	if (defined $self->{ignoreErrors} and not ref($self->{ignoreErrors})) {
	    $self->{ignoreErrors} = [ $self->{ignoreErrors} ];
	}
	$self->{ignoreErrors} = [] unless defined $self->{ignoreErrors};

	# nochain: ignore errors on selfsigned certs and incorrect key usage
	push(@{$self->{ignoreErrors}}, (18, 26)) if (exists $self->{nochain} and $self->{nochain});

	# create hash from the list of errors to ignore
	$self->{ignoreErrorsHash} = { map { $_, 1 } @{$self->{ignoreErrors}}};
	

	if( ($self->{inFile}) and ( -e "$self->{inFile}") ) {
		$self->{signature} = "";

		open(FD, "<$self->{inFile}" )
			or return $self->setError (7911021,
                                      $self->{gettext} ("OpenCA::PKCS7->new: Cannot open infile __FILENAME__ for reading.",
                                                        "__FILENAME__", $self->{inFile}));
		while ( $tmp = <FD> ) {
			$self->{signature} .= $tmp;
		}
		close(FD);
	};

	if( ($self->{dataFile}) and ( -e "$self->{dataFile}") ) {
		$self->{data} = "";

		open(FD, "<$self->{dataFile}" )
			or return $self->setError (7911023,
                                      $self->{gettext} ("OpenCA::PKCS7->new: Cannot open datafile __FILENAME__ for reading.",
                                                        "__FILENAME__", $self->{dataFile}));
		while ( $tmp = <FD> ) {
			$self->{data} .= $tmp;
		}
		close(FD);
	};

        if (not $self->{opaquesig} and not $self->{data} and $self->{inFile} and ( -e "$self->{inFile}")) {
		$self->{data} = "";

		open(FD, "<$self->{inFile}" )
			or return $self->setError (7911025,
                                      $self->{gettext} ("OpenCA::PKCS7->new: Cannot open infile __FILENAME__ for reading.",
                                                        "__FILENAME__", $self->{inFile}));
		while ( $tmp = <FD> ) {
			$self->{data} .= $tmp;
		}
		close(FD);
	};

	return $self->setError (7911031,
                   $self->{gettext} ("OpenCA::PKCS7->new: Cannot initialize signature (__ERRNO__). __ERRVAL__",
                                     "__ERRNO__", $self->errno,
                                     "__ERRVAL__", $self->errval))
		if (not $self->initSignature() );

        return $self;
}

sub initSignature {
	my $self = shift;
	my $keys = { @_ };
	my $tmp;

	return $self->setError (7912011,
                   $self->{gettext} ("OpenCA::PKCS7->initSignature: No signature specified."))
		if (not $self->{signature});
	return $self->setError (7912012,
                   $self->{gettext} ("OpenCA::PKCS7->initSignature: No data specified."))
		if (not $self->{data} and (not $self->{opaquesig}));

	if( $self->getParsed() ) {
		return 1;
	} else {
		return $self->setError (7912021,
                           $self->{gettext} ("OpenCA::PKCS7->initSignature: Cannot parse signature (__ERRNO__). __ERRVAL__",
                                             "__ERRNO__", $self->errno,
                                             "__ERRVAL__", $self->errval))
	}
}

sub getParsed {
	my $self = shift;
	my $keys = { @_ };

	my ( $ret, $tmp );

	$tmp = $self->{backend}->verify( SIGNATURE=>$self->{signature},
			OPAQUESIGNATURE => $self->{opaquesig},
			## old: DATA_FILE=>$self->{dataFile},
			DATA    => $self->{data},
			CA_CERT => $self->{caCert},
			CA_DIR  => $self->{caDir},
			VERBOSE => 1);
	print "OpenCA::PKCS7->getParsed: OpenCA::OpenSSL->verify returns:<br>\n".
	      $tmp."<br>\n"
		if ($self->{DEBUG});

	## why should verify the signature twice?
	#$tmp = $self->{backend}->verify( SIGNATURE=>$self->{signature},
	#		OPAQUESIGNATURE => $self->{opaquesig},
	#		DATA_FILE=>$self->{dataFile},
	#		NOCHAIN=>1,
	#		VERBOSE=>1 );

	if (not $tmp) {
	    if (not $self->{ignoreErrorsHash}->{$OpenCA::OpenSSL::errno}) {
		$self->setstatus($OpenCA::OpenSSL::errno);

		return $self->setError (7921021,
                           $self->{gettext} ("OpenCA::PKCS7->getParsed: The crypto-backend cannot verify the signature (__ERRNO__). __ERRVAL__",
                                             "__ERRNO__", $OpenCA::OpenSSL::errno,
                                             "__ERRVAL__", $OpenCA::OpenSSL::errval));
	    }
	}


	if ( not $ret = $self->parseDepth( DEPTH=>"0", DATA=>$tmp ) ) {
	    print STDERR "Error on output of openca-sv.\n$tmp\n";
	    if (not $self->{ignoreErrorsHash}->{$OpenCA::OpenSSL::errno}) {
		$self->setstatus($OpenCA::OpenSSL::errno);

		return $self->setError (7921031,
                           $self->{gettext} ("OpenCA::PKCS7->getParsed: Cannot parse the signer (__ERRNO__). __ERRVAL__",
                                             "__ERRNO__", $self->errno,
                                             "__ERRVAL__", $self->errval));
	    }
	}

	$self->{parsed}->{SIGNER} = $ret->{0};

	if ( ( $tmp ) and ( $ret = $self->parseDepth( DATA=>$tmp )) ) {
		$self->{parsed}->{CHAIN} = $ret;
	}

	$self->{parsed}->{SIGNER}->{CERTIFICATE} = 
		$self->{backend}->pkcs7Certs( PKCS7=>$self->{signature});
	if (not defined $self->{parsed}->{SIGNER}->{CERTIFICATE})
        {
		return $self->setError (7921033,
                           $self->{gettext} ("OpenCA::PKCS7->getParsed: The extraction of the certificates from the signature failed (__ERRNO__). __ERRVAL__",
                                             "__ERRNO__", $self->{backend}->errno,
                                             "__ERRVAL__", $self->{backend}->errval));
	}

	$self->{parsed}->{SIGNATURE} = $self->{signature};

	return $self->{parsed};
}

# returns the last status set by the module
# Options:
# FORMAT => ARRAY:
#   return arrayref containing an array of all error codes encountered,
#   individual error codes may appear more than once
# FORMAT => HASH:  
#   return hashref containing all error codes encountered (key: errorcode,
#   value: 1)
# FORMAT not set or other value: return last error
sub status {
        my $self = shift;
	my $keys = { @_ };

	if (exists $keys->{FORMAT} and $keys->{FORMAT} eq "ARRAY") {
	    return $self->{statusStack};
	} elsif (exists $keys->{FORMAT} and $keys->{FORMAT} eq "HASH") {
	    return { map { $_, 1 } @{$self->{statusStack}}};
	}
	
        return $self->{status};
}


# add one single error to the error stack
sub setstatus {
    my $self = shift;
    my $err = shift;
    
    $self->{status} = $err;
    if (ref($self->{statusStack}) eq "ARRAY") {
	push(@{$self->{statusStack}}, $err);
    } else {
	carp("self->{statusStack} is not an Arrayref");
    }
}


sub getSigner {
	my $self = shift;

	my $keys = { @_ };
	my ( $tmp, $ret );

	return $self->setError (7922011,
                   $self->{gettext} ("OpenCA::PKCS7->getSigner: The signature was not parsed."))
		if( not $self->{parsed} );
	return $self->{parsed}->{SIGNER};
}

sub verifyChain {
	my $self = shift;

	my $keys = { @_ };
	my ( $tmp, $ret );

	#unnecessary because the signature was already loaded
	#if ( $self->{inFile} ) {
	#	$tmp=$self->{backend}->verify( SIGNATURE_FILE => $self->{inFile},
        #                                      OPAQUESIGNATURE => $self->{opaquesig},
	#				       DATA           => $self->{data},
	#				       CA_CERT        => $self->{caCert},
	#				       CA_DIR         => $self->{caDir},
	#				       VERBOSE        => 1 );
	#} else {
		$tmp=$self->{backend}->verify( SIGNATURE => $self->{signature},
					       OPAQUESIGNATURE => $self->{opaquesig},
					       DATA      => $self->{data},
					       CA_CERT   => $self->{caCert},
					       CA_DIR    => $self->{caDir},
					       VERBOSE   => 1 );
	#};

	return $self->setError (7931021,
                   $self->{gettext} ("OpenCA::PKCS7->verifyChain: The crypto-backend fails (__ERRNO__). __ERRVAL__",
				     "__ERRNO__", $OpenCA::OpenSSL::errno,
                                     "__ERRVAL__", $OpenCA::OpenSSL::errval))
		if (not $tmp);

	## Returns if signature is not valid (verify returned an error)
	return $self->setError (7931022,
                   $self->{gettext} ("OpenCA::PKCS7->verifyChain: The crypto-backend fails."))
		if( $? != 0 );

	if ( not $ret = $self->parseDepth( DEPTH=>"0", DATA=>$tmp ) ) {
		print STDERR "Error on output of openca-sv.\n$tmp\n";
		return $self->setError (7931031,
                           $self->{gettext} ("OpenCA::PKCS7->verifyChain: Cannot parse the signer (__ERRNO__). __ERRVAL__",
                                             "__ERRNO__", $self->errno,
                                             "__ERRVAL__", $self->errval));
	}

	return $ret;
}

sub parseDepth {

	my $self = shift;
	my $keys = { @_ };

	my $depth = $keys->{DEPTH};
	my $data  = $keys->{DATA};
	my @dnList = ();
	my @ouList = ();

	my ( $serial, $dn, $email, $cn, @ou, $o, $c );
	my ( $currentDepth, $subject, $tmp, $line, $ret );
	
	return $self->setError (7932011,
                   $self->{gettext} ("OpenCA::PKCS7->parseDepth: No data specified."))
		if (not $data);

	my @lines = split ( /(\n|\r)/ , $data );

	while( $line = shift @lines ) {

		print "OpenCA::PKCS7->parseDepth: line: $line<br>\n"
			if ($self->{DEBUG});
		if ($line =~ /^\s*error:20:/i and 
		    not $self->{ignoreErrorsHash}->{20}) {
			$self->setError (7932021,
                            $self->{gettext} ("OpenCA::PKCS7->parseDepth: The chain is not complete."));
			$self->setstatus(20);
		} elsif ($line =~ /^\s*error:18:/i and
		    not $self->{ignoreErrorsHash}->{18}) {
		        $self->setError (7932023,
					 $self->{gettext} ("OpenCA::PKCS7->parseDepth: Selfsigned certificate at depth 0."));
			$self->setstatus(18);
		} elsif ($line =~ /^\s*error:26:/i and
		    not $self->{ignoreErrorsHash}->{26}) {
		        ## OpenCA uses CA certs to sign the role
		        $self->setError (7932025,
					 $self->{gettext} ("OpenCA::PKCS7->parseDepth: One of the certificates was used for a not allowed operation. Usually a CA certificate signed data or a normal certificate acts as a CA. (__ERRVAL__)",
							   "__ERRVAL__", $line));
			$self->setstatus(26);
		} elsif ($line =~ /^\s*error:([^:]*):/i and
		    not $self->{ignoreErrorsHash}->{$1}) {
			$self->setError (7932039,
                            $self->{gettext} ("OpenCA::PKCS7->parseDepth: There is a problem with the verification of the chain. (__ERRVAL__)",
                                              "__ERRVAL__", $line));
			$self->setstatus($1);
		}

		next if( $line !~ /^depth/i );

		( $currentDepth, $serial, $dn ) =
			( $line =~ /depth:([\d]+) serial:([a-fA-F\d]+) subject:(.*)/ );
		use Math::BigInt;
		my $serial_obj = Math::BigInt->new ('0x'.$serial);
		$ret->{$currentDepth}->{SERIAL} = $serial_obj->bstr();
		$ret->{$currentDepth}->{DN} = $dn;
		if ($self->{DEBUG})
		{
			print "OpenCA::PKCS7->parseDepth: depth: $currentDepth<br>\n";
			print "OpenCA::PKCS7->parseDepth: serial:".
			      $ret->{$currentDepth}->{SERIAL}."<br>\n";
			print "OpenCA::PKCS7->parseDepth: dn:".
			      $ret->{$currentDepth}->{DN}."<br>\n";
		}

		## Split the Subject into separate fields
		@dnList = split( /[\,\/]+/, $dn );
		@ouList = ();

		my $tmpOU;

		## load the differnt parts of the DN into DN_HASH
		print "OpenCA::PKCS7->parseDepth: DN: ".$dn."<br>\n" if ($self->{DEBUG});
		my $x500_dn = X500::DN->ParseRFC2253 ($dn);
		if (not $x500_dn) {
        		print "OpenCA::PKCS7->parseDepth: X500::DN failed<br>\n" if ($self->{DEBUG});
			return $self->setError (7932081,
                                   $self->{gettext} ("OpenCA::PKCS7->parseDepth: X500::DN failed."));
			return undef;
		}
		my $rdn;
		foreach $rdn ($x500_dn->getRDNs()) {
			next if ($rdn->isMultivalued());
			my @attr_types = $rdn->getAttributeTypes();
			my $type  = $attr_types[0];
			my $value = $rdn->getAttributeValue ($type);
			push (@{$ret->{$currentDepth}->{DN_HASH}->{uc($type)}}, $value);
			print "OpenCA::PKCS7->parseDepth: DN_HASH: $type=$value<br>\n" if ($self->{DEBUG});
		}

	}

	return $ret;
}

sub getSignature {
	my $self = shift;

	return $self->setError (7923011,
                   $self->{gettext} ("OpenCA::PKCS7->getSignature: There is no signature present."))
		if( not $self->{signature} );
	return $self->{signature};
}

sub getSignerCert {
	my $self = shift;

	my $keys = { @_ };


}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
