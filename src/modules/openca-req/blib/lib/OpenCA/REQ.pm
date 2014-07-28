## OpenCA::REQ
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

## moduleerrorcode is 72
##
## functions:
##
## new		11
## init		12
## getParsed	21
## getHeader	31
## getSignature	32
## getKey	33
## getBody	34
## getRawHeader	35
## parseReq	13
## getTXT	41
## getPEM	42
## getDER	43
## getItem	51
## getSerial	52
## setParams    61

use strict;
use Digest::MD5;
use X500::DN;

package OpenCA::REQ;

our ($errno, $errval);

($OpenCA::REQ::VERSION = '$Revision: 1.9 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

my %params = (
	req            => undef,
	item           => undef,
	pemREQ         => undef,
	derREQ         => undef,
	txtREQ         => undef,
	spkacREQ       => undef,
	revokeREQ      => undef,
	parsedSPKAC    => undef,
	parsedCRR      => undef,
	parsedItem     => undef,
	backend        => undef,
	beginHeader    => undef,
	endHeader      => undef,
	beginSignature => undef,
	endSignature   => undef,
	beginKey       => undef,
	endKey         => undef,
	beginAttribute => undef,
	endAttribute   => undef,
	reqFormat      => undef,
);

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

	## support for: return $self->setError (1234, "Something fails.") if (not $xyz);
	return undef;
}

sub new {
	my $that = shift;
	my $class = ref($that) || $that;

	my $self = {
		%params,
	};

        bless $self, $class;

	$self->{beginHeader} 	= "-----BEGIN HEADER-----";
	$self->{endHeader} 	= "-----END HEADER-----";
	$self->{beginSignature} = "-----BEGIN PKCS7-----";
	$self->{endSignature} 	= "-----END PKCS7-----";
	$self->{beginKey}	= "-----BEGIN .*PRIVATE KEY-----";
	$self->{endKey} 	= "-----END .*PRIVATE KEY-----";
	$self->{beginAttribute}	= "-----BEGIN ATTRIBUTE-----";
	$self->{endAttribute}	= "-----END ATTRIBUTE-----";
	$self->{reqFormat}      = "";

        my $keys = { @_ };
        my ( $infile, $keyfile, $tmp );

        $self->{req}       = $keys->{DATA};
        $self->{reqFormat} = ( $keys->{FORMAT} or $keys->{INFORM} );

        $self->{backend}    = $keys->{SHELL};
        $self->{gettext}    = $keys->{GETTEXT};
        $infile     = $keys->{INFILE};
	$keyfile    = $keys->{KEYFILE};
	
	return $self->setError (7211010, "OpenCA::REQ->new: The translation function is not specified.")
            if (not $self->{gettext});
	return $self->setError (7211011,
            $self->{gettext} ("OpenCA::REQ->new: The backend is not specified."))
            if (not $self->{backend});

	if( $keyfile ) {
		if ( not defined $self->{reqFormat} or not $self->{reqFormat} ) {
			$self->{reqFormat} = "PEM";
		}
		$self->{req} = $self->{backend}->genReq( 
				  KEYFILE=>$keys->{KEYFILE},
				  DN=>$keys->{DN},
				  SUBJECT=>$keys->{SUBJECT},
				  OUTFORM=>$self->{reqFormat},
				  PASSWD=>$keys->{PASSWD} );

		return $self->setError (7211021,
			   $self->{gettext} ("OpenCA::REQ->new: Cannot create new request. Backend fails with errorcode __ERRNO__. __ERRVAL__",
                                             "__ERRNO__", $OpenCA::OpenSSL::errno,
			                     "__ERRVAL__", $OpenCA::OpenSSL::errval))
			if ( not $self->{req} );
	}

	if( $infile ) {
                $self->{req} = "";

                open(FD, "<$infile" ) or
			return $self->setError (7211031,
			           $self->{gettext} ("OpenCA::REQ->new: Cannot open infile __FILENAME__ for reading.",
                                                     "__FILENAME__", $infile));
                while ( $tmp = <FD> ) {
                        $self->{req} .= $tmp;
                }
                close(FD);

		return $self->setError (7211033,
                           $self->{gettext} ("Cannot read request from infile __FILENAME__.",
                                             "__FILENAME__", $infile))
			if( not $self->{req});
        }

	if( not (defined($self->{reqFormat})) or ($self->{reqFormat} eq "")) {
		if( ( $self->{req} ) and ( $self->{req} =~ /SPKAC\s*=\s*/g ) ){
			$self->{reqFormat} = "SPKAC";
		} elsif (($self->{req}) and ($self->{req} =~ 
					/REVOKE_CERTIFICATE_SERIAL\s*=\s*/g)){
                	$self->{reqFormat} = "CRR";
		} else {
                	$self->{reqFormat} = "PEM";
		}
        }

        if ( $self->{req} ne "" ) {
		$self->{item} = $self->{req};

                if ( not $self->init( REQ=>$self->{req},
                                          FORMAT=>$self->{reqFormat})) {
			return $self->setError (7211041,
			           $self->{gettext} ("OpenCA::REQ->new: Cannot initialize request (__ERRNO__). __ERRVAL__",
                                                     "__ERRNO__", $errno,
                                                     "__ERRVAL__", $errval));
                }

        }

        return $self;
}

sub init {
        my $self = shift;
        my $keys = { @_ };

        $self->{reqFormat} 	= $keys->{FORMAT};
	$self->{req}		= $self->getBody( REQUEST=> $keys->{REQ});

	if (not $self->{req}) {
       		$self->{parsedItem} = $self->parseReq( REQ=>$keys->{REQ},
						FORMAT=>$self->{reqFormat} );
		return $self->setError (7212011,
                           $self->{gettext} ("OpenCA::REQ->init: Cannot parse request (__ERRNO__). __ERRVAL__",
                                             "__ERRNO__", $errno,
                                             "__ERRVAL__", $errval))
			if (not $self->{parsedItem});
	} elsif( $self->{reqFormat} !~ /SPKAC|CRR/i ) {
		$self->{pemREQ} = "";
		$self->{derREQ} = "";
		$self->{txtREQ} = "";

		$self->{parsedItem} = $self->parseReq( REQ=>$keys->{REQ},
						FORMAT=>$self->{reqFormat} );
		return $self->setError (7212024,
                           $self->{gettext} ("OpenCA::REQ->init: Cannot parse request (__ERRNO__). __ERRVAL__",
                                             "__ERRNO__", $errno,
                                             "__ERRVAL__", $errval))
			if (not $self->{parsedItem});
	} else {

		if ( $self->{reqFormat} =~ /SPKAC/ ) {
			$self->{spkacREQ} = $self->{req};
        		$self->{parsedSPKAC}=$self->parseReq( REQ=>$keys->{REQ},
							FORMAT=>"SPKAC" );
			$self->{parsedItem} = $self->{parsedSPKAC};

			return $self->setError (7212026,
                           $self->{gettext} ("OpenCA::REQ->init: Cannot parse request (__ERRNO__). __ERRVAL__",
                                             "__ERRNO__", $errno,
                                             "__ERRVAL__", $errval))
				if( not $self->{parsedSPKAC} );

		} elsif ( $self->{reqFormat} =~ /CRR/ ) {
			$self->{revokeREQ} = $self->{req};
        		$self->{parsedCRR}=
				$self->parseReq( REQ=>$keys->{REQ},
					FORMAT=>"CRR" );
			$self->{parsedItem} = $self->{parsedCRR};

			return $self->setError (7212031,
                           $self->{gettext} ("OpenCA::REQ->init: Cannot parse request (__ERRNO__). __ERRVAL__",
                                             "__ERRNO__", $errno,
                                             "__ERRVAL__", $errval))
				if( not $self->{parsedCRR} );
		} else {
			return $self->setError (7212041,
                                   $self->{gettext} ("OpenCA::REQ->init: Unknown request's format."));
		}
	}

        return 1;
}

sub getParsed {
        my $self = shift;

	if( $self->{reqFormat} =~ /SPKAC/i ) {
		return $self->setError (7221011,
                           $self->{gettext} ("OpenCA::REQ->getParsed: SPKAC-request was not parsed."))
			if( not $self->{parsedSPKAC} );
		return $self->{parsedSPKAC};
	} elsif( $self->{reqFormat} =~ /CRR/i ) {
		return $self->setError (7221013,
                           $self->{gettext} ("OpenCA::REQ->getParsed: CRR was not parsed."))
			if( not $self->{parsedCRR} );
		return $self->{parsedCRR};
	} else {
        	return $self->setError (7221014,
                           $self->{gettext} ("OpenCA::REQ->getParsed: Request was not parsed."))
			if ( not $self->{parsedItem} );
        	return $self->{parsedItem};
	}
}

sub getHeader {
	my $self = shift;
	my $keys = { @_ };
	my $req = $keys->{REQUEST};

	my ( $txt, $ret, $i, $key, $val );

	my $beginHeader = $self->{beginHeader};
	my $endHeader = $self->{endHeader};
	my $beginAttribute = $self->{beginAttribute};
	my $endAttribute = $self->{endAttribute};

	if( ($txt) = ( $req =~ /$beginHeader\s*\n([\s\S\n]+)\n$endHeader/) ) {
                my $active_multirow = undef;

		$active_multirow = 0;
		$key = "";
		foreach $i ( split ( /\s*\n/, $txt ) ) {
                        if ($active_multirow) {
                          ## multirow
                          if ($i =~ /^$endAttribute$/) {
                            ## end of multirow
                            $active_multirow = 0;
                          } else {
                            $ret->{$key} .= "\n" if ($ret->{$key});
                            ## additional data
                            $ret->{$key} .= $i;
                          }
                        } elsif ($i =~ /^$beginAttribute$/) {
                          ## begin of multirow
                          $active_multirow = 1;
                        } else {
                          ## no multirow 
                          ## if multirow then $ret->{key} is initially empty)
			  ## fix CR
			  $i =~ s/\s*\r$//;
			  $i =~ s/\s*=\s*/=/;
			  ( $key, $val ) = ( $i =~ /^([^=]*)\s*=\s*(.*)\s*/ );
			  $ret->{$key} = $val;
			  ## fix old requests
			  if ($key eq "SUBJ") {
				$ret->{SUBJECT} = $val;
			  }
                        }

		}
	}

	# foreach $i ( keys %$ret ) {
	# 	print STDERR "REQ::getHeader()->$i => " . $ret->{$i} . "\n";
	# }

	return $ret;
}

sub getRawHeader {
	my $self = shift;
	my $keys = { @_ };
	my $req = $keys->{REQUEST};

	my $beginHeader	= $self->{beginHeader};
	my $endHeader 	= $self->{endHeader};

	my ( $ret ) = ( $req =~ /($beginHeader[\S\s\n]+$endHeader)/ );
	return $ret;
}

sub getSignature {
	my $self = shift;
	my $keys = { @_ };
	my $req = $keys->{REQUEST};
	return $self->getParsed()->{SIGNATURE} if (not $req);

	my $beginSig 	= $self->{beginSignature};
	my $endSig 	= $self->{endSignature};

	my ( $ret ) = ( $req =~ /($beginSig[\S\s\n]+$endSig)/ );
	return $ret;
}

sub getKey {
	my $self = shift;
	my $keys = { @_ };
	my $req = $keys->{REQUEST};

	my $beginKey 	= $self->{beginKey};
	my $endKey 	= $self->{endKey};

	if ( not $req ) {
		$req = $self->{item};
	}

	my ( $ret ) = ( $req =~ /($beginKey[\S\s\n]+$endKey)/ );
	return $ret;
}

sub getBody {
	my $self = shift;
	my $keys = { @_ };

	my $ret = $keys->{REQUEST};
	return $self->{req} if (not $ret);

	my $beginHeader 	= $self->{beginHeader};
	my $endHeader 		= $self->{endHeader};

	my $beginSig 		= $self->{beginSignature};
	my $endSig 		= $self->{endSignature};

	my $beginKey 		= $self->{beginKey};
	my $endKey 		= $self->{endKey};

	## Let us throw away text between the two headers, included
	$ret =~ s/($beginHeader[\S\s\n]+$endHeader\n*)//;

	## Let us throw away text between the two headers, included
	$ret =~ s/($beginSig[\S\s\n]+$endSig)//;

	## Let us throw away text between the two headers, included
	$ret =~ s/($beginKey[\S\s\n]+$endKey)//;

	## Let us throw away leading and trailing nonse
	## this is important for signature handling
	$ret =~ s/^[\r\n]*//s;
	$ret =~ s/[\r\n]*$//s;

	return $ret;
}

sub parseReq 
{
	my $self = shift;
	my $keys = { @_ };

	my $fullReq = $keys->{REQ};
	my $format  = $keys->{FORMAT};

	my @dnList = ();
	my @exts = ();

	my ( $ret, $tmp, $key, $val, $tmpOU, $ra, $textReq );

	return $self->setError (7213011,
		$self->{gettext} ("There is no complete request available.")) if (not $fullReq);

	## timing test
	#my $start;
	#use Time::HiRes qw( usleep ualarm gettimeofday tv_interval );
	#$start = [gettimeofday];
	#$self->{DEBUG_SPEED} = 1;

	$ret->{SIGNATURE}         = $self->getSignature ( REQUEST=>$fullReq );
	$ret->{PRIVKEY}           = $self->getKey       ( REQUEST=>$fullReq );
	$ret->{HEADER}            = $self->getHeader    ( REQUEST=>$fullReq );
	$ret->{RAWHEADER}         = $self->getRawHeader ( REQUEST=>$fullReq );
	$ret->{BODY}              = $self->getBody      ( REQUEST=>$fullReq );
	$ret->{ITEM}              = $self->{item};

	#print "OpenCA::REQ->parseReq: split_time_1=".tv_interval($start)."<br>\n"
	#	if ($self->{DEBUG_SPEED});

	if (not $ret->{BODY})
	{
		## this must be a request with TYPE == HEADER
		print $self->{gettext} ("OpenCA::REQ->parseReq: This is a HEADER only.")."<br>\n" if ($self->{DEBUG});

		if (not $ret->{HEADER})
		{
			return $self->setError (7213015,
				   $self->{gettext} ("OpenCA::REQ->init: The request has no body."));
		};

		if ( not $ret->{HEADER}->{TYPE} =~ /HEADER/i)
		{
			return $self->setError (7213016,
				   $self->{gettext} ("OpenCA::REQ->init: The request has no body and has not the type HEADER."));
		}

		$ret->{TYPE}  = "HEADER";
		$ret->{DN} = $ret->{HEADER}->{SUBJECT};
	}
	else
	{
		$textReq = $ret->{BODY};

		print "OpenCA::REQ->parseReq: FORMAT: $format<br>\n" if ($self->{DEBUG});

		if (uc $format ne "CRR")
		{
			## Get Attributes from openssl directly
			my @attrlist;
			if ( $format =~ /SPKAC/i )
			{
				@attrlist = ( "PUBKEY", "KEYSIZE", "PUBKEY_ALGORITHM", "EXPONENT", "MODULUS",
				              "SIGNATURE_ALGORITHM" );
			}
			else
			{
				@attrlist = ( "DN", "VERSION", "SIGNATURE_ALGORITHM",
				              "PUBKEY", "KEYSIZE", "PUBKEY_ALGORITHM", "EXPONENT", "MODULUS", "EXTENSIONS" );
			}

			#print "OpenCA::REQ->parseReq: split_time_1_4=".tv_interval($start)."<br>\n"
			#	if ($self->{DEBUG_SPEED});

			my $attrs = $self->{backend}->getReqAttribute( DATA=>$ret->{BODY}. "\n",
						 ATTRIBUTE_LIST=>\@attrlist, INFORM=>$format );

			#print "OpenCA::REQ->parseReq: split_time_1_5=".tv_interval($start)."<br>\n"
			#	if ($self->{DEBUG_SPEED});

			$ret->{PLAIN_EXTENSIONS} = $attrs->{EXTENSIONS};
			$ret->{OPENSSL_EXTENSIONS} = {};
			delete $attrs->{EXTENSIONS};

			# parse extensions
			my @lines = split(/\n/, $ret->{PLAIN_EXTENSIONS});
			my $i = 0;
			while($i < scalar(@lines))
			{
				if($lines[$i] =~ /^\s*([^:]+):\s*(?:critical|)\s*$/i) 
				{
					my ($val, $key);

					$key = $1;
					$ret->{OPENSSL_EXTENSIONS}->{$key} = [];
					$i++;

					while(exists $lines[$i] and $lines[$i] !~ /^\s*[^:]+:\s*(?:critical|)\s*$/ && $i < scalar(@lines))
					{
						$val = $lines[$i];
				    $val =~ s/^\s+//;
				    $val =~ s/\s+$//;
				    $i++;
				    next if $val =~ /^$/;
				    push(@{$ret->{OPENSSL_EXTENSIONS}->{$key}}, $val);
					}
				}
				else
				{
					## FIXME: can this ever happen?
					$i++;
				}
			}
			
			if ($self->{DEBUG})
			{
				print "OpenCA::REQ->parseReq: show all extensions and their values<br>\n";
				while(my ($key, $val) = each(%{$ret->{OPENSSL_EXTENSIONS}}))
				{
					print "OpenCA::REQ->parseReq: found extension: $key<br>\n";
					print "OpenCA::REQ->parseReq: with value(s):       $_<br>\n" foreach(@{$val});
				}
			}

			foreach (keys %$attrs )
			{
				$ret->{$_} = $attrs->{$_};
				if ($self->{DEBUG})
				{
					print "OpenCA::REQ->parseReq: ATTRIBUTE: ".$_."<br>\n";
					print "OpenCA::REQ->parseReq: VALUE: ".$ret->{$_}."<br>\n";
				}
			}
		}

		if(exists $ret->{PUBKEY})
		{
			my $md5 = new Digest::MD5;
			$md5->add( $ret->{PUBKEY} );
			$ret->{KEY_DIGEST} = $md5->hexdigest();
		}

		if ( $format =~ /SPKAC/i )
		{
			## Specific for SPKAC requests...
			my ( @reqLines );

			@reqLines = split( /\n/ , $textReq );
			for $tmp (@reqLines) 
			{
				$tmp =~ s/\r$//;

				my ($key,$val)=($tmp =~ /([\w]+)\s*=\s*(.*)\s*/ );
				## this is a bug at minimum for emailAddress
				## $key = uc( $key );

				if ($key ne "")
				{
					if ($key =~ /SPKAC/i)
					{
						$ret->{SPKAC} = $val;
					}
					else
					{
						$ret->{DN} .= ", " if ($ret->{DN});
						$ret->{DN} .= $key."=".$val;
					}
				}
			}

			## Now retrieve the SPKAC crypto infos...
			$textReq=$self->{backend}->SPKAC( SPKAC=>$textReq);

			$ret->{VERSION} 	= 1;
			$ret->{TYPE}  = 'SPKAC';
		}
		elsif ($format =~ /CRR/i)
		{
			## Specific for CRRs...
			my ( @reqLines );

			@reqLines = split( /\n/ , $textReq );
			for $tmp (@reqLines)
			{
				$tmp =~ s/\r$//;

				($key,$val)=($tmp =~ /([\w]+)\s*=\s*(.*)\s*/ );
				$key = uc( $key );

				$ret->{$key} = $val;

				## MADWOLF: Debug info
				## print STDERR "CRR_REQ->parseRequest()->Adding $key -> $val\n";
			}

			$ret->{VERSION} = 1 if ( not exists $ret->{VERSION});

			$ret->{TYPE}  		= 'CRR';
			$ret->{HEADER}->{TYPE} 	= $ret->{TYPE};

			$ret->{REVOKE_CERTIFICATE_DN} =~ s/^\///;
			$ret->{REVOKE_CERTIFICATE_DN} =~ s/\/([A-Za-z0-9\-]+)=/, $1=/g;

			## allow automatic parsing
			$ret->{DN} = $ret->{REVOKE_CERTIFICATE_DN};

			$ret->{REASON} = $ret->{REVOKE_REASON};
			$ret->{REVOKE_REASON} = $ret->{REVOKE_REASON};
		}
		else
		{
			$ret->{DN} =~ s/\,\s*$//;
			if (exists $ret->{HEADER}->{TYPE})
			{
				$ret->{TYPE} = $ret->{HEADER}->{TYPE};
			}
			else
			{
				$ret->{TYPE}  		= 'PKCS#10';
			}
		}
	}

	#print "OpenCA::REQ->parseReq: split_time_2=".tv_interval($start)."<br>\n"
	#	if ($self->{DEBUG_SPEED});

	## load the differnt parts of the DN into DN_HASH
	my $fixed_dn;
	my $rdn;
	if ($ret->{HEADER}->{SUBJECT})
	{
		print "OpenCA::REQ->parseReq: SUBJECT: ".$ret->{HEADER}->{SUBJECT}."<br>\n" if ($self->{DEBUG});
		$fixed_dn = $ret->{HEADER}->{SUBJECT};
	}
	else
	{
		print "OpenCA::REQ->parseReq: DN: ".$ret->{DN}."<br>\n" if ($self->{DEBUG});
		$fixed_dn = $ret->{DN};
	}

	## OpenSSL includes a bug in -nameopt RFC2253
	## = signs are not escaped if they are normal values
	my $i = 0;
	my $now = "name";
	while ($i < length ($fixed_dn))
	{
		if (substr ($fixed_dn, $i, 1) eq '\\')
		{
			$i++;
		} elsif (substr ($fixed_dn, $i, 1) eq '=') {
			if ($now =~ /value/)
			{
				## OpenSSL forgets to escape =
				$fixed_dn = substr ($fixed_dn, 0, $i)."\\".substr ($fixed_dn, $i);
				$i++;
			} else {
				$now = "value";
			}
		} elsif (substr ($fixed_dn, $i, 1) =~ /[,+]/) {
			$now = "name";
		}
		$i++;
	}

	#print "OpenCA::REQ->parseReq: split_time_3=".tv_interval($start)."<br>\n"
	#	if ($self->{DEBUG_SPEED});

	if ($fixed_dn =~ /[\\+]/)
	{
		$fixed_dn =~ s/\w+=\s*\,//g;
		$fixed_dn =~ s/\w+=\s*$//;

		my $x500_dn = X500::DN->ParseRFC2253 ($fixed_dn);

		foreach $rdn ($x500_dn->getRDNs())
		{
			next if ($rdn->isMultivalued());
			my @attr_types = $rdn->getAttributeTypes();
			my $type  = $attr_types[0];
			my $value = $rdn->getAttributeValue ($type);
			push (@{$ret->{DN_HASH}->{uc($type)}}, $value);
			print "OpenCA::REQ->parseReq: DN_HASH: $type=$value<br>\n" if ($self->{DEBUG});
		}
	}
	else
	{
		my @rdns = split /,/, $fixed_dn;
		foreach $rdn (@rdns)
		{
			my ($type, $value) = split /=/, $rdn;
			$type =~ s/^\s*//;
			$type =~ s/\s*$//;
			$value =~ s/^\s*//;
			$value =~ s/\s*$//;
			push (@{$ret->{DN_HASH}->{uc($type)}}, $value);
			print "OpenCA::REQ->parseReq: DN_HASH: $type=$value<br>\n" if ($self->{DEBUG});
		}
	}

	#print "OpenCA::REQ->parseReq: split_time_4=".tv_interval($start)."<br>\n"
	#	if ($self->{DEBUG_SPEED});

	## show DN to check conformance to RFC 2253
	if ($self->{DEBUG})
	{
		print "OpenCA::REQ->parseReq: TYPE: ".$ret->{TYPE}."<br>\n";
		print "OpenCA::REQ->parseReq: DN: ".$ret->{DN}."<br>\n";
	}

	## set emailaddress

	$ret->{EMAILADDRESSES} = [ $self->get_emails ($ret) ];
	$ret->{EMAILADDRESS} = $ret->{EMAILADDRESSES}->[0];

	if ($self->{DEBUG})
	{
		print "OpenCA::REQ->parseReq: SUBJECT_ALT_NAME: ".$ret->{HEADER}->{SUBJECT_ALT_NAME}."<br>\n";
		print "OpenCA::REQ->parseReq: EMAILADDRESS: ".$ret->{EMAILADDRESS}."<br>\n";
	}

	if (exists $ret->{HEADER}->{TYPE} and $ret->{HEADER}->{TYPE} !~ /HEADER/)
	{
		## Common Request Parsing ...
		$ret->{PK_ALGORITHM}  = $ret->{PUBKEY_ALGORITHM};
		$ret->{SIG_ALGORITHM} = $ret->{SIGNATURE_ALGORITHM};
		$ret->{TYPE} .= " with PKCS#7 Signature" if ( $ret->{SIGNATURE} );
	}

	## timing test

	#if ($self->{DEBUG_SPEED})
	#{
	#	print "OpenCA::REQ->parseReq: split_time_last=".tv_interval($start)."<br>\n";
	#	$errno += tv_interval ( $start );
	#	print "OpenCA::REQ->parseReq: total_time=".$errno."<br>\n";
	#}

	return $ret;
}

sub getTXT {
	my $self = shift;
	my $ret;

	if( $self->{reqFormat} =~ /SPKAC/i ) {
		return $self->setError (7241011,
                           $self->{gettext} ("OpenCA::REQ->getTXT: The request should be in SPKAC-format but there is no SPKAC-request."))
			if( not $self->{spkacREQ} );

		$ret =  $self->{req} . 
			$self->{backend}->SPKAC( SPKAC => $self->{spkacREQ} );
		return $ret;
	} elsif( $self->{reqFormat} =~ /CRR/i ) {
		return	$self->setError (7241013,
                            $self->{gettext} ("OpenCA::REQ->getTXT: The request should be a CRR but there is no such request."))
			if( not $self->{revokeREQ} );

		$ret =  $self->{req};
		return $ret;
	} else {
		if (not $self->{txtREQ}) {
			$self->{txtREQ} = $self->{backend}->dataConvert(
			         DATA=>$self->{req},
			         DATATYPE=>"REQUEST",
			         INFORM=>$self->{reqFormat},
			         OUTFORM=>"TXT" );
			return $self->setError (7241021,
                                   $self->{gettext} ("OpenCA::REQ->init: Cannot convert request to TXT-format (__ERRNO__). __ERRVAL__",
                                                     "__ERRNO__", $OpenCA::OpenSSL::errno,
                                                     "__ERRVAL__", $OpenCA::OpenSSL::errval))
				if (not $self->{txtREQ});
		}

		return $self->setError (7241015,
                           $self->{gettext} ("OpenCA::REQ->getTXT: The request should be a TXT-request but there is no TXT-request."))
			if ( not $self->{txtREQ} );
		return $self->{txtREQ};
	}
}

sub getPEM {
	my $self = shift;
	my $ret;

	return $self->setError (7242011,
                   $self->{gettext} ("OpenCA::REQ->getPEM: The request is in SPKAC-format and not in PEM-format."))
		if( $self->{reqFormat} =~ /SPKAC/i );
	return $self->setError (7242013,
                   $self->{gettext} ("OpenCA::REQ->getPEM: The request is a CRR."))
		if( $self->{reqFormat} =~ /CRR/i );

	if ( $self->{reqFormat} eq 'PEM' ) {
		$self->{req} .= "\n" if ($self->{req} !~ /\n$/);
		return $self->{req};
	}
	if (not $self->{pemREQ}) {
    	$self->{pemREQ} = $self->{backend}->dataConvert( 
		       DATA=>$self->{req},
		       DATATYPE=>"REQUEST",
		       INFORM=>$self->{reqFormat},
		       OUTFORM=>"PEM" );
		return $self->setError (7242021,
                           $self->{gettext} ("OpenCA::REQ->getPEM: Cannot convert request to PEM-format (__ERRNO__). __ERRVAL__",
                                             "__ERRNO__", $OpenCA::OpenSSL::errno,
                                             "__ERRVAL__", $OpenCA::OpenSSL::errval))
			if (not $self->{pemREQ});
	}

	return $self->setError (7242015,
                   $self->{gettext} ("OpenCA::REQ->getPEM: The request is not available in PEM-format."))
		if ( not $self->{pemREQ} );

	return $self->{pemREQ};
}

sub getDER {
	my $self = shift;
	my $ret;

	return $self->setError (7243011,
                   $self->{gettext} ("OpenCA::REQ->getDER: The request is in SPKAC-format and not in DER-format."))
		if( $self->{reqFormat} =~ /SPKAC/i );
	return $self->setError (7243013,
                   $self->{gettext} ("OpenCA::REQ->getDER: The request is a CRR."))
		if( $self->{reqFormat} =~ /CRR/i );

	if ( $self->{reqFormat} eq 'DER' ) {
		return $self->{req};
	}
	if (not $self->{derREQ}) {
		$self->{derREQ} = $self->{backend}->dataConvert( 
		       DATA=>$self->{req},
		       DATATYPE=>"REQUEST",
		       INFORM=>$self->{reqFormat},
		       OUTFORM=>"DER" );
		return $self->setError (7243021,
                           $self->{gettext} ("OpenCA::REQ->getDER: Cannot convert request to DER-format (__ERRNO__). __ERRVAL__",
                                             "__ERRNO__", $OpenCA::OpenSSL::errno,
                                             "__ERRVAL__", $OpenCA::OpenSSL::errval))
			if (not $self->{derREQ});
	}

	return $self->setError (7243015,
                   $self->{gettext} ("OpenCA::REQ->getDER: The request is not available in DER-format."))
		if ( not $self->{derREQ} );

	return $self->{derREQ};
}

sub getItem {
	my $self = shift;

	return $self->getParsed()->{ITEM};
}

sub getSerial {
	my $self = shift;

	my $ret = $self->getParsed()->{HEADER}->{SERIAL};
        if (not defined $ret) {
		## old requests
		$ret = $self->getParsed()->{SERIAL};
	}

	return $ret;
}

sub setParams {

	my $self = shift;
	my $params = { @_ };
	my $key;

	foreach $key ( keys %{$params} ) {
		## we should place the parameters here
	}

	return 1;
}

## by michael bell to support signature in the header
## 1) works actually only with PEM because automatical
## transformation to DER etc. is a high risc
## for a failure
## 2) please submit only one attribute
sub setHeaderAttribute {

  my $self = shift;
  my $keys = { @_ };

  my $beginHeader = $self->{beginHeader};
  my $endHeader = $self->{endHeader};
  my $beginAttribute = $self->{beginAttribute};
  my $endAttribute = $self->{endAttribute};

  ## check format to be PEM
  return $self->setError (7251011,
             $self->{gettext} ("OpenCA::REQ->setHeaderAttribute: The request is not in PEM-format."))
	if ($self->{reqFormat} !~ /^PEM|CRR|SPKAC$/i);
  print $self->{gettext} ("REQ->setHeaderAttribute: correct format - PEM")."<br>\n" if ($self->{DEBUG});

  ## check for header
  if ($self->{item} !~ /$beginHeader/) {
    ## create header
    $self->{item} = $beginHeader."\n".$endHeader."\n".$self->{item};
  }

  for my $attribute (keys %{$keys}) {

    # print STDERR "REQ->setHeaderAttribute: $attribute:=".
    # 					$keys->{$attribute}."<br>\n";

	next if ( not $attribute );

    ## insert into item
    ## find last position in header
    ## enter attributename
    ## check fo multirow
    if ($keys->{$attribute} =~ /\n/) {
      ## multirow
      $self->{item} =~ s/${endHeader}/${attribute}=\n${beginAttribute}\n$keys->{$attribute}\n${endAttribute}\n${endHeader}/;
    } else {
	# print STDERR "REQ::setHeaderAttribute::Setting $attribute = " .
	# 		$keys->{$attribute} . "\n" if ( $self->{DEBUG} );

      	## Delete old attribute
	if ( $self->getParsed()->{HEADER}->{$attribute} ) {
      		$self->{item} =~ s/($attribute[^\n]+\n)//;
	}

      ## single row
      $self->{item} =~ s/${endHeader}/${attribute} = $keys->{$attribute}\n${endHeader}/;
      # print STDERR "REQ::NEW HEADER\n".$self->{item}."\n";
    }

  }

  ## if you call init then all information is lost !!!
  return $self->setError (7251021,
             $self->{gettext} ("OpenCA::REQ->setHeaderAttribute: Cannot re-initialize the request (__ERRNO__). __ERRVAL__",
                               "__ERRNO__", $errno,
                               "__ERRVAL__", $errval))
  	if (not $self->init ( REQ => $self->{item},
                    FORMAT      => $self->{reqFormat}));

  return 1;
}

sub getStatus {
    my $self = shift;
    return $self->{STATUS};
}

sub setStatus
{
	my $self = shift;
	my $status = shift;

	my $status_update = undef;
	my $now = gmtime;

	## MADWOLF: Debug Information
	## print STDERR "REQ->setStatus(): new Status to be set is $status... \n" if ($self->{DEBUG});

	## Handles special fields like SUSPENDED_AFTER, REVOKED_AFTER, etc.
	$status =~ s/\_.*//;
	if (($self->{STATUS} ne $status) and ($status !~ /NEW|PENDING|TEMPNEW|TEMPPENDING/)) {
		$status_update = $status . "_AFTER";
		if( $self->getParsed()->{HEADER}->{$status_update} eq "" ) {
			$self->setHeaderAttribute ( $status_update => $now );
		}
		# $self->{$status_update} = $now;
	}

	if ( $self->{reqFormat} =~ /CRR/ ) {
		$self->{DATATYPE} = $status . "_CRR";
	} else {
		$self->{DATATYPE} = $status . "_REQUEST";
	}
	$self->{STATUS} = $status;

	# print STDERR "REQ->setStatus(): new Status set is $status... \n";

	return $self->getStatus();
}

sub get_emails {
    my $self = shift;
    my $parsed = $self->getParsed();
    $parsed = shift if ($_[0]);

    my @emails = ();

    ## extract emails from subject alt name

    if ( $parsed->{HEADER}->{SUBJECT_ALT_NAME} ) {
        my @subjectAltNames = split (/,\s*/, $parsed->{HEADER}->{SUBJECT_ALT_NAME});
        foreach my $h (@subjectAltNames) {
            next if ($h !~ /^\s*email(|\.[0-9]+)[:=]/is);
            $h =~ s/^\s*email(|\.[0-9]+)[:=]//i;
            push (@emails, $h);
        }
    }

    ## extract emails from subject

    if (exists $parsed->{DN_HASH}->{EMAILADDRESS})
    {
        foreach my $mail (@{$parsed->{DN_HASH}->{EMAILADDRESS}})
        {
            push @emails, $mail;
        }
    }

    return @emails;
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
__END__
# Below is the stub of documentation for your module. You better edit it!

=head1 NAME

OpenCA::REQ - Perl extension to easily manage Cert REQUESTs

=head1 SYNOPSIS

  use OpenCA::REQ;

=head1 DESCRIPTION

Sorry, no help available. The REQ module is capable of importing
request like this:

	-----BEGIN HEADER-----
	VAR = NAME
	VAR = NAME
	...
	-----END HEADER-----
	(real request text here)
	-----BEGIN PKCS7-----
	(pkcs#7 signature here
	-----END PKCS7-----

The Real request text can be a request in every form ( DER|PEM ) or
textual (called SPKAC|CRR datatype). The syntax of the latters
is VAR = NAME on each line (just like the HEADER section).

=head1 AUTHOR

Massimiliano Pala <madwolf@openca.org>

=head1 SEE ALSO

OpenCA::OpenSSL, OpenCA::X509, OpenCA::CRL, OpenCA::Configuration,
OpenCA::TRIStateCGI, OpenCA::Tools

=cut
