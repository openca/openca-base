## OpenCA::X509
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
## Copyright remains Massimiliano Pala's, and as such any Copyright notices
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
##    "This product includes OpenCA software written by Massimiliano Pala
##     (madwolf@openca.org) and the OpenCA Group (www.openca.org)"
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

## // the module's errorcode is 74
##
## functions
##
## new			11
## init			12
## getHeader		21
## getKey		22
## getBody		23
## getParsed		31
## parseCert		13
## getPEM		41
## getPEMHeader		42
## getDER		43
## getTXT		44
## setHeaderAttribute	51
## getItem		61
## getSerial		62
## setParams            71

use strict;
use Digest::MD5;
use X500::DN;

package OpenCA::X509;

our ($errno, $errval);

($OpenCA::X509::VERSION = '$Revision: 1.11 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

my %params = (
	cert		=> undef,
	item		=> undef,
	pemCert		=> undef,
	pemHeader	=> undef,
	derCert		=> undef,
	txtCert		=> undef,
	backend		=> undef,
	parsedItem	=> undef,
	beginCert	=> undef,
	endCert		=> undef,
	beginHeader	=> undef,
	endHeader	=> undef,
	beginKey	=> undef,
	endKey		=> undef,
	beginAttribute	=> undef,
	endAttribute	=> undef,
	certFormat	=> undef,
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

## Create an instance of the Class
sub new {
	my $that = shift;
	my $class = ref($that) || $that;

        my $self = {
		%params,
	};

        bless $self, $class;

	my $keys = { @_ };
	my ( $infile, $tmp );

        $self->{item} 	    = $keys->{DATA};
	$self->{certFormat} = ( $keys->{FORMAT} or $keys->{INFORM} or "PEM" );
	$infile		    = $keys->{INFILE};

	$self->{backend}    = $keys->{SHELL};
	$self->{gettext}    = $keys->{GETTEXT};

	$self->{beginCert}	= "-----BEGIN CERTIFICATE-----";
	$self->{endCert}	= "-----END CERTIFICATE-----";
	$self->{beginHeader}	= "-----BEGIN HEADER-----";
	$self->{endHeader}	= "-----END HEADER-----";
	$self->{beginAttribute}	= "-----BEGIN ATTRIBUTE-----";
	$self->{endAttribute}	= "-----END ATTRIBUTE-----";
	$self->{beginKey}	= "-----BEGIN .*PRIVATE KEY-----";
	$self->{endKey}		= "-----END .*PRIVATE KEY-----";

	$self->_debug("OpenCA::X509::new start");

	if( $infile ) {
		$self->{item} = "";

		open( FD, "<$infile" )
			or return $self->setError (7411011,
                                      $self->{gettext} ("OpenCA::X509->new: Cannot open infile __FILENAME__ for reading.",
                                                        "__FILENAME__", $infile));
		while ( $tmp = <FD> ) {
			$self->{item} .= $tmp;
		}
		close( FD );
	}

	$self->_debug("OpenCA::X509::item loaded (" . $self->{item} . ")");

	if ( defined($self->{item}) and $self->{item} ne "" ) {
		$self->{cert} = $self->getBody( ITEM=>$self->{item} );

		$self->_debug("OpenCA::X509::init starting");
		if ( not $self->init() ) {
			return $self->setError (7411021,
                                   $self->{gettext} ("OpenCA::X509->new: Cannot initialize certificate (__ERRNO__). __ERRVAL__",
                                                     "__ERRNO__", $errno,
                                                     "__ERRVAL__", $errval));
		}

		$self->_debug("OpenCA::X509::init returned");
	}

	$self->_debug("OpenCA::X509::new completed ($self)");

        return $self;
}

sub init {
	my $self = shift;

	return $self->setError (7412011,
                   $self->{gettext} ("OpenCA::X509->init: No certificate present."))
		if (not $self->{cert});

	$self->{pemCert} = "";

	$self->{derCert} = "";

	$self->{txtCert} = "";

	$self->{parsedItem} = $self->parseCert();
	return $self->setError (7412031,
                   $self->{gettext} ("OpenCA::X509->init: Cannot parse certificate (__ERRNO__). __ERRVAL__",
                                     "__ERRNO__", $errno,
                                     "__ERRVAL__", $errval))
		if (not $self->{parsedItem});

        ## build pem-header
        $self->{pemHeader} = $self->{beginHeader};
        for my $h (keys %{$self->{parsedItem}->{HEADER}}) {
          $self->{pemHeader} .= "\n".$h."=";
          if ( $self->{parsedItem}->{HEADER}->{$h} =~ /\n/ ) {
            ## multirow attribute
            $self->{pemHeader} .= "\n".$self->{beginAttribute}.
                                  "\n".$self->{parsedItem}->{HEADER}->{$h}.
                                  "\n".$self->{endAttribute};
          } else {
            $self->{pemHeader} .= $self->{parsedItem}->{HEADER}->{$h};
          }
        }
        $self->{pemHeader} .= "\n".$self->{endHeader}."\n";

	return 1;
}

## modified by michael bell to support multirow-values
sub getHeader {
	my $self = shift;
	my $keys = { @_ };
	my $req = $keys->{ITEM};

	my ( $txt, $ret, $i, $key, $val );

	my $beginHeader = $self->{beginHeader};
	my $endHeader = $self->{endHeader};
	my $beginAttribute = $self->{beginAttribute};
	my $endAttribute = $self->{endAttribute};

	if( ($txt) = ( $req =~ /$beginHeader\n([\S\s\n]+)\n$endHeader/m) ) {
                my $active_multirow = 0;
		foreach $i ( split ( /\n/, $txt ) ) {
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
			  $i =~ s/\s*=\s*/=/;
			  ( $key, $val ) = ( $i =~ /(.*)\s*=\s*(.*)\s*/ );
			  $ret->{$key} = $val;
                        }
		}
	}

	if (not defined $ret->{CSR_SERIAL})
	{
		$ret->{CSR_SERIAL} = -1;
	}

	return $ret;
}

sub getKey {
	my $self = shift;
	my $keys = { @_ };
	my $cert = $keys->{ITEM};

	my $beginKey 	= $self->{beginKey};
	my $endKey 	= $self->{endKey};

	$cert = $self->{item} if ( $cert eq "" );

	my ( $ret ) = ( $cert =~ /($beginKey[\S\s\n]+$endKey)/ );
	return $ret;
}

sub getRawHeader {
	my $self = shift;
	my $keys = { @_ };
	my $cert = $keys->{ITEM};

	my $beginHeader	= $self->{beginHeader};
	my $endHeader 	= $self->{endHeader};

	my ( $ret ) = ( $cert =~ /($beginHeader[\S\s\n]+$endHeader)/ );
	return $ret;
}

sub getBody {
	my $self = shift;
	my $keys = { @_ };
	my $cert = $keys->{ITEM};

	my $beginCert 	= $self->{beginCert};
	my $endCert	= $self->{endCert};

	my ( $ret ) = ( $cert =~ /($beginCert[\S\s\n]+$endCert)/ );
	return $ret;
}

sub getParsed {
	my $self = shift;

	return $self->setError (7431011,
                   $self->{gettext} ("OpenCA::X509->getParsed: The certificate was not parsed."))
		if ( not $self->{parsedItem} );
	return $self->{parsedItem};
}

sub parseCert {

	my $self = shift;
	my $keys = { @_ };

	my ( @ouList, @exts, $ret, $k, $v, $tmp, $md5 );

	my @attList = ( "SERIAL", "DN", "ISSUER", "NOTBEFORE", "NOTAFTER",
			"ALIAS", "MODULUS", "PUBKEY", "FINGERPRINT", "HASH", "EMAILADDRESS",
			"VERSION", "PUBKEY_ALGORITHM", "SIGNATURE_ALGORITHM", "EXPONENT",
			"KEYSIZE", "EXTENSIONS", "OPENSSL_SUBJECT", 
			"HEX_SERIAL" );

	$self->_debug("OpenCA::X509::parseCert() start" );

	if ($self->{certFormat} eq "DER") {
		$self->_debug("OpenCA::X509::parseCert() getCertAttribute" .
								"(DER)" );
		$ret = $self->{backend}->getCertAttribute(
			ATTRIBUTE_LIST => \@attList,
			DATA           => $self->getDER(),
			INFORM         => "DER");
	} else {
		$self->_debug("OpenCA::X509::parseCert() getCertAttribute" .
								"(PEM)" );
		$self->_debug("OpenCA::X509::parseCert() getPem -> " .
				$self->getPEM() );

		$ret = $self->{backend}->getCertAttribute(
			ATTRIBUTE_LIST => \@attList,
			DATA           => $self->getPEM(),
			INFORM         => "PEM");

		$self->_debug("OpenCA::X509::parseCert() got cert ($ret)" );
	}

	if( $self->{DEBUG} ) {
		$self->_debug("OpenCA::X509->parseCert: DN: ".
							$ret->{DN}."<br>\n");
	}

	#print STDERR "OpenCA::X509->parseCert: SERIAL: ".$ret->{SERIAL} ."\n";

	$ret->{DN} =~ s/(^\/|\/$)//g;
	$ret->{DN} =~ s/\/([A-Za-z0-9\-]+)=/, $1=/g;
				
	$ret->{ISSUER} =~ s/(^\/|\/$)//g;
	$ret->{ISSUER} =~ s/\/([A-Za-z0-9\-]+)=/, $1=/g;

	if ($ret->{EMAILADDRESS})
	{
		if (index ($ret->{EMAILADDRESS}, "\n") < 0 )
		{
			$ret->{EMAILADDRESSES}->[0] = $ret->{EMAILADDRESS};
		} else {
			my @harray = split /\n/, $ret->{EMAILADDRESS};
			$ret->{EMAILADDRESSES} = \@harray;
                        $ret->{EMAILADDRESS}   = $ret->{EMAILADDRESSES}->[0];
		}
	}

	## OpenSSL includes a bug in -nameopt RFC2253
	## = signs are not escaped if they are normal values
	my $i = 0;
	my $now = "name";
	while ($i < length ($ret->{DN}))
	{
		if (substr ($ret->{DN}, $i, 1) =~ /\\/)
		{
			$i++;
		} elsif (substr ($ret->{DN}, $i, 1) =~ /=/) {
			if ($now =~ /value/)
			{
				## OpenSSL forgets to escape =
				$ret->{DN} = substr ($ret->{DN}, 0, $i)."\\".substr ($ret->{DN}, $i);
				$i++;
			} else {
				$now = "value";
			}
		} elsif (substr ($ret->{DN}, $i, 1) =~ /[,+]/) {
			$now = "name";
		}
		$i++;
	}

	## load the differnt parts of the DN into DN_HASH
	print "OpenCA::X509->parseCert: DN: ".$ret->{DN}."<br>\n" if ($self->{DEBUG});
	## X500::DN is too slow so we replace it by our own code
	my $h_subject = $ret->{DN};
	## duplicate normal characters in front of special characters
	## because we remove these leading characters during split
	$h_subject =~ s/([^\\])([+=,])/$1$1$2/g;
	my @rdns = split /[^\\],/, $h_subject;
	foreach my $rdn (@rdns) {
		print "OpenCA::X509->parseCert: RDN: $rdn<br>\n"
			if ($self->{DEBUG});
		my @components = split /[^\\][=+]/, $rdn;
		for (my $i=0; $i < scalar @components; $i++)
		{
			$components[$i] =~ s/\\([\s+=])/$1/g;
			$components[$i] =~ s/^\s*//;
			$components[$i] =~ s/\s*$//;
		}
		for (my $i=0; $i < scalar @components; $i+=2)
		{
			push (@{$ret->{DN_HASH}->{uc($components[$i])}},
			      $components[$i+1]);
			print "OpenCA::X509->parseCert: DN_HASH: ".
			      $components[$i]."=".
                                     $components[$i+1]."<br>\n" if ($self->{DEBUG});
		}
	}

	my $h_subject = $ret->{ISSUER};
	## duplicate normal characters in front of special characters
	## because we remove these leading characters during split
	$h_subject =~ s/([^\\])([+=,])/$1$1$2/g;
	my @rdns = split /[^\\],/, $h_subject;
	foreach my $rdn (@rdns) {
		print "OpenCA::X509->parseCert: RDN: $rdn<br>\n"
			if ($self->{DEBUG});
		my @components = split /[^\\][=+]/, $rdn;
		for (my $i=0; $i < scalar @components; $i++)
		{
			$components[$i] =~ s/\\([\s+=])/$1/g;
			$components[$i] =~ s/^\s*//;
			$components[$i] =~ s/\s*$//;
		}
		for (my $i=0; $i < scalar @components; $i+=2)
		{
			push (@{$ret->{ISSUER_HASH}->{uc($components[$i])}},
			      $components[$i+1]);
			print "OpenCA::X509->parseCert: ISSUER_HASH: ".
			      $components[$i]."=".
                                     $components[$i+1]."<br>\n" if ($self->{DEBUG});
		}
	}

	if( exists $ret->{PUBKEY} ) {
		$md5 = new Digest::MD5;
		$md5->add( $ret->{PUBKEY} );
		$ret->{KEY_DIGEST} = $md5->hexdigest();
	}

	## Check if Email field is only present in subjectAltName
	if (not $ret->{EMAILADDRESS} and
	    exists $ret->{DN_HASH}->{EMAILADDRESS} and
	    $ret->{DN_HASH}->{EMAILADDRESS}[0]) {
		$ret->{EMAILADDRESS} = $ret->{DN_HASH}->{EMAILADDRESS}[0];
	}

        $ret->{SIG_ALGORITHM} = $ret->{SIGNATURE_ALGORITHM};
        $ret->{PK_ALGORITHM}  = $ret->{PUBKEY_ALGORITHM};

	## load all extensions
	$ret->{PLAIN_EXTENSIONS} = $ret->{EXTENSIONS};
	delete $ret->{EXTENSIONS};
	$ret->{OPENSSL_EXTENSIONS} = {};

	my ($c, $val, $key);
	my @lines = split(/\n/, $ret->{PLAIN_EXTENSIONS});

	$i = 0;
	while($i < @lines) {
		if($lines[$i] =~ /^\s*([^:]+):\s*(?:critical|)\s*$/i) {
			$key = $1;
			$ret->{OPENSSL_EXTENSIONS}->{$key} = [];
			$i++;
			while(exists $lines[$i] and 
				$lines[$i] !~ /^\s*[^:]+:\s*(?:critical|)\s*$/ 
							and $i < @lines) {
			        $val = $lines[$i];
				if ( $key =~ /CRL Distribution Points/ ) {
					if ( $lines[$i] !~ /[a-zA-Z0-9]+/ ) {
						$i++;
						$val = $lines[$i];
					}
				}

			        $val =~ s/^\s+//;
			        $val =~ s/\s+$//;
				$i++;
				next if $val =~ /^$/;
				push(@{$ret->{OPENSSL_EXTENSIONS}->{$key}}, $val);
			}
		} else {
			## FIXME: can this every happen?
			$i++;
		}
	}

	if ($self->{DEBUG}) {
		print "OpenCA::X509->parseCert: show all extensions and their values<br>\n";
		while(($key, $val) = each(%{$ret->{OPENSSL_EXTENSIONS}})) {
			print "OpenCA::X509->parseCert: found extension: $key<br>\n";
			print "OpenCA::X509->parseCert: with value(s):       $_<br>\n" foreach(@{$val});
		}
	}

	## load special extensions
	my $h = $ret->{OPENSSL_EXTENSIONS}->{"X509v3 Basic Constraints"}[0];
	$h ||= "";
	$h =~ s/\s//g;
	if ($h =~ /CA:TRUE/i) {
		$ret->{IS_CA} = 1;
		$ret->{EXTENSIONS}->{BASIC_CONSTRAINTS}->{CA} = 1;
	} else {
		$ret->{IS_CA} = 0;
		$ret->{EXTENSIONS}->{BASIC_CONSTRAINTS}->{CA} = 0;
	}

	$ret->{BODY}              = $self->getBody   (ITEM => $self->{item});
	$ret->{HEADER}            = $self->getHeader (ITEM => $self->{item});
	$ret->{RAWHEADER}         = $self->getRawHeader ( ITEM=>$self->{item});
	$ret->{PRIVKEY}           = $self->getKey    (ITEM => $self->{item});
	$ret->{ITEM}              = $ret->{BODY};
	$ret->{FLAG_EXPORT_STATE} = 0;

        ## if email was not set then we check the subject alternative name
        if (not $ret->{EMAILADDRESS}) {
          my $h = $ret->{OPENSSL_EXTENSIONS}->{"X509v3 Subject Alternative Name"}[0];
	  if ($h && $h =~ /^(.*,|)\s*email:/i) {
            ## email steckt im subjectAltName
            $h =~ s/^(.*,|)\s*email:\s*//ig;
            $h =~ s/\s*$//g;
            $h =~ s/,.*$//g;
            $ret->{EMAILADDRESS} = $h;
          }
        }

	return $ret;
}

sub getPEM {
	my $self = shift;

	if ( $self->{certFormat} eq 'PEM' ) {
		$self->{cert} =~ s/^\n*//;
		$self->{cert} =~ s/\n*$/\n/;
		return $self->{cert};
	}
	if (not $self->{pemCert}) {
		$self->{pemCert} = $self->{backend}->dataConvert( DATA=>$self->{cert},
					DATATYPE=>"CERTIFICATE",
					INFORM=>$self->{certFormat},
					OUTFORM=>"PEM" );
		return $self->setError (7441005,
                           $self->{gettext} ("OpenCA::X509->getPEM: Cannot convert certificate to PEM-format (__ERRNO__). __ERRVAL__",
                                             "__ERRNO__", $OpenCA::OpenSSL::errno,
                                             "__ERRVAL__", $OpenCA::OpenSSL::errval))
			if (not $self->{pemCert});
	}

	## return $self->setError (7441011, "OpenCA::X509->getPEM: The certificate is not available in PEM-format.")
	##	if (not $self->{pemCert});
	return $self->{pemCert};
}

sub getPEMHeader {
	my $self = shift;

	return $self->setError (7442011,
                   $self->{gettext} ("OpenCA::X509->getPEMHeader: There is no PEM-header available."))
		if (not $self->{pemHeader});
	return $self->{pemHeader};
}

sub getDER {
	my $self = shift;

	if ( $self->{certFormat} eq 'DER' ) {
		return $self->{cert};
	}
	if (not $self->{derCert}) {
		$self->{derCert} = $self->{backend}->dataConvert( DATA=>$self->{cert},
					DATATYPE=>"CERTIFICATE",
					INFORM=>$self->{certFormat},
					OUTFORM=>"DER" );
		return $self->setError (7443005,
                           $self->{gettext} ("OpenCA::X509->getDER: Cannot convert certificate to DER-format (__ERRNO__). __ERRVAL__",
                                             "__ERRNO__", $OpenCA::OpenSSL::errno,
                                             "__ERRVAL__", $OpenCA::OpenSSL::errval))
			if (not $self->{derCert});
	}

	## return $self->setError (7443011, "OpenCA::X509->getDER: The certificate is not available in DER-format.")
	## 	if( not $self->{derCert} );
	return $self->{derCert};
}

sub getTXT {
	my $self = shift;

	if (not $self->{txtCert}) {
		$self->{txtCert} = $self->{backend}->dataConvert( DATA=>$self->{cert},
					DATATYPE=>"CERTIFICATE",
					INFORM=>$self->{certFormat},
					OUTFORM=>"TXT" );
		return $self->setError (7444005,
                           $self->{gettext} ("OpenCA::X509->init: Cannot convert certificate to TXT-format (__ERRNO__). __ERRVAL__",
                                             "__ERRNO__", $OpenCA::OpenSSL::errno,
                                             "__ERRVAL__", $OpenCA::OpenSSL::errval))
			if (not $self->{txtCert});
	}

	## return $self->setError (7444011, "OpenCA::X509->getTXT: The certificate is not available in TXT-format.")
	## 	if( not $self->{txtCert} );
	return $self->{txtCert};
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

  ## check certFormat to be PEM
  return $self->setError (7451011,
             $self->{gettext} ("OpenCA::X509->setHeaderAttribute: The certificate is not in PEM-format."))
	if ($self->{certFormat} !~ /^PEM$/i);

  ## check for header
  if ($self->{item} !~ /$beginHeader/) {
    ## create header
    $self->{item} = $beginHeader."\n".$endHeader."\n".$self->{item};
  }

  # print STDERR "ITEM => " . $self->{item} . "\n";

  for my $attribute (keys %{$keys}) {

	next if ( not $attribute );
    
	# print "X509->setHeaderAttribute: $attribute:=" .
	# 		$keys->{$attribute}."<br>\n" if ($self->{DEBUG});

    ## insert into item
    ## find last position in header
    ## enter attributename
    ## check fo multirow
    if ($keys->{$attribute} =~ /\n/) {
      ## multirow
      $self->{item} =~ s/${endHeader}/${attribute} =\n${beginAttribute}\n$keys->{$attribute}\n${endAttribute}\n${endHeader}/;
    } else {
      ## Delete old attribute
	if ( $self and $self->getParsed() and
                        $self->getParsed()->{HEADER} and
			$self->getParsed()->{HEADER}->{$attribute} ) {
        	# print STDERR "REQ::setHeaderAttribute::Deleting $attribute\n";
                $self->{item} =~ s/^$attribute[^\n]+\n//;
        }

      ## single row
      $self->{item} =~ s/${endHeader}/${attribute} = $keys->{$attribute}\n${endHeader}/;
    }

  }

  # print STDERR "AfterAttributes::ITEM => " . $self->{item} . "\n";

  ## if you call init then all information is lost !!!
  if (not $self->init ( CERTIFICATE => $self->{item}, FORMAT => "PEM")) {
	print STDERR "X509->setHeaderAttribute: $errno - $errval\n";

  	return $self->setError (7451021,
             $self->{gettext} ("OpenCA::X509->setHeaderAttribute: Cannot re-initialize the certificate (__ERRNO__). __ERRVAL__",
                               "__ERRNO__", $errno,
                               "__ERRVAL__", $errval))
  }

  return 1;
}

sub getItem {
	my $self = shift;
	my $txtItem = "";
	my $bH = $self->{beginHeader};
	my $eH = $self->{endHeader};

	## remove empty header
	if ($self->getPEMHeader() !~ /^\n*$bH\n*$eH\n*$/) {
		$txtItem  .= $self->getPEMHeader ()."\n";
	}
	$txtItem .= $self->getPEM();
	$txtItem .= $self->getParsed()->{PRIVKEY} || "";

	return $txtItem;
}

sub getSerial {
	my $self = shift;
	my $dataType = shift;

	if ( ( $dataType =~ /CA_CERTIFICATE/  ) or 
			($self->getParsed()->{DATATYPE} =~ /CA_CERTIFICATE/) ) {
		return $self->getFingerprint();
	} else {
		return $self->getParsed()->{SERIAL};
	}
}

sub getFingerprint {
	my $self = shift;
	my $ret = undef;

	return $self->{backend}->getFingerprint( CERT=>$self );

	# $ret = $self->{backend}->getDigest(
	# 		ALGORITHM => "sha1",
	# 		DATA => $self->getDER());

	# return $ret;

	# return $self->{backend}->getDigest ( 
	# 			ALGORITHM => "sha1",
	# 			DATA => $self->getPEM() );
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

sub getStatus {
    my $self = shift;
    return $self->{STATUS};
}

sub setStatus {
	my $self = shift;
	my $status = shift;

	my $status_update = undef;
	my $now = gmtime;

	## Handles special fields like SUSPENDED_AFTER, REVOKED_AFTER, etc.
	$status =~ s/\_.*//;
	if (($self->{STATUS} ne $status) and ($status !~ /VALID/)) {
		$status_update = $status . "_AFTER";
		if( $self->getParsed()->{HEADER}->{$status_update} eq "" ) {
			$self->setHeaderAttribute ( $status_update => $now );
		}
		# $self->{$status_update} = $now;
	}

	$self->{DATATYPE} = $self->{STATUS} . "_CERTIFICATE";
	$self->{STATUS} = $status;

	return $self->getStatus();
}

sub _debug {
	my $self = shift;
	my $text = join (" ", @_);

	return 1 if ( $self->{DEBUG} ne 1 );

	print STDERR "OpenCA::X509->$text\n";

	return 1;
}

# Autoload methods go after =cut, and are processed by the autosplit program.

1;
