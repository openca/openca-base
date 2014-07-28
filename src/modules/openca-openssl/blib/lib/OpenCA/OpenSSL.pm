## OpenCA::OpenSSL
##
## Copyright (C) 1998-2001 Massimiliano Pala (madwolf@openca.org)
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
## Contributions by:
##          Martin Leung <ccmartin@ust.hk>
##	    Uwe Gansert <ug@suse.de>

##
## General Errorcodes:
##
## The errorcodes consists of seven numbers:
## 1234567
## 12: module
## 34: function
## 567: errorcode
##
## The modules errorcode is 77.
##
## The functions use the following errorcodes:
##
## new			00
## setParams		01
## errno		02
## errval		03
## genKey		11
## genReq		12
## genCert		13
## crl2pkcs7		21
## dataConvert		22
## issueCert		31
## revoke		32
## issueCrl		33
## SPKAC		41
## getDigest		51
## verify		42
## sign			43
## decrypt		46
## encrypt		47
## getCertAttribute	61
## getReqAttribute	62
## getCRLAttribute	63
## pkcs7Certs		44
## updateDB		71
## getSMIME		52
## getPIN		53
## getOpenSSLDate	54
## getNumericDate	55
## getNumericDateDays	56
	

use strict;

package OpenCA::OpenSSL;

our ($errno, $errval);

use X500::DN;
use Carp;
use OpenCA::OpenSSL::SMIME;

## i18n stuff needs this
use Locale::Messages qw (:locale_h :libintl_h);
use POSIX qw (setlocale);

($OpenCA::OpenSSL::VERSION = '$Revision: 1.32 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"2\.0":""/eg;

## Global Variables Go HERE
my %params = (
	 shell => undef,
	 cnf => undef,
	 tmpDir => undef,
	 baseDir => undef,
	 verify => undef,
	 sign => undef,
	 decrypt => undef,
	 encrypt => undef,
	 errno => undef,
	 errval => undef,
         OPENSSL => undef,
         CALLBACK_HANDLER => undef,
         PIN_CALLBACK => undef,
         STDERR_CALLBACK => undef,
         STDOUT_CALLBACK => undef
);

## Create an instance of the Class
sub new {
	my $that = shift;
	my $class = ref($that) || $that;

        my $self = {
		%params,
	};

        bless $self, $class;

	my $keys = { @_ };

	$self->setParams( @_ );

	if( not $self->{binDir} ) {
		$self->{binDir} = "/usr/bin";
	};

        if( not $self->{shell} ) {
                $self->{shell} = "$self->{binDir}/openssl";
        };

	if( not $self->{openca_sv} ) {
		$self->{openca_sv} = "$self->{binDir}/openca-sv";
	}

	if( not $self->{verify} ) {
		$self->{verify} = "$self->{binDir}/openca-sv verify";
	};

	if( not $self->{sign} ) {
		$self->{sign} = "$self->{binDir}/openca-sv sign";
	};

	if( not $self->{decrypt} ) {
		$self->{decrypt} = "$self->{binDir}/openca-sv decrypt";
	};

	if( not $self->{encrypt} ) {
		$self->{encrypt} = "$self->{binDir}/openca-sv encrypt";
	};

	if( not $self->{tmpDir} ) {
		$self->{tmpDir} = '/tmp';
	};

	if( not $self->{gettext} ) {
		$self->setError (7700110, "There is no translation function specified.");
		return undef;
	};

	if( not -e $self->{openssl} ) {
		$self->setError (7700120,
                    $self->{gettext} ("There is no path to OpenSSL specified."));
		return undef;
	};

	$self->setError (0, "");

        return $self;
}


sub setParams {

	my $self = shift;
	my $params = { @_ };
	my $key;
	my $rebuild_engine = 0;

	## activate debugging
	# $self->{DEBUG} = $params->{DEBUG} if (exists $params->{DEBUG});

	foreach $key ( keys %{$params} ) {

		$self->_debug ("setParams: key: $key");
                $self->_debug ("setParams: value: $params->{$key}");

		$self->{cnf}         = $params->{$key} if ( $key =~ /CONFIG/ );
		$self->{gettext}     = $params->{$key} if ( $key =~ /GETTEXT/ );

		$self->{openssl}     = $params->{$key} if ( $key =~ /SHELL/  );
		$self->{wrapper}     = $params->{$key} if ( $key =~ /WRAPPER/ );
		$self->{ENGINE}      = $params->{$key} if ( $key =~ /^ENGINE/ );
                $self->{PRE_ENGINE}  = $params->{$key} if ( $key =~ /PRE_ENGINE/ );
                $self->{POST_ENGINE} = $params->{$key} if ( $key =~ /POST_ENGINE/ );
                $self->{DYNAMIC_ENGINE}   = $params->{$key} if ( $key =~ /DYNAMIC_ENGINE/ );
                $self->{CALLBACK_HANDLER} = $params->{$key} if ( $key =~ /CALLBACK_HANDLER/);
                $self->{GET_PIN_CALLBACK} = $params->{$key} if ( $key =~ /GET_PIN_CALLBACK/);
                $self->{PIN_CALLBACK}     = $params->{$key} if ( $key =~ /^PIN_CALLBACK/);
                $self->{STDERR_CALLBACK}  = $params->{$key} if ( $key =~ /STDERR_CALLBACK/);
                $self->{STDOUT_CALLBACK}  = $params->{$key} if ( $key =~ /STDOUT_CALLBACK/);

		$self->{KEY}         = $params->{$key} if ( $key eq "KEY" );
		$self->{KEYFORM}     = $params->{$key} if ( $key eq "KEYFORM" );
		$self->{PASSWD}      = $params->{$key} if ( $key =~ /PASSWD/ );
		$self->{PEM_CERT}    = $params->{$key} if ( $key =~ /PEM_CERT/ );

		$self->{tmpDir}      = $params->{$key} if ( $key =~ /TMPDIR/ );
		$self->{binDir}      = $params->{$key} if ( $key =~ /BINDIR/ );
		if ( $key =~ /OPENCA_SV/ )
		{
			$self->{openca_sv} = $params->{$key};
			$self->{verify}    = $self->{openca_sv}." verify";
			$self->{sign}      = $self->{openca_sv}." sign";
			$self->{decrypt}   = $self->{openca_sv}." decrypt";
			$self->{encrypt}   = $self->{openca_sv}." encrypt";
			$rebuild_engine    = 1;
		}
		$ENV{RANDFILE}  = $params->{$key} if ( $key =~ /RANDFILE/ );
		$self->{DEBUG}  = $params->{$key} if ( $key =~ /DEBUG/ );
		open STDERR, $params->{$key} if ( $key =~ /STDERR/ );
	}

	$self->{shell} = $self->{openssl};

	# add wrapper to commands that make use of private keys
	if ((exists $self->{wrapper}) and $self->{wrapper})
	{
	    foreach (qw(shell sign decrypt))
	    {
		if (exists $self->{$_})
		{
		    $self->{$_} = $self->{wrapper} . " " . $self->{$_};
		}
	    }
	}

        # set keyform if engine is in use
        if ($self->{ENGINE} and not $self->{KEYFORM})
        {
            $self->{KEYFORM} = "e";
        }

	return 1;
}

sub errno {
        my $self = shift;

        return $errno;
}

sub errval {
        my $self = shift;

        return $errval;
}

sub setError {
	my $self = shift;

	if (scalar (@_) == 4) {
		my $keys = { @_ };
		$errval	= $keys->{ERRVAL};
		$errno	= $keys->{ERRNO};
	} else {
		$errno	= $_[0];
		$errval	= $_[1];
	}

        $self->_debug ("setError: errno: $errno");
        $self->_debug ("setError: errval: $errval");

	## support for: return $self->setError (1234, "Something fails.") if (not $xyz);
	return undef;
}

sub getRandomBytes {
	my $self = shift;
	my $bytes = shift;
	my $ret = undef;

	if ( $bytes <= 0 ) {
		return undef;
	}

	$ret = OpenCA::OpenSSL::Misc::rand_bytes ( $bytes );

	return $ret;
}


sub genKey {

	## Generate a new key, arguments accepted are, in order
	##  ( BITS=>$bits, OUTFILE=>$outfile, ALGORITHM=>$alg, PASSWD=>$passwd )

	my $self = shift;
	my $keys = { @_ };

	my $bits    = $keys->{BITS};
	my $outfile = $keys->{OUTFILE};
	$outfile = $self->{KEY} if (not $outfile);
	my $alg     = $keys->{ALGORITHM};
	$alg = "aes256" if (not $alg);
	my $type    = lc($keys->{TYPE});
	my $passwd  = $keys->{PASSWD};
	$passwd = $self->{PASSWD} if (not $passwd);
	my $engine  = $self->{ENGINE};
	my $rand    = $keys->{RAND};

	## generate the parameter file if necessary

	# $self->{DEBUG} = 1;

        my $param_file = "";
	if ( lc($type) eq "dsa" ) {
	    use File::Basename;
	    $param_file  = $self->{tmpDir};
            $param_file  = dirname ($outfile) if (dirname ($outfile));
	    $param_file .= "/dsa_param.$$";

	    my $command = "dsaparam -out $param_file ";
	    if( $engine ) {
		$command .= "-engine $engine ";
            }
	    if ($bits) {
                $command .= $bits;
	        undef $bits;
            } else {
                $command .= "2048";
            }

	    if (not $self->_execute_command (COMMAND => $command, KEY_USAGE => $engine)) {
		$self->setError (7711005,
                    $self->{gettext} ("OpenCA::OpenSSL->genKey: Cannot execute command (__ERRNO__). __ERRVAL__",
                                      "__ERRVAL__", $self->errval,
                                      "__ERRNO__", $self->errno));
		return undef;
	    }
	}

	## generate the key

	my $command = "";

	if ($type) {
		$self->_debug ( "genKey -> type is $type!");
		if( $type =~ /^ecdsa$/i ) {
			$command .= "ecparam -genkey -noout ";
		} else {
			$command .= "gen".lc($type)." ";
		}
	} else {
		$command .= "genrsa ";
	}

	if( $engine ) {
		$command .= "-engine $engine ";
        }

	if( ($passwd) and (lc($type) ne "ecdsa")) {
		$command .= "-passout env:pwd ";
		$alg = "aes256 " if ( not(defined($alg)) or $alg eq "" );

		if ( defined($alg) && $alg ne "" ) {
			$command .= "-$alg ";
		}
	}

	if ( defined($outfile) && $outfile ne "" ) {
		$command .= "-out $outfile ";
	}

	if ( defined($rand) && $rand ne "" ) {
		$command .= "-rand $rand ";
	} else {
		$ENV{'RANDFILE'} = $self->{tmpDir}."/.rand_${$}";
	}

	if ($param_file) {
		## DSA
		$command .= $param_file;
	} elsif ( $type =~ /^ecdsa$/i ) {
		if( defined($bits) ) {
			if ( $bits <= 112 ) {
				$command .= " -name secp112r1 ";
			} elsif ( $bits <= 128 ) {
				$command .= " -name secp128r1 ";
			} elsif ( $bits <= 160 ) {
				$command .= " -name secp160r1 ";
			} elsif ( $bits <= 192 ) {
				$command .= " -name prime192v1 ";
			} elsif ( $bits <= 224 ) {
				$command .= " -name secp224r1 ";
			} elsif ( $bits <= 256 ) {
				$command .= " -name prime256v1 ";
			} elsif ( $bits <= 384 ) {
				$command .= " -name secp384r1 ";
			} elsif ( $bits <= 521 ) {
				$command .= " -name secp521r1 ";
			} else {
				#not supported, let's default to 224
				$command .= " -name secp224r1 ";
				$self->setError (7711006,
                    			$self->{gettext} ("OpenCA::OpenSSL->genKey: You must specify a key length less or equal to 521 for ECDSA keys."));
				$self->_debug ( "genKey -> ERROR::type is ECDSA but bits is $bits!");
				return undef;
			}
		} else {
			$self->setError (7711007,
                    		$self->{gettext} ("OpenCA::OpenSSL->genKey: You must specify a key length for ECDSA keys."));
				$self->_debug ( "genKey -> ERROR::type is ECDSA but bits is not defined ($bits)!");
			return undef;
		}

        } elsif (defined($bits)) {
		## RSA
		$command .= $bits;
        } else {
		$self->setError (7711008,
                    $self->{gettext} ("OpenCA::OpenSSL->genKey: You must specify a parameterfile for DSA or a the key length for RSA keys."));
		return undef;
        }

	$self->_debug ( "genKey -> INFO::Command is ($command)");

	$ENV{'pwd'} = "$passwd" if (defined($passwd));
	if (not $self->_execute_command (COMMAND => $command, KEY_USAGE => $engine)) {
		$self->setError (7711011,
                    $self->{gettext} ("OpenCA::OpenSSL->genKey: Cannot execute command (__ERRNO__). __ERRVAL__" . "(__COMMAND__)",
                                      "__ERRVAL__", $self->errval,
                                      "__ERRNO__", $self->errno),
				      "__COMMAND__", $command );
		delete ($ENV{'pwd'}) if( defined($passwd));
		return undef;
	}

	if( ($passwd) and (lc($type) eq "ecdsa" )) {
		my $encCommand = "";

		$encCommand = "ec ";
		$encCommand .= "-passout env:pwd ";
		if( $alg ne "" ) {
			$encCommand .= "-ecdsa ";
		};

		if ( $outfile ne "" ) {
			$encCommand .= "-in \"$outfile\" -out \"$outfile\"";
		}

		$self->_execute_command( COMMAND => $encCommand,
				KEY_USAGE => $engine );
	}

	delete ($ENV{'pwd'})      if( defined($passwd));
	delete ($ENV{'RANDFILE'}) if (defined($ENV{'RANDFILE'}));

	if( not defined( $rand )) {
		unlink( $self->{tmpDir}."/.rand_${$}" );
	}

	if( $? != 0 ) {
		$self->setError (7711021,
                    $self->{gettext} ("OpenCA::OpenSSL->genKey: OpenSSL fails (__ERRNO__).",
                                      "__ERRNO__", $?));
		return undef;
	}

	return 1;
}

sub genReq {

	## Generate a Request file, parameter accepted are
	## ( $outfile, $keyfile, $passwd , [email, cn, ou, o, c ] )
	## To utilize null passwd simply pass a "" reference.

	my $self = shift;
	my $keys = { @_ };

	my $engine = $self->{ENGINE};

	my $outfile = $keys->{OUTFILE};
	my $outform = $keys->{OUTFORM};
	my $keyfile = $keys->{KEYFILE};
	$keyfile = $self->{KEY} if (not $keyfile);
	my $subject = $keys->{SUBJECT};
	my $noemaildn = $keys->{NOEMAILDN};
	my $passwd  = $keys->{PASSWD};
	my $extensions = $keys->{EXTENSIONS};
	$passwd = $self->{PASSWD} if (not $passwd);
	my $command = "req -new ";
	my $tmpfile = $self->{tmpDir} . "/${$}_req.pem";
	my ( $ret, $tmp );

	if( not $keyfile ) {
		$self->setError (7712011,
                    $self->{gettext} ("OpenCA::OpenSSL->genReq: No keyfile specified."));
		return undef;
	}

	## fix DN-handling of OpenSSL
	if ($subject) {
		$subject =~ s/\w+=\s*\,//g;
		$subject =~ s/\w+=\s*$//;
		# $self->setError(7712014,"NEW SUBJECT => $subject");
		# return undef;

                $self->_debug ("genReq: subject_rfc2253: $subject");
		my $dn_obj = X500::DN->ParseRFC2253 ($subject);
		if (not $dn_obj) {
			$self->setError (7712013,
			    $self->{gettext} ("OpenCA::OpenSSL->genReq: Cannot build X500::DN-object from subject __SUBJECT__",
                                              "__SUBJECT__", $subject));
			return undef;
		}
		$subject = $dn_obj->getOpenSSLString ();
                $self->_debug ("genReq: subject_x500: $subject");
	} else {
                $self->_debug ("genReq: the subject of the request is not defined");
		$self->setError (7712015,
                    $self->{gettext} ("OpenCA::OpenSSL->genReq: The subject of the request is not defined."));
		return undef;
        }

 	if ( defined($self->{cnf}) && $self->{cnf} ne "" ) {
		$command .= "-config " . $self->{cnf} . " ";
	}

	if (not $self->{PIN_CALLBACK} and not $self->{GET_PIN_CALLBACK})
	{
	 	$command .= "-passin env:pwd " if ( defined($passwd) && $passwd ne "" );
	}

	if( $keys->{NOEMAILDN} ) {
	 	$subject =~ s/emailAddress=[^\/\,]+\,*\/*//gi;
	 	$subject =~ s/(\,*|\/*)$//;
	 	$subject =~ s/^\/\//\//;
	} else {
		$subject =~ s/EMAILADDRESS\s*=/emailAddress=/g;
	}

	$command .= "-subj \"$subject\" ";
        $command .= "-multivalue-rdn " if ($subject =~ /[^\\](\\\\)*\+/);

	if( $engine ) {
                $command .= "-engine $engine -keyform ".$self->{KEYFORM}." ";
        }

	if( $extensions ) {
		$command .= "-reqexts \"$extensions\" ";
	}

	if( defined($outform) ) {
		$outform = uc( $outform );

		if ( $outform =~ /(PEM|DER)/i ) {
			$command .= "-outform $outform ";
		} elsif ( $outform =~ /(TXT)/ ) {
			$command .= "-text -noout ";
		}
  	}

	$command .= "-key $keyfile ";

	if ( $outfile ne "" ) {
		$command .= "-out $outfile ";
	} else {
		$command .= " -out $tmpfile ";
	}
	
	$ENV{'pwd'} = "$passwd" if( defined($passwd));
	if (not $self->_execute_command (COMMAND => $command, KEY_USAGE => $engine)) {
		$self->setError (7712071,
                    $self->{gettext} ("OpenCA::OpenSSL->genReq: Cannot execute command (__ERRNO__). __ERRVAL__",
                                      "__ERRVAL__", $self->errval,
                                      "__ERRNO__",  $self->errno));
		delete( $ENV{'pwd'} ) if( defined($passwd) );
		return undef;
	}
	delete( $ENV{'pwd'} ) if( defined($passwd) );

	if( not defined $outfile or $outfile eq "" ) {
		if (not open( FD, "<$tmpfile" )) {
			$self->setError (7712081,
                            $self->{gettext} ("OpenCA::OpenSSL->genReq: Cannot open tmpfile __FILENAME__ for reading.",
                                              "__FILENAME__", $tmpfile));
			return undef;
		}
		while( $tmp = <FD> ) {
			$ret .= $tmp;
		}
		close(FD);
		unlink( "$tmpfile" );

		return $ret;
	}

	
	return 1;
}

sub genCert {

	## Generate a new Certificate file, parameter accepted are
	## (OUTFILE=>$outfile,KEYFILE=>$keyfile,REQFILE=>$reqfile,
	## PASSWD=>$passwd, DN=>[ @list ] )

	my $self = shift;
	my $keys = { @_ };

	my $outfile = $keys->{OUTFILE};
	my $keyfile = $keys->{KEYFILE};
	$keyfile = $self->{KEY} if (not $keyfile);
	my $reqfile = $keys->{REQFILE};
	my $subject = $keys->{SUBJECT};
	my $noemail = $keys->{NOEMAILDN};
	my $passwd  = $keys->{PASSWD};
	$passwd = $self->{PASSWD} if (not $passwd);
	my $days    = $keys->{DAYS};
	my $tmpfile = $self->{tmpDir} . "/${$}_crt.tmp";

	my $engine  = $self->{ENGINE};

	my $extfile = $keys->{EXTFILE};
	my $extensions  = $keys->{EXTENSIONS};

	## fix DN-handling of OpenSSL
	if ($subject) {
		$subject =~ s/\w+=\s*\,//g;
		$subject =~ s/\w+=\s*$//;
		# $self->setError(7712014,"NEW SUBJECT => $subject");
		# return undef;

                $self->_debug ("genReq: subject_rfc2253: $subject");
		my $dn_obj = X500::DN->ParseRFC2253 ($subject);
		if (not $dn_obj) {
			$self->setError (7713013,
			    $self->{gettext} ("OpenCA::OpenSSL->genCert: Cannot build X500::DN-object from subject __SUBJECT__.",
                                              "__SUBJECT__", $subject));
			return undef;
		}
		$subject = $dn_obj->getOpenSSLString ();
                $self->_debug ("genReq: subject_x500: $subject");
	}

	my $command = "ca -batch -selfsign ";

	my ( $ret, $tmp );

	if (not $keyfile) {
		$self->setError (7713015,
                    $self->{gettext} ("OpenCA::OpenSSL->genCert: No keyfile specified."));
		return undef;
	}
	if (not $reqfile) {
		$self->setError (7713016,
                    $self->{gettext} ("OpenCA::OpenSSL->genCert: No requestfile specified."));
		return undef;
	}

        if( $engine ) {
                $command .= "-engine $engine -keyform ".$self->{KEYFORM}." ";
        }

	if ( defined($subject) && ($subject ne "") ) {

		# if( $keys->{NOEMAILDN} ) {
		 # 	$subject =~ s/emailAddress=[^\/\,]+\,*\/*//gi;
		 # 	$subject =~ s/(\,*|\/*)$//;
		 # 	$subject =~ s/^\/\//\//;
		# };

		if ( $subject =~ /EMAILADDRESS\s*=/ ) {
			$subject =~ s/EMAILADDRESS\s*=/emailAddress=/g;
		}

		$command .= " -subj \"$subject\" ";
	};

        $command .= "-multivalue-rdn " if ($subject and $subject =~ /[^\\](\\\\)*\+/);

	if (not $self->{PIN_CALLBACK} and not $self->{GET_PIN_CALLBACK})
	{
		$command .= "-passin env:pwd " 
			if ( defined($passwd) && $passwd ne "" );
	}

	$command .= "-config ". $self->{cnf} . " "
		if ( defined($self->{'cnf'}) && $self->{cnf} ne "" );

	$command .= "-days $days " 
		if ( defined($days) && $days =~ /\d+/ && $days > 0 );

	$command .= "-in \"$reqfile\" -keyfile \"$keyfile\" ";

	$command .= "-extensions \"" . $extensions . "\" " if( $extensions );
	$command .= qq{ -extfile "$extfile" } if ( $extfile );

	if( defined($outfile) && $outfile ne "" ) {
		$command .= "-out \"$outfile\" ";
	} else {
		$command .= "-out \"$tmpfile\" ";
	}

	$ENV{'pwd'} = "$passwd" if( defined($passwd) );

        $ret = $self->_execute_command (COMMAND => $command, 
						KEY_USAGE => $engine);

	delete( $ENV{'pwd'} ) if( defined($passwd) );

	if( not $ret ) {
		$self->setError (7713071,
                    $self->{gettext} ("OpenCA::OpenSSL->genCert: OpenSSL failed (__ERRNO__). __ERRVAL__",
                                      "__ERRNO__", $self->errno,
                                      "__ERRVAL__", $self->errval));
		return undef;
	}

	if( not(defined($outfile)) or $outfile eq "" ) {
		if (not open( FD, "<$tmpfile" )) {
			$self->setError (7713081,
                            $self->{gettext} ("OpenCA::OpenSSL->genCert: Cannot open tmpfile __FILENAME__ for reading.",
                                              "__FILENAME__", $tmpfile));
			return undef;
		}
		while( $tmp = <FD> ) {
			$ret .= $tmp;
		}
		close(FD);
		unlink( "$tmpfile" );
	}

	return "$ret";
}

sub crl2pkcs7 {
	my $self = shift;
	my $keys = { @_ };

	my $data    = $keys->{DATA};
	my $crlfile = $keys->{CRLFILE};
	my $inform  = $keys->{INFORM};
	my $outfile = $keys->{OUTFILE};
	my $outform = $keys->{OUTFORM};

	my ( $ret, $tmp, $tmpfile, $command, $nocrl );
	$command = "crl2pkcs7 ";

	if( (not(defined($data)) or $data eq "") and
			(not(defined($crlfile)) or $crlfile eq "" )) {
		$nocrl = 1;
		$command .= "-nocrl ";
	} else {
		$nocrl = 0;
	}

	if ( not defined $crlfile or $crlfile eq "" ){
		$tmpfile = $self->{tmpDir} . "/${$}_incrl.tmp";
		if (not open( FD, ">$tmpfile" )) {
			$self->setError (7721011,
                            $self->{gettext} ("OpenCA::OpenSSL->crl2pkcs7: Cannot open tmpfile __FILENAME__ for writing.",
                                              "__FILENAME__", $tmpfile));
			return undef;
		}
		print FD "$data";
		close( FD );
	} else {
		$tmpfile = $crlfile;
	}
	$command .= "-in $tmpfile " if( $nocrl == 1 );

	$command .= "-out $outfile "
		if ( defined($outfile) and $outfile ne "");
	$command .= "-inform $inform "
		if ( defined($inform) and $inform ne "");
	$command .= "-outform $outform "
		if ( defined($outform) and $outform ne "");

	if( defined $keys->{CERTSLIST} ) {
		my @certs = @{ $keys->{CERTSLIST}};

		for (@certs) {
			$command .= "-certfile $_ "
				if( ("$_" ne "") and (-f "$_") );
		}
	}

	$ret = $self->_execute_command (COMMAND => $command);
	if(not $ret) {
		$self->setError (7721071,
                    $self->{gettext} ("OpenCA::OpenSSL->crl2pkcs7: OpenSSL fails (__ERRNO__). __ERRVAL__",
                                      "__ERRNO__", $self->errno,
                                      "__ERRVAL__", $self->errval));
		$ret = undef;
	} else {
		$ret = 1 if( $outfile ne "" );
	}
	unlink("$tmpfile") if ( $crlfile eq "" );

	return $ret;
}

sub dataConvert {

	## You can convert data structures to different formats
	## Accepted parameters are:
	##
	##    DATATYPE=> CRL|CERTIFICATE|REQUEST|KEY
	##    OUTFORM => PEM|DER|NET|TXT|PKCS12|PKCS8
	##    INFORM  => PEM|DER|NET|TXT|PKCS12|PKCS8
	##    OUTFILE => $outfile
	##    INFILE  => $infile
	##    DATA    => $data
	##    KEYFILE => $keyfile
	##    CACERT  => $cacert

	##    PKCS12 encode parameter :
	##    INFILE or DATA (must be PEM encoded)
	##    KEYFILE (might be in front of the DATA or in INFILE)
	##    P12PASSWD = password for pkcs12 file (optional)
	##    PASSWD  = password for KEYFILE (optional)
	##    INPASSWD  = password for KEYFILE (optional)
	##    OUTPASSWD  = password for KEYFILE (optional)
	##    OUTFILE = optional
	##    ALGO    = optionl, default = des3
	##    DATATYPE must be 'CERTIFICATE'
	##    CACERT	= add additional cacert to pkcs#12

	##    PKCS12 decode parameter
	##    INFILE or DATA (must be PKCS12 encoded)
	##    P12PASSWD
	##    PASSWD (PEM password optional)
	##    OUTFILE = optional
	##    DATATYPE must be 'CERTIFICATE'	

	##    KEY encode/decode parameter
	##    PUBOUT = true value - output only the public key?
	##    PUBIN  = true value - input is only the public key?

	my $self = shift;
	my $keys = { @_ };

	my $data    = $keys->{DATA};
	my $type    = $keys->{DATATYPE};
	my $outform = $keys->{OUTFORM};
	my $encoding= $keys->{ENCODING};
	my $inform  = $keys->{INFORM};
	my $outfile = $keys->{OUTFILE};
	my $infile  = $keys->{INFILE};
	my $keyfile = $keys->{KEYFILE};
	$keyfile = $self->{KEY} if (not $keyfile);
	my $passwd  = $keys->{'PASSWD'};
	$passwd = $self->{PASSWD} if (not $passwd and
	                              not exists $keys->{'OUTPASSWD'} and
	                              not exists $keys->{'INPASSWD'});
	my $p12pass = $keys->{'P12PASSWD'};
	my $inpwd   = $keys->{'INPASSWD'};
	my $outpwd  = $keys->{'OUTPASSWD'};
	my $algo    = $keys->{'ALGO'} || 'des3';
	my $nokeys  = $keys->{'NOKEYS'};
	my $cacert  = $keys->{'CACERT'};
	$cacert = $self->{PEM_CERT} if (not $cacert);
	my $pubin   = $keys->{'PUBIN'};
	my $pubout  = $keys->{'PUBOUT'};

	my ( $command, $tmp, $ret, $tmpfile );

	## rest errordetection
	if( $? != 0 ) {
                $self->_debug ("dataConvert: resetting error from ${?} to 0.");
		$? = 0;
	}
	if( $errno != 0 ) {
                $self->_debug ("dataConvert: resetting errno from $errno to 0.");
		$self->setError (0, "");
	}

	if ( not $type) {
		$self->setError (7722011,
                    $self->{gettext} ("OpenCA::OpenSSL->dataConvert: No datatype specified."));
		return undef;
	}
	if ( (not $data) and (not $infile) and ($type =~ /KEY/)) {
		$infile = $self->{KEY};
	}
	if ( (not $data) and (not $infile)) {
		$self->setError (7722012,
                    $self->{gettext} ("OpenCA::OpenSSL->dataConvert: No input data specified."));
		return undef;
	}
	if ( not $algo =~ /des3|des|idea/ ) {
		$self->setError (7722013,
                    $self->{gettext} ("OpenCA::OpenSSL->dataConvert: Unsupported algorithm specified."));
		return undef;
	}
	if ( defined($nokeys) and ($outform eq 'PKCS12') ) {
		$self->setError (7722014,
		    $self->{gettext} ("OpenCA::OpenSSL->dataConvert: No keys available but the output format is PKCS#12."));
		return undef;
	}

	## Return if $infile does not exists
	if( $infile and ( not -e $infile )) {
		$self->setError (7722015,
                    $self->{gettext} ("OpenCA::OpenSSL->dataConvert: The specified inputfile doesn't exist."));
		return undef;
	}
	if (not $infile) {
		$infile = $self->{tmpDir} . "/${$}_data.tmp";
                $self->_debug ("dataConvert: create temporary infile $infile");
                $self->_debug ("dataConvert: the data is like follows");
                $self->_debug ("dataConvert: $data");
		if (not  open FD, ">".$infile) {
                        $self->_debug ("dataConvert: failed to open temporary infile $infile");
			$self->setError (7722041,
			    $self->{gettext} ("OpenCA::OpenSSL->dataConvert: Cannot write inputdata to tmpfile __FILENAME__.",
                                              "__FILENAME__", $infile));
			return undef;
		}
		print FD $data;
		close FD;
	} else {
		$data = 0;
	}

	$outform = "PEM" if( not $outform ); 
	$inform  = "PEM" if( not $inform ); 

	$tmpfile = "$self->{tmpDir}/${$}_cnv.tmp";
	$command = "";

	if( $type =~ /CRL/i ) {
		$command .= "crl ";
	} elsif ( $type =~ /CERTIFICATE/i ) {
		if( $outform eq 'PKCS12' or $inform eq 'PKCS12' ) {
			$command .= 'pkcs12 ';
		} else {
			$command .= "x509 -nameopt RFC2253,-esc_msb ";
		}
	} elsif ( $type =~ /REQ/i ) {
		$command .= "req -nameopt RFC2253,-esc_msb ";
 		if ( defined($self->{cnf}) && $self->{cnf} ne "" ) {
			$command .= "-config " . $self->{cnf} . " ";
		}
	} elsif ( $type =~ /KEY/i ) {
		## PKCS8 enforces PEM because the OpenSSL command req can
		## only handle PEM-encoded PKCS#8 keys
		if ( ($outform =~ /PKCS8/i) or ($inform =~ /PKCS8/i) ) {
			$command .= "pkcs8 ";
		} else {
			$command .= "rsa ";
		}
		if ( $pubout ) {
			$command .= " -pubout ";
		}
		if ( $pubin ) {
			$command .= " -pubin ";
		}
		if (not $inpwd) {
			$inpwd = $passwd;
		}
		if (not $inpwd) {
			## unlink ($infile) if ($data);
			## $self->setError (7722018,
			## 		"OpenCA::OpenSSL->dataConvert: Cannot convert key without input passphrase.");
			## return undef;
		} else {
			$command .= ' -passin env:inpwd ';
		}
		if (not $outpwd) {
			$outpwd = $passwd;
		}
		if (not $outpwd) {
			## unlink ($infile) if ($data);
			## $self->setError (7722019,
			## 		"OpenCA::OpenSSL->dataConvert: Cannot convert key without output passphrase.");
			## return undef;

			## I had to comment this one out. In my version of
			## openssl (0.9.7a-1) it is not necessary nor
			## recognized.
			#$command .= ' -nocrypt ';
		} else {
			$command .= ' -passout env:outpwd ';
		}
	} else {
		## if no known type is given...
		$self->setError (7722021,
		    $self->{gettext} ("OpenCA::OpenSSL->dataConvert: The datatype which should be converted is not known."));
		unlink ($infile) if ($data);
		return undef;
	}

	$outfile = $tmpfile if ( not $outfile );

	$command .= "-out $outfile ";
	$command .= "-in $infile "; 
	$command .= "-inkey $keyfile " if( defined($keyfile) and ($inform eq 'PKCS12' or $outform eq 'PKCS12')); #PKCS12 only

	# outform in PKCS12 is always PEM
	if( $outform =~ /TXT/i ) {
		## FIXME: noout was removed because of a bug in OpenSSL 0.9.7
		## FIXME: the crl command returns an error if -noout is in use
		## $command .= "-text -noout ";
		$command .= "-text ";
	} elsif ( $outform =~ /(PEM|DER|NET)/i ) {
		if( $inform eq 'PKCS12' ) {
			$command .= '-passout env:pempwd 'if( defined($passwd) );
			$command .= '-passin env:p12pwd ' if( defined($p12pass) );
			$command .= '-nokeys ' if( defined($nokeys) );
			if( defined($passwd) ) {
	                        $command .= "-$algo " if( $algo eq 'des' or
                                                          $algo eq 'des3' or
                                                          $algo eq 'idea' );
			} else {
				$command .= '-nodes' if( not defined($passwd) );
			}
		} else {
			$command .= "-outform " . uc($outform) . " ";
		}
	} elsif ( $outform eq 'PKCS12' ) {
		$command .= "-export ";
		$command .= '-passout env:p12pwd ';
		$command .= '-passin env:pempwd ' if( defined($passwd) );
		$command .= "-certfile $cacert " if(defined($cacert));
	} elsif ( $outform =~ /PKCS8/i ) {
		$command .= " -topk8 ";
		$command .= " -nocrypt " if (not $outpwd);
		if ($encoding) {
			$command .= " -outform ".uc($encoding)." ";
		} else {
			$command .= " -outform PEM ";
		}
	} else {
		## no valid format received...
                $self->_debug ("dataConvert: failed to determine the output format ($outform)");
		unlink ($infile) if ($data);
		$self->setError (7722024,
		    $self->{gettext} ("OpenCA::OpenSSL->dataConvert: The output format is unknown or unsupported."));
		return undef;
	}

	if( $outform ne 'PKCS12' ) {
		if( $inform =~ /(PEM|DER|NET)/i ) {
			$command .= "-inform " . uc($inform) ." ";
		} elsif( $inform eq 'PKCS12' ) {
	 		# nothing to do here.
		} elsif( $inform eq 'PKCS8' ) {
	 		# nothing to do here.
		} else {
			## no valid format received ...
                        $self->_debug ("dataConvert: failed to determine the input format ($inform)");
			unlink ($infile) if ($data);
			$self->setError (7722026,
			    $self->{gettext} ("OpenCA::OpenSSL->dataConvert: You don't try to convert to PKCS#12 but the input format is unknown or unsupported."));
			return undef;
		}
	}

        $self->_debug ("dataConvert: p12pass is set") if( defined($p12pass) );
        $self->_debug ("dataConvert: passwd is set")  if( defined($passwd) );
        $self->_debug ("dataConvert: inpwd is set")   if( defined($inpwd) );
        $self->_debug ("dataConvert: outpwd is set")  if( defined($outpwd) );
        $self->_debug ("dataConvert: command=$command");

	if( $? != 0 ) {
		$self->setError (7722069,
                    $self->{gettext} ("OpenCA::OpenSSL->dataConvert: Unkown Error detected before OpenSSL starts (__ERRNO__)",
                                      "__ERRNO__", $?));
		unlink ($infile) if ($data);
		return undef;
	}

	$ENV{'p12pwd'} = "$p12pass" if( defined($p12pass) );
	$ENV{'pempwd'} = "$passwd"  if( defined($passwd) );
	$ENV{'inpwd'}  = "$inpwd"   if( defined($inpwd) );
	$ENV{'outpwd'} = "$outpwd"  if( defined($outpwd) );

	if( defined($infile) && $infile ne "" ) {
                $self->_debug ("dataConvert: using infile");
		$ret=$self->_execute_command (COMMAND => $command);
	} else {
                $self->_debug ("dataConvert: data piping is no longer supported - please use tmp files");
		$self->setError (7722071,
		    $self->{gettext} ("OpenCA::OpenSSL->dataConvert: Data piping is no longer supported."));
		return undef;
	}
        $self->_debug ("dataConvert: openssl itself successful");

	delete($ENV{'pwd'});
	delete($ENV{'pempwd'});
	delete($ENV{'inpwd'});
	delete($ENV{'outpwd'});
        $self->_debug ("dataConvert: passphrases deleted");

	if( not $ret ) {
		$self->setError (7722073,
                    $self->{gettext} ("OpenCA::OpenSSL->dataConvert: OpenSSL failed (__ERRNO__). __ERRVAL__",
                                      "__ERRNO__", $self->errno,
                                      "__ERRVAL__", $self->errval));
		unlink ($tmpfile) if (not $keys->{OUTFILE});
		unlink ($infile) if ($data);
		return undef;
	}

	unlink ($infile) if ($data);

	if( $keys->{OUTFILE} ) {
                $self->_debug ("dataConvert: return 1 and infile deleted if temporary");
		return 1;
	}

	$ret = "";
	if (not open( TMP, "<$outfile" )) {
                $self->_debug ("dataConvert: cannot open outfile $outfile for reading");
		$self->setError (7722081,
                    $self->{gettext} ("OpenCA::OpenSSL->dataConvert: Cannot open outfile __FILENAME__ for reading.",
                                      "__FILENAME__", $outfile));
		return undef;
	}
	while( $tmp = <TMP> ) {
		$ret .= $tmp;
	}
	close( TMP );
	unlink ($outfile);

        $self->_debug ("dataConvert: return result like follows");
        $self->_debug ("dataConvert: $ret");
	return $ret;
		
}

sub issueCert {

	## Use this function to issue a certificate using the
	## ca utility. Use this if you already own a valid CA
	## certificate. Accepted parameters are:

	## REQDATA     => $data
	## REQFILE     => $reqfilename
	## INFORM      => PEM|DER|NET|SPKAC   ; defaults to PEM
	## PRESERVE_DN => Y/N		  ; defaults to Y/N
	## CAKEY       => $CAkeyfile
	## CACERT      => $CAcertfile
	## DAYS        => $days
	## PASSWD      => $passwd
	## EXTS        => $extentions
	## NOEMAILDN   => -noemailDN
	## NOUNIQUEDN  => -nouniqueDN

	my $self = shift;
	my $keys = { @_ };

	my $reqdata  = $keys->{REQDATA};
	my $reqfile  = $keys->{REQFILE};
	my $inform   = $keys->{INFORM};
	my $preserve = ( $keys->{PRESERVE_DN} or "N" );
	my $cakey    = $keys->{CAKEY};
	$cakey = $self->{KEY} if (not $cakey);
	my $days     = $keys->{DAYS};
	my $startDate= $keys->{START_DATE};
	my $endDate  = $keys->{END_DATE};
	my $passwd   = $keys->{PASSWD};
	$passwd = $self->{PASSWD} if (not $passwd);
	my $exts     = $keys->{EXTS};
	my $extFile  = $keys->{EXTFILE};
	my $subject  = $keys->{SUBJECT};

	my $reqfiles =$keys->{REQFILES};
	my $outdir   =$keys->{OUTDIR};
	my $caName   = $keys->{CA_NAME};
	
	my $engine   = $self->{ENGINE};

	my ( $ret, $tmpfile );

	## fix DN-handling of OpenSSL
	if ($subject) {

		## OpenSSL includes a bug in -nameopt RFC2253
		## = signs are not escaped if they are normal values
		my $i = 0;
		my $now = "name";
		while ($i < length ($subject))
		{
			if (substr ($subject, $i, 1) =~ /\\/)
			{
				$i++;
			} elsif (substr ($subject, $i, 1) =~ /=/) {
				if ($now =~ /value/)
				{
					## OpenSSL forgets to escape =
					$subject = substr ($subject, 0, $i)."\\".substr ($subject, $i);
					$i++;
				} else {
					$now = "value";
				}
			} elsif (substr ($subject, $i, 1) =~ /[,+]/) {
				$now = "name";
			}
			$i++;
		}

		$subject =~ s/\w+=\s*\,//g;
		$subject =~ s/\w+=\s*$//;
		# $self->setError(7712014,"NEW SUBJECT => $subject");
		# return undef;

                $self->_debug ("issueCert: subject_rfc2253: $subject");
		my $dn_obj = X500::DN->ParseRFC2253 ($subject);
                $self->_debug ("issueCert: subject parsed by X500::DN");
		if (not $dn_obj) {
                        $self->_debug ("issueCert: cannot create X500::DN-object");
			$self->setError (7731001,
                            $self->{gettext} ("OpenCA::OpenSSL->issueCert: Cannot create X500::DN-object."));
			return undef;
		}
		$subject = $dn_obj->getOpenSSLString ();
                $self->_debug ("issueCert: subject_x500: $subject");
	}

	#return if( (not $reqdata) and (not $reqfile));
	# to make multi certs you need to tell openssl 
	# what directory to put it.
	if( (not $reqdata) and (not $reqfile) and
	    ((not $reqfiles) or (not $outdir)) ) {
		$self->setError (7731011,
                    $self->{gettext} ("OpenCA::OpenSSL->issueCert: No request specified."));
		return undef;
	}
	if (not $reqfile and not $reqfiles) {
		$reqfile = $self->{tmpDir} . "/${$}_req.tmp";
                $self->_debug ("issueCert: create temporary reqfile $reqfile");
                $self->_debug ("issueCert: the data is like follows");
                $self->_debug ("issueCert: $reqdata");
		if (not  open FD, ">".$reqfile) {
                        $self->_debug ("issueCertConvert: failed to open temporary reqfile $reqfile");
			$self->setError (7731015,
			    $self->{gettext} ("OpenCA::OpenSSL->issueCert: Cannot write inputdata to tmpfile __FILENAME__.",
                                              "__FILENAME__", $reqfile));
			return undef;
		}
		print FD $reqdata;
		close FD;
	} else {
		$reqdata = 0;
	}

	$inform   = "PEM" if( not $inform ); 

	my $command = "ca -batch ";
	## activate this if you have a patched OpenSSL 0.9.8
	## $command .= "-multivalue-rdn ";

        if( $engine ) {
                $command .= "-engine $engine -keyform ".$self->{KEYFORM}." ";
        }

	$command .= "-config " .$self->{cnf}." " if ( $self->{cnf} );
	$command .= "-keyfile $cakey " if( $cakey );
	if (not $self->{PIN_CALLBACK} and not $self->{GET_PIN_CALLBACK})
	{
		$command .= "-passin env:pwd " if ( $passwd ne "" );
	}
	$command .= "-days $days " if ( $days );
	$command .= "-extfile $extFile " if ( $extFile );
	$command .= "-extensions $exts " if ( $exts );
	$command .= "-preserveDN " if ( $preserve =~ /Y/i );
	$command .= "-startdate $startDate " if ( $startDate );
	$command .= "-enddate $endDate " if ( $endDate );
	$command .= "-name $caName " if ( $caName );
	$command .= "-subj \"$subject\" " if ( $subject );
        $command .= "-multivalue-rdn " if ($subject and $subject =~ /[^\\](\\\\)*\+/);
	$command .= "-noemailDN " if ( $keys->{NOEMAILDN} );
	$command .= "-nouniqueDN " if ( $keys->{NOUNIQUEDN} );

	if( $inform =~ /(PEM|DER|NET)/i ) {

		#this has to be the last option
		$command .= "-outdir $outdir " if ($outdir);
		$command .=  "-infiles @$reqfiles" if ($reqfiles);

		$command .= "-in $reqfile " if ( $reqfile );
	} elsif ( $inform =~ /SPKAC/ ) {
		if ( not $reqfile ) {
			$self->setError (7731012,
			    $self->{gettext} ("OpenCA::OpenSSL->issueCert: You must specify a requestfile if you use SPKAC."));
			return undef;
		}
		$command .= "-spkac $reqfile ";
	} else {
		## no valid format received ...
		$self->setError (7731013,
		    $self->{gettext} ("OpenCA::OpenSSL->issueCert: The requests format (__FORMAT__) is not supported.",
                                      "__FORMAT__", $inform));
		return undef;
	}

	## running the OpenSSL command
        $self->_debug ("issueCert: openssl=$command");
	$ENV{'pwd'} = "$passwd";
        $ret = $self->_execute_command (COMMAND => $command, KEY_USAGE => $engine);
	delete ($ENV{'pwd'});
	unlink ($reqfile) if ($reqdata);
	if( not $ret ) {
		$self->setError (7731075,
                    $self->{gettext} ("OpenCA::OpenSSL->issueCert: OpenSSL fails (__ERRNO__). __ERRVAL__",
                                      "__ERRNO__", $self->errno,
                                      "__ERRVAL__", $self->errval));
		return undef;
	}

        $self->_debug ("issueCert: certificate issued successfully");
	return 1;
}

sub revoke {

	## CAKEY  => $CAkeyfile (Optional)
	## CACERT => $CAcertfile (Optional)
	## PASSWD => $passwd (Optional - if not needed)
	## INFILE => $certFile (PEM Formatted certificate file);
	## CRL_REASON => Reason for revocation
	## 	unspecified
	##	keyCompromise
	##	CACompromise
	##	affiliationChanged
	## 	superseded
	##	cessationOfOperation
	##	certificateHold
	##	removeFromCRL
	##	holdInstruction
	##	keyTime
	##	CAkeyTime

	my $self = shift;
	my $keys = { @_ };

	my $cakey    = $keys->{CAKEY};
	$cakey = $self->{KEY} if (not $cakey);
	my $cacert   = $keys->{CACERT};
	$cacert = $self->{PEM_CERT} if (not $cacert);
	my $passwd   = $keys->{PASSWD};
	$passwd = $self->{PASSWD} if (not $passwd);
	my $certFile = $keys->{INFILE};
	my $crlReason= $keys->{CRL_REASON};

	my $engine = $self->{ENGINE};

	my ( $tmp, $ret );
	my $command = "ca -revoke $certFile ";

	if (not $certFile) {
		$self->setError (7732011,
                    $self->{gettext} ("OpenCA::OpenSSL->revoke: No inputfile specified."));
		return undef;
	}

        if( $engine ) {
                $command .= "-engine $engine -keyform ".$self->{KEYFORM}." ";
        }

	$command .= "-config " . $self->{cnf}. " " if ( defined($self->{'cnf'}) && $self->{cnf} ne "" );
	$command .= "-keyfile $cakey " if( defined($cakey) && $cakey ne "" );
	if (not $self->{PIN_CALLBACK} and not $self->{GET_PIN_CALLBACK})
	{
		$command .= "-passin env:pwd " if ( defined($passwd) && $passwd ne "" );
	}
	$command .= "-cert $cacert " if ( defined($cacert) && $cacert ne "" );
	$command .= "-nouniqueDN " if ( $keys->{NOUNIQUEDN} );
	$command .= "-crl_reason $crlReason " if ( $keys->{CRL_REASON} );

	$ENV{'pwd'} = "$passwd";
        $ret = $self->_execute_command (COMMAND => $command, KEY_USAGE => $engine);
	delete ($ENV{'pwd'});
	if( not $ret ) {
		$self->setError (7732073,
                    $self->{gettext} ("OpenCA::OpenSSL->revoke: OpenSSL failed (__ERRNO__). __ERRVAL__" . "<br /><br />(COMMAND=>$command)",
                                      "__ERRNO__", $self->errno,
                                      "__ERRVAL__", $self->errval));
		return undef;
	} else {
		return 1;
	}
}


sub issueCrl {

	## CAKEY   => $CAkeyfile
	## CACERT  => $CAcertfile
	## PASSWD  => $passwd
	## DAYS    => $days
	## SECONDS => $seconds
	## EXTS    => $extentions
	## OUTFILE => $outfile
	## OUTFORM => PEM|DER|NET|TXT

	my $self = shift;
	my $keys = { @_ };

	my $cakey    = $keys->{CAKEY};
	$cakey = $self->{KEY} if (not $cakey);
	my $cacert   = $keys->{CACERT};
	$cacert = $self->{PEM_CERT} if (not $cacert);
	my $hours     = $keys->{HOURS};
	my $days      = $keys->{DAYS};
	my $passwd   = $keys->{PASSWD};
	$passwd = $self->{PASSWD} if (not $passwd);
	my $outfile  = $keys->{OUTFILE};
	my $outform  = $keys->{OUTFORM};
	my $exts     = $keys->{EXTS};
	my $extfile  = $keys->{EXTFILE};

	my $engine   = $self->{ENGINE};
	
	my ( $ret, $tmp, $tmpfile );
	my $command = "ca -gencrl ";

        if( $engine ) {
                $command .= "-engine $engine -keyform ".$self->{KEYFORM}." ";
        }

	if ( not defined $outfile or $outfile eq "" ){
		$tmpfile = $self->{tmpDir} . "/${$}_crl.tmp";
	} else {
		$tmpfile = $outfile;
	}
	$command .= "-out $tmpfile ";

	$command .= "-config " . $self->{cnf}. " " if ( defined($self->{'cnf'}) && $self->{cnf} ne "" );
	$command .= "-keyfile $cakey " if( defined($cakey) && $cakey ne "" );
	if (not $self->{PIN_CALLBACK} and not $self->{GET_PIN_CALLBACK})
	{
		$command .= "-passin env:pwd " if ( defined($passwd) && $passwd ne "" );
	}
	$command .= "-cert $cacert " if ( defined($cacert) && $cacert ne "" );
	$command .= "-crldays $days " if ( defined($days) && $days ne "" );
	$command .= "-crlhours $hours " if ( defined($hours) && $hours ne "" );
	$command .= "-crlexts $exts " if ( defined($exts) && $exts ne "" );
	$command .= "-extfile $extfile " if ( defined($extfile) && $extfile ne "" );
	$command .= "-nouniqueDN " if ( $keys->{NOUNIQUEDN} );

	$ENV{'pwd'} = "$passwd";
	$ret = $self->_execute_command (COMMAND => $command, KEY_USAGE => $engine);
	delete( $ENV{'pwd'} );

	if( not $ret ) {
		$self->setError (7733071,
                    $self->{gettext} ("OpenCA::OpenSSL->issueCrl: OpenSSL failed (__ERRNO__). __ERRVAL__",
                                      "__ERRNO__", $self->errno,
                                      "__ERRVAL__", $self->errval));
		return undef;
	}

	$ret = $self->dataConvert( INFILE  =>$tmpfile,
				   OUTFORM =>$outform,
				   DATATYPE=>"CRL" );

	if( not $ret ) {
		$self->setError (7733082,
                    $self->{gettext} ("OpenCA::OpenSSL->issueCrl: data conversion failed (__ERRNO__). __ERRVAL__",
                                      "__ERRNO__", $self->errno(),
                                       "__ERRVAL__", $self->errval()));
		return undef;
	}

	if( defined($outfile) && $outfile ne "" ) {
		if (not open( FD, ">$outfile" )) {
			$self->setError (7733084,
                            $self->{gettext} ("OpenCA::OpenSSL->issueCrl: Cannot open outfile __FILENAME__ for writing.",
                                              "__FILENAME__", $outfile));
			return undef;
		}
		print FD "$ret";
		close( FD );
		return 1;
	}

	unlink( $tmpfile );
	return "$ret";
}

sub SPKAC {

	my $self = shift;
	my $keys = { @_ };

	my $infile  = $keys->{INFILE};
	my $outfile = $keys->{OUTFILE};
	my $spkac   = $keys->{SPKAC};

	my $command = "spkac -verify ";
	my $tmpfile = $self->{tmpDir} . "/${$}_SPKAC.tmp";

	my $engine  = $self->{ENGINE};

	my $ret = "";
	my $retVal = 0;
	my $tmp;

	if( defined($spkac) && $spkac ne "" ) {
		$infile = $self->{tmpDir} . "/${$}_in_SPKAC.tmp";
		if (not open( FD, ">$infile" )) {;
			$self->setError (7741011,
                            $self->{gettext} ("OpenCA::OpenSSL->SPKAC: Cannot open infile __FILENAME__ for writing.",
                                              "__FILENAME__", $infile));
			return undef;
		}
		print FD "$spkac\n";
		close ( FD );
	}

        if( $engine ) {
                $command .= "-engine $engine ";
        }

	$command .= "-in $infile " if( defined($infile) && $infile ne "" );
	if( defined($outfile) && $outfile ne "" ) {
		$command .= "-out $outfile ";
	} else {
		$command .= "-out $tmpfile ";
	}

        $ret = $self->_execute_command (COMMAND => $command);

	## Unlink the infile if it was temporary
	unlink $infile if( defined($spkac) && $spkac ne "");

	if (not $ret) {
		$self->setError (7741073,
                    $self->{gettext} ("OpenCA::OpenSSL->SPKAC: OpenSSL failed (__ERRNO__). __ERRVAL__",
                                      "__ERRNO__", $self->errno,
                                      "__ERRVAL__", $self->errval));
		return undef;
	}

	if( defined($outfile) && $outfile ne "" ) {
		return 1;
	}

	## Get the output
	if (not open( TMP, "$tmpfile" )) {
		$self->setError (7741081,
                    $self->{gettext} ("OpenCA::OpenSSL->SPKAC: Cannot open tmpfile __FILENAME__.",
                                      "__FILENAME__", $tmpfile));
		return undef;
	}
	while ( $tmp = <TMP> ) {
		$ret .= $tmp;
	}
	close( TMP );
	unlink $tmpfile if (not defined $outfile or $outfile eq "");

	if ( $? != 0 ) {
		$self->setError (7741083,
                    $self->{gettext} ("OpenCA::OpenSSL->SPKAC: Cannot read tmpfile __FILENAME__ successfully (__ERRNO__).",
                                      "__FILENAME__", $tmpfile,
                                      "__ERRNO__", $?));
		return undef;
	}

	return $ret;
}

sub getFingerprint {
	my $self = shift;

	my $keys = { @_ };

	my $alg = lc ( $keys->{ALGORITHM} );
	my $cert = $keys->{CERT};

	if ( $alg eq "" ) {
		$alg = "sha1";
	}

	if ( not $cert or not $cert->getPEM()) {
		return undef;
	}

	my $cert_dat =  OpenCA::OpenSSL::X509::_new_from_pem ($cert->getPEM());

	return OpenCA::OpenSSL::X509::fingerprint ( $cert_dat, $alg );

	# return getDigest ( 	DATA      => $keys->{DATA},
	#			ALGORITHM => $alg,
	#			ENGINE    => $keys->{ENGINE} );
}


sub getDigest {

	## Returns Digest of the provided message
	## DATA=>$data, ALGORITHM=>$alg

	my $self = shift;
	my $keys = { @_ };
	
	my $data    = $keys->{DATA};
	my $alg     = lc( $keys->{ALGORITHM} );

	my $engine  = $self->{ENGINE};

	my ( $command, $ret );

	$alg = "sha256" if( not $alg );

	if (not $data) {
		$self->setError (7751011,
                    $self->{gettext} ("OpenCA::OpenSSL->getDigest: No data specified."));
		return undef;
	}

	$command = "dgst -$alg ";

        if( defined($engine) and ($engine ne "")) {
                $command .= "-engine $engine ";
        }

	$ret = $self->_execute_command (COMMAND => $command, INPUT => $data);
	$ret =~ s/\n//g;
	$ret =~ s/^[^=]+=\s+//;

	if( not $ret ) {
		$self->setError (7751071,
                    $self->{gettext} ("OpenCA::OpenSSL->getDigest: OpenSSL failed (__ERRNO__). __ERRVAL__",
                                      "__ERRNO__", $self->errno,
                                      "__ERRVAL__", $self->errval));
		return undef;
	} else {
		return $ret;
	}
}

# The common invocation mode requires a DATA specification (signed text)
# and a SIGNATURE (detached PKCS#7 signature).
# If OPAQUESIGNATURE is set, DATA and DATA_FILE must not be specified,
# and SIGNATURE or SIGNATURE_FILE must hold a PKCS#7 object containing 
# both data and signature.
sub verify {

	## Verify PKCS7 signatures (new OpenCA::verify command
	## should be used )

	my $self = shift;
	my $keys = { @_ };

	my $data    = $keys->{DATA};
	my $datafile= $keys->{DATA_FILE};
	my $sig     = $keys->{SIGNATURE};
	my $sigfile = $keys->{SIGNATURE_FILE};
	my $cacert  = $keys->{CA_CERT};
	$cacert = $self->{PEM_CERT} if (not $cacert);
	my $cadir   = $keys->{CA_DIR};
	my $verbose = $keys->{VERBOSE};
	my $out	    = $keys->{OUTFILE};
	my $noChain = $keys->{NOCHAIN};
	my $opaquesig = $keys->{OPAQUESIGNATURE};
	my $tmpfile = $self->{tmpDir} . "/${$}_vrfy.tmp";
	my $command = $self->{verify} . " ";

	my ( $ret, $tmp );

	if((not $opaquesig) and (not $data) and (not $datafile) ) {
                $self->_debug ("verify: cannot open command");
		$self->setError (7742011,
                    $self->{gettext} ("OpenCA::OpenSSL->verify: No input source specified."));
		return undef;
	}

	if ((not $opaquesig) and (not $datafile)) {
		$datafile = $self->{tmpDir} . "/${$}_data.tmp";
		if (not open (FD, ">".$datafile)) {
			$self->setError (7742023,
                            $self->{gettext} ("OpenCA::OpenSSL->verify: Cannot open datafile __FILENAME__ for writing.",
                                              "__FILENAME__", $datafile));
			return undef;
		}
		print FD $data;
		close FD;
	} else {
		$data = 0;
	}

	if (not $sigfile) {
		$sigfile = $self->{tmpDir} . "/${$}_sig.tmp";
		if (not open (FD, ">".$sigfile)) {
			$self->setError (7742025,
                            $self->{gettext} ("OpenCA::OpenSSL->verify: Cannot open sigfile __FILENAME__ for writing.",
                                              "__FILENAME__", $sigfile));
			unlink $datafile if ($data);
			return undef;
		}
		print FD $sig;
		close FD;
		$sig = 1;
	} else {
		$sig = 0;
	}

	$command   .= "-verbose " if ( $verbose );
	$command   .= "-cf $cacert " if ( $cacert );
	$command   .= "-cd $cadir " if ($cadir);
	$command   .= "-data $datafile " if ($datafile);
	## the user should know what he is doing
	## $command   .= "-no_chain " if ( $noChain and not($cacert or $cadir));
	$command   .= "-no_chain " if ( $noChain );
	$command   .= "-in $sigfile" if ( $sigfile );
	$command   .= ">$out " if ( $out );

	if( not $out ) {
		$command .= " >$tmpfile";
	}

	$command .= " 2>\&1";

        $self->_debug ("verify: command=$command");

	$ret =`$command`;
	my $org_err = $?;

	unlink ($datafile ) if ($data);
	unlink ($sigfile)   if ($sig);

	$ret = "";
	if (not open( TMP, "<$tmpfile" )) {
                $self->_debug ("verify: Cannot open tmpfile");
		$self->setError (7742082,
                    $self->{gettext} ("OpenCA::OpenSSL->verify: Cannot open tmpfile __FILENAME__ for reading.",
                                      "__FILENAME__", $tmpfile));
		return undef;
	}
	while( not eof ( TMP ) ) {
		$ret .= <TMP>;
	}
	close( TMP );

	if ( $? == 256 ) {
                $self->_debug ("verify: error detected");
                $self->_debug ("verify: original errorcode: ${?}");
                $self->_debug ("verify: deleting error");
		$? = 0;
	} elsif ( $? != 0 ) {
            if ($? == -1)
            {
	        $self->setError (7742071,
                    $self->{gettext} ("OpenCA::OpenSSL->verify: openca-sv failed with errorcode -1. This usually means that the command __COMMAND__ is not present.",
                                      "__COMMAND__", $self->{verify}));
            } elsif ($? == 32256)
            {
	        $self->setError (7742074,
                    $self->{gettext} ("OpenCA::OpenSSL->verify: openca-sv failed with errorcode 32256. This usually means that the file permissions are wrong for the command __COMMAND__.",
                                      "__COMMAND__", $self->{verify}));
            } elsif ($? == 32512)
            {
	        $self->setError (7742072,
                    $self->{gettext} ("OpenCA::OpenSSL->verify: openca-sv failed with errorcode 32512. This usually means that the command openca-sv is malformed or not present (__COMMAND__).",
                                      "__COMMAND__", $self->{verify}));
            } else
            {
                $self->_debug ("verify: error detected");
                $self->_debug ("verify: original errorcode: ${?}");
		(my $h) = 
			( $ret =~ /(Verify Error\s*.*?\s*:\s*.*?)\n/ );
		$self->setError (7742073,
                    $self->{gettext} ("OpenCA::OpenSSL->verify: openca-sv failed (__ERRNO__). __ERRVAL__",
                                      "__ERRNO__", $org_err,
                                      "__ERRVAL__", $h));
                $self->_debug ("verify: errorcode: $self->errno");
                $self->_debug ("verify: errormsg: $self->errval");
            }
	    unlink( $tmpfile ) if (not $out);
	    return undef;
	}
	unlink( $tmpfile ) if (not $out);
	if ($ret =~ /\[Error\]/i)
	{
		$self->setError (7742075,
                    $self->{gettext} ("OpenCA::OpenSSL->verify: openca-sv failed. __ERRVAL__",
                                      "__ERRVAL__", $ret));
		return undef;
	}
            

        $self->_debug ("verify: returned data:\n$ret");
	if( not $out) {
		unlink( $tmpfile );
                $self->_debug ("verify: finished successfully (return output)");
		return $ret;
	} else {
                $self->_debug ("verify: finished successfully (return 1)");
		return 1;
	}
}

sub sign {

	## Generate a PKCS7 signature.

	my $self = shift;
	my $keys = { @_ };

	my $data    = $keys->{DATA};
	my $datafile= $keys->{DATA_FILE};
	my $out     = $keys->{OUT_FILE};
	my $certfile= $keys->{CERT_FILE};
	$certfile = $self->{PEM_CERT} if (not $certfile);
	my $cert    = $keys->{CERT};
	my $keyfile = $keys->{KEY_FILE};
	$keyfile = $self->{KEY} if (not $keyfile);
	my $key     = $keys->{KEY};
	my $nonDetach = $keys->{INCLUDE_DATA};
	my $pwd     = ( $keys->{PWD} or $keys->{PASSWD} );
	$pwd = $self->{PASSWD} if (not $pwd);
	my $tmpfile = $self->{tmpDir} . "/${$}_sign.tmp";

	my $command = $self->{sign} . " ";
        if( $self->{ENGINE} ) {
                my $init = $self->_build_engine_params(KEY_USAGE => "1");
                $command .= " -engine $self->{ENGINE} -keyform ".$self->{KEYFORM}." $init ";
        }

	my ( $ret );

	if( (not $data) and (not $datafile) ) {
		$self->setError (7743011,
                    $self->{gettext} ("OpenCA::OpenSSL->sign: No input source."));
		return undef;
	}
	if( (not $cert) and (not $certfile) ) {
		$self->setError (7743012,
                    $self->{gettext} ("OpenCA::OpenSSL->sign: No certificate specified."));
		return undef;
	}
	if( (not $key)  and (not $keyfile) ) {
		$self->setError (7743013,
                    $self->{gettext} ("OpenCA::OpenSSL->sign: No private key specified."));
		return undef;
	}

	if ( not $datafile ) {
		$datafile = $self->{tmpDir} . "/${$}_data.tmp";
		if (not open FD, ">".$datafile) {
			$self->setError (7743031,
                            $self->{gettext} ("OpenCA::OpenSSL->sign: Cannot open datafile __FILENAME__ for writing.",
                                              "__FILENAME__", $datafile));
			return undef;
		}
		print FD $data;
		close FD;
	} else {
		$data = 0;
	}
	if ( not $keyfile ) {
		$keyfile = $self->{tmpDir} . "/${$}_key.tmp";
		if (not open FD, ">".$keyfile) {
			$self->setError (7743033,
                            $self->{gettext} ("OpenCA::OpenSSL->sign: Cannot open keyfile __FILENAME__ for writing.",
                                              "__FILENAME__", $keyfile));
			unlink ($datafile) if ($data);
			return undef;
		}
		print FD $key;
		close FD;
	} else {
		$key = 0;
	}
	if ( not $certfile ) {
		$certfile = $self->{tmpDir} . "/${$}_cert.tmp";
		if (not open FD, ">".$certfile) {
			$self->setError (7743035,
                            $self->{gettext} ("OpenCA::OpenSSL->sign: Cannot open certfile __FILENAME__ for writing.",
                                              "__FILENAME__", $certfile));
			unlink ($datafile) if ($data);
			unlink ($keyfile) if ($key);
			return undef;
		}
		print FD $cert;
		close FD;
	} else {
		$cert = 0;
	}

	$command   .= "-in $datafile ";
	$command   .= "-out $out "            if ( $out );
	if (not $self->{GET_PIN_CALLBACK})
	{
		$command   .= "-passin env:pwd " if ( $pwd );
	}
	$command   .= "-nd "                  if ( $nonDetach );

	$command   .= "-cert $certfile ";
	$command   .= " -keyfile $keyfile ";

	if( not $out) {
		$command .= " >$tmpfile";
	};

        $self->_debug ("sign: $command");

	$ENV{pwd} = "$pwd" if ( $pwd );
	$ret =`$command`;
	delete ($ENV{pwd});

	if ( $? == 256 ) {
                $self->_debug ("sign: Error 256 detected");
                $self->_debug ("sign: ignoring error");
	} elsif ( $? ) {
		unlink( $tmpfile )  if (not $out);
		unlink( $datafile ) if ($data);
		unlink( $keyfile )  if ($key);
		unlink( $certfile ) if ($cert);
                if ($? == -1)
                {
		    $self->setError (7743073,
                        $self->{gettext} ("OpenCA::OpenSSL->sign: openca-sv failed with errorcode -1. This usually means that the command __COMMAND__ is not present.",
                                          "__COMMAND__", $self->{openca_sv}));
                } elsif ($? == 32256) {
		    $self->setError (7743074,
                        $self->{gettext} ("OpenCA::OpenSSL->sign: openca-sv failed with errorcode 32256. This usually means that the file permissions are wrong for the command __COMMAND__.",
                                          "__COMMAND__", $self->{openca_sv}));
                } elsif ($? == 32512) {
		    $self->setError (7743072,
                        $self->{gettext} ("OpenCA::OpenSSL->sign: openca-sv failed with errorcode 32512. This usually means that the command openca-sv is malformed or not present (__COMMAND__).",
                                          "__COMMAND__", $self->{openca_sv}));
                } else {
		    $self->setError (7743071,
                        $self->{gettext} ("OpenCA::OpenSSL->sign: openca-sv failed (__ERRNO__).",
                                          "__ERRNO__", $?));
                }
		return undef;
	}
	unlink( $datafile ) if ($data);
	unlink( $keyfile )  if ($key);
	unlink( $certfile ) if ($cert);

	if( not $out ) {
		if (not open( TMP, "<$tmpfile" )) {
			$self->setError (7743081,
                            $self->{gettext} ("OpenCA::OpenSSL->sign: Cannot open tmpfile __FILENAME__ for reading.",
                                              "__FILENAME__", $tmpfile));
			return undef;
		}
		do {
			$ret .= <TMP>;
		} while (not eof(TMP));
		close(TMP);

		unlink( $tmpfile );
	}

	## If we are here there have been no errors, so
	## if $ret is empty, let us return a true value...
	$ret = 1 if ( not $ret );

	return $ret;
}

sub encrypt {

	## Encrypt PKCS7 containers

	my $self = shift;
	my $keys = { @_ };
	my $data    = $keys->{DATA};
	my $datafile= $keys->{DATA_FILE};
	my $certfile= $keys->{CERT_FILE};
	$certfile = $self->{PEM_CERT} if (not $certfile);
	my $out	    = $keys->{OUTFILE};
	my $tmpfile = $self->{tmpDir} . "/${$}_decrypt.tmp";
	my $command = $self->{encrypt} . " ";

	my ( $ret, $tmp );

	if( (not $data) and (not $datafile) ) {
		$self->setError (7747011,
                    $self->{gettext} ("OpenCA::OpenSSL->encrypt: No input source specified."));
		return undef;
	}
	if( not $certfile ) {
		$self->setError (7747012,
                    $self->{gettext} ("OpenCA::OpenSSL->encrypt: No certificate specified."));
		return undef;
	}

	if (not $datafile) {
		$datafile = $self->{tmpDir} . "/${$}_data.tmp";
		if (not open (FD, ">".$datafile)) {
			$self->setError (7747023,
                            $self->{gettext} ("OpenCA::OpenSSL->encrypt: Cannot open datafile __FILENAME__ for writing.",
                                              "__FILENAME__", $datafile));
			return undef;
		}
		print FD $data;
		close FD;
	} else {
		$data = 0;
	}

	$command   .= "-in $datafile " if ($datafile);
	$command   .= "-cert $certfile ";
	$command   .= ">$out " if ( $out );

	if( not $out ) {
		$command .= " $tmpfile";
	}

        $self->_debug ("encrypt: command=$command");

	$ret =`$command`;
	my $org_err = $?;
        $self->_debug ("encrypt: question mark: ${?}");
        $self->_debug ("encrypt: \@: ${@}");
        $self->_debug ("encrypt: ret: $ret");
	unlink ($datafile ) if ($data);

	if (not $out)
	{
		$ret = "";
		if (not open( TMP, "<$tmpfile" )) {
                        $self->_debug ("encrypt: Cannot open tmpfile for reading");
			$self->setError (7747082,
                            $self->{gettext} ("OpenCA::OpenSSL->encrypt: Cannot open tmpfile __FILENAME__ for reading.",
                                              "__FILENAME__", $tmpfile));
			return undef;
		}
		while( not eof ( TMP ) ) {
			$ret .= <TMP>;
		}
		close( TMP );
	}

	if ( $? == 256 and not $@ )
        {
                $self->_debug ("encrypt: error detected");
                $self->_debug ("encrypt: original errorcode: ${?}");
                $self->_debug ("encrypt: deleting error");
		$? = 0;
        } elsif ($? != 0) 
        {
            if ($? == -1)
            {
	        $self->setError (7747071,
                    $self->{gettext} ("OpenCA::OpenSSL->encrypt: openca-sv failed with errorcode -1. This usually means that the command __COMMAND__ is not present.",
                                      "__COMMAND__", $self->{encrypt}));
            } elsif ($? == 32256)
            {
	        $self->setError (7747074,
                    $self->{gettext} ("OpenCA::OpenSSL->encrypt: openca-sv failed with errorcode 32256. This usually means that the file permissions are wrong for the command __COMMAND__.",
                                      "__COMMAND__", $self->{encrypt}));
            } elsif ($? == 32512)
            {
	        $self->setError (7747072,
                    $self->{gettext} ("OpenCA::OpenSSL->encrypt: openca-sv failed with errorcode 32512. This usually means that the command openca-sv is malformed or not present (__COMMAND__).",
                                      "__COMMAND__", $self->{encrypt}));
	    } else
            {
                $self->_debug ("encrypt: error detected");
                $self->_debug ("encrypt: original errorcode: ${?}");
	        ## (my $h) = 
	        ## ( $ret =~ /(Encrypt Error\s*.*?\s*:\s*.*?)\n/ );
	        my $h = $ret;

		$self->setError (7747073,
                    $self->{gettext} ("OpenCA::OpenSSL->encrypt: openca-sv failed (__ERRNO__). __ERRVAL__",
                                      "__ERRNO__", $org_err,
                                      "__ERRVAL__", $h));
                $self->_debug ("encrypt: errorcode: $self->errno");
                $self->_debug ("encrypt: errormsg:  $self->errval");
            }
	    unlink( $tmpfile ) if (not $out);
	    return undef;
	}

        $self->_debug ("encrypt: returned data:\n$ret");
	if( not $out) {
		unlink( $tmpfile );
                $self->_debug ("encrypt: finished successfully (return output)");
		return $ret;
	} else {
                $self->_debug ("encrypt: finished successfully (return 1)");
		return 1;
	}
}

sub decrypt {

	## Extract data from a PKCS7 structure.

	my $self = shift;
	my $keys = { @_ };

	my $data    = $keys->{DATA};
	my $datafile= $keys->{DATA_FILE};
	$datafile = $keys->{INFILE} if (not $datafile);
	my $out     = $keys->{OUT_FILE};
	my $certfile= $keys->{CERT_FILE};
	$certfile = $self->{PEM_CERT} if (not $certfile);
	my $cert    = $keys->{CERT};
	my $keyfile = $keys->{KEY_FILE};
	$keyfile = $self->{KEY} if (not $keyfile);
	my $key     = $keys->{KEY};
	my $pwd     = ( $keys->{PWD} or $keys->{PASSWD} );
	$pwd = $self->{PASSWD} if (not $pwd);
	my $tmpfile = $self->{tmpDir} . "/${$}_decrypt.tmp";

	my $command = $self->{decrypt} . " ";
        if( $self->{ENGINE} ) {
                my $init = $self->_build_engine_params(KEY_USAGE => "1");
                $command .= " -engine $self->{ENGINE} -keyform ".$self->{KEYFORM}." $init ";
        }

	my ( $ret );

	if( (not $data) and (not $datafile) ) {
		$self->setError (7746011,
                    $self->{gettext} ("OpenCA::OpenSSL->decrypt: No input source."));
		return undef;
	}
	if( (not $cert) and (not $certfile) ) {
		$self->setError (7746012,
                    $self->{gettext} ("OpenCA::OpenSSL->decrypt: No certificate specified."));
		return undef;
	}
	if( (not $key)  and (not $keyfile) ) {
		$self->setError (7746012,
                    $self->{gettext} ("OpenCA::OpenSSL->decrypt: No private key specified."));
		return undef;
	}

	if ( not $datafile ) {
		$datafile = $self->{tmpDir} . "/${$}_data.tmp";
		if (not open FD, ">".$datafile) {
			$self->setError (7746031,
                            $self->{gettext} ("OpenCA::OpenSSL->decrypt: Cannot open datafile __FILENAME__ for writing.",
                                              "__FILENAME__", $datafile));
			return undef;
		}
		print FD $data;
		close FD;
	} else {
		$data = 0;
	}
	if ( not $keyfile ) {
		$keyfile = $self->{tmpDir} . "/${$}_key.tmp";
		if (not open FD, ">".$keyfile) {
			$self->setError (7746033,
                            $self->{gettext} ("OpenCA::OpenSSL->decrypt: Cannot open keyfile __FILENAME__ for writing.",
                                              "__FILENAME__", $keyfile));
			unlink ($datafile) if ($data);
			return undef;
		}
		print FD $key;
		close FD;
	} else {
		$key = 0;
	}
	if ( not $certfile ) {
		$certfile = $self->{tmpDir} . "/${$}_cert.tmp";
		if (not open FD, ">".$certfile) {
			$self->setError (7746035,
                            $self->{gettext} ("OpenCA::OpenSSL->decrypt: Cannot open certfile __FILENAME__ for writing.",
                                              "__FILENAME__", $certfile));
			unlink ($datafile) if ($data);
			unlink ($keyfile) if ($key);
			return undef;
		}
		print FD $cert;
		close FD;
	} else {
		$cert = 0;
	}

	$command   .= "-in $datafile ";
	$command   .= "-out $out "            if ( $out );
	if (not $self->{GET_PIN_CALLBACK})
	{
		$command   .= "-passin env:pwd " if ( $pwd );
	}
	$command   .= "-cert $certfile ";
	$command   .= " -keyfile $keyfile ";

	if( not $out) {
		$command .= " >$tmpfile";
	};

        $self->_debug ("decrypt: $command");

	$ENV{pwd} = "$pwd" if ( $pwd );
	$ret =`$command`;
	delete ($ENV{pwd});

	if ( $? ) {
		unlink( $tmpfile )  if (not $out);
		unlink( $datafile ) if ($data);
		unlink( $keyfile )  if ($key);
		unlink( $certfile ) if ($cert);
                if ($? == -1)
                {
	            $self->setError (7746073,
                        $self->{gettext} ("OpenCA::OpenSSL->decrypt: openca-sv failed with errorcode -1. This usually means that the command __COMMAND__ is not present.",
                                  "__COMMAND__", $self->{openca_sv}));
                } elsif ($? == 32256)
                {
	            $self->setError (7746074,
                        $self->{gettext} ("OpenCA::OpenSSL->decrypt: openca-sv failed with errorcode 32256. This usually means that the file permissions are wrong for the command __COMMAND__.",
                                  "__COMMAND__", $self->{openca_sv}));
                } elsif ($? == 32512)
                {
	            $self->setError (7746072,
                        $self->{gettext} ("OpenCA::OpenSSL->decrypt: openca-sv failed with errorcode 32512. This usually means that the command openca-sv is malformed or not present (__COMMAND__).",
                                  "__COMMAND__", $self->{openca_sv}));
                } else {
		    $self->setError (7746071,
                        $self->{gettext} ("OpenCA::OpenSSL->decrypt: openca-sv failed (__ERRNO__).",
                                          "__ERRNO__", $?));
                }
		return undef;
	}
        $self->_debug ("decrypt: openca-sv succeeded");
	unlink( $datafile ) if ($data);
	unlink( $keyfile )  if ($key);
	unlink( $certfile ) if ($cert);

	if( not $out ) {
		if (not open( TMP, "<$tmpfile" )) {
			$self->setError (7746081,
                            $self->{gettext} ("OpenCA::OpenSSL->decrypt: Cannot open tmpfile __FILENAME__ for reading.",
                                              "__FILENAME__", $tmpfile));
			return undef;
		}
		do {
			$ret .= <TMP>;
		} while (not eof(TMP));
		close(TMP);

		unlink( $tmpfile );
	}

	## If we are here there have been no errors, so
	## if $ret is empty, let us return a true value...
	$ret = 1 if ( not $ret );

	return $ret;
}

sub getCertAttribute {
	my $self = shift;
	my $keys = { @_ };

	my $cert;

	# $self->_debug("OpenCA::OpenSSL::getCertAttribute() start");

	if ($keys->{INFORM} and $keys->{INFORM} =~ /DER/) {
		$cert = OpenCA::OpenSSL::X509::_new_from_der ($keys->{DATA});
	} else {
		$cert = OpenCA::OpenSSL::X509::_new_from_pem ($keys->{DATA});
	}

	# $self->_debug("OpenCA::OpenSSL::getCertAttribute() got cert");

	my @attribute = ();
	if( $keys->{ATTRIBUTE_LIST} && ref($keys->{ATTRIBUTE_LIST}) ) {
		@attribute = @{$keys->{ATTRIBUTE_LIST}};
	} else {
		@attribute = ( $keys->{ATTRIBUTE} );
	}

	return undef if (not $cert);

	my ( $ret );

	# initialize additional OIDs not present in default OPENSSL
	$cert->init_oids;

	foreach my $attribute ( @attribute ) {
		$_ = uc $attribute;
		my $func;

		SWITCH: {
			$func = lc $attribute;
			if (/^NOTBEFORE$/) {$func = "notBefore"};
			if (/^NOTAFTER$/)  {$func = "notAfter"};
			if (/^DN$/)        {$func = "subject"};
			if (/^HASH$/)      {$func = "subject_hash"};
		}

		# $self->_debug("OpenCA::OpenSSL::getCertAttribute() calling $func ($attribute) ");

		$ret->{$attribute} = $cert->$func;
	}

	return $ret;
}

sub getReqAttribute {
	my $self = shift;
	my $keys = { @_ };

	## timing test
	##
	## my $start;
	## use Time::HiRes qw( usleep ualarm gettimeofday tv_interval );
	## $start = [gettimeofday];

	my $csr;
	if ($keys->{INFORM} and $keys->{INFORM} =~ /DER/)
	{
		$csr = OpenCA::OpenSSL::PKCS10::_new_from_der ($keys->{DATA});
	} elsif ($keys->{INFORM} and $keys->{INFORM} =~ /SPKAC/) {
		$csr = OpenCA::OpenSSL::SPKAC::_new ($keys->{DATA});
	} else {
		$csr = OpenCA::OpenSSL::PKCS10::_new_from_pem ($keys->{DATA});
	}

	my @attribute = ();
	if( $keys->{ATTRIBUTE_LIST} && ref($keys->{ATTRIBUTE_LIST}) ) {
		@attribute = @{$keys->{ATTRIBUTE_LIST}};
	} else {
		@attribute = ( $keys->{ATTRIBUTE} );
	}

	return undef if (not $csr);

	my ( $ret );

	foreach my $attribute ( @attribute ) {
		$_ = uc $attribute;
		my $func;
		SWITCH: {
			$func = lc $attribute;
			if (/^DN$/)        {$func = "subject"};
		}
		$ret->{$attribute} = $csr->$func;
	}

	## timing test
	##
	## if ($self->{DEBUG}) {
	## 	$errno += tv_interval ( $start ) if ($self->{DEBUG});
	## 	print "OpenCA::OpenSSL::getReqAttribute: total_time=".$errno."<br>\n";
	## }

	return $ret;
}

sub getCRLAttribute {
	my $self = shift;
	my $keys = { @_ };

	my $crl;
	if ($keys->{INFORM} and $keys->{INFORM} =~ /DER/)
	{
		$crl = OpenCA::OpenSSL::CRL::_new_from_der ($keys->{DATA});
	} else {
		$crl = OpenCA::OpenSSL::CRL::_new_from_pem ($keys->{DATA});
	}

	my @attribute = ();
	if( $keys->{ATTRIBUTE_LIST} && ref($keys->{ATTRIBUTE_LIST}) ) {
		@attribute = @{$keys->{ATTRIBUTE_LIST}};
	} else {
		@attribute = ( $keys->{ATTRIBUTE} );
	}

	return undef if (not $crl);

	my ( $ret );

	foreach my $attribute ( @attribute ) {
		$_ = uc $attribute;
		my $func;
		SWITCH: {
			$func = lc $attribute;
			if (/^LASTUPDATE$/) {$func = "lastUpdate"};
			if (/^NEXTUPDATE$/) {$func = "nextUpdate"};
			if (/^DN$/)         {$func = "issuer"};
		}
		$ret->{$attribute} = $crl->$func;
	}
	return $ret;
}

sub pkcs7Certs {

	my $self = shift;
	my $keys = { @_ };

	my $infile  = $keys->{INFILE};
	my $outfile = $keys->{OUTFILE};
	my $pkcs7   = $keys->{PKCS7};

	my $command = "pkcs7 -print_certs ";
	my $tmpfile = $self->{tmpDir} . "/${$}_SPKAC.tmp";

	my $engine  = $self->{ENGINE};

	my $ret = "";
	my $retVal = 0;
	my $tmp;

	if( defined($pkcs7) && $pkcs7 ne "" ) {
		$infile = $self->{tmpDir} . "/${$}_in_SPKAC.tmp";
		if (not open( FD, ">$infile" )) {
			$self->setError (7744021,
                            $self->{gettext} ("OpenCA::OpenSSL->pkcs7Certs: Cannot open infile __FILENAME__ for writing.",
                                              "__FILENAME__", $infile));
			return undef;
		}
		print FD $pkcs7."\n";
		close ( FD );
	}

        if( defined($engine) and ($engine ne "")) {
                $command .= "-engine $engine ";
        }

	$command .= "-in $infile " if( defined($infile) && $infile ne "" );
	if( defined($outfile) && $outfile ne "" ) {
		$command .= "-out $outfile ";
	} else {
		$command .= "-out $tmpfile ";
	}

        $self->_debug ("pkcs7Certs: command=$command");
	$ret = $self->_execute_command(COMMAND => $command);
	if( not $ret ) {
		$self->setError (7744071,
                    $self->{gettext} ("OpenCA::OpenSSL->pkcs7Certs: OpenSSL failed (__ERRNO__). __ERRVAL__",
                                      "__ERRNO__", $self->errno,
                                      "__ERRVAL__", $self->errval));
		unlink $infile if( defined($pkcs7) && $pkcs7 ne "");
		unlink $tmpfile if (not (defined($outfile)) or $outfile eq "");
		return undef;
	}

	## Unlink the infile if it was temporary
	unlink $infile if( defined($pkcs7) && $pkcs7 ne "");

	## Get the output
	if (not open( TMP, $tmpfile )) {
		$self->setError (7744081,
                    $self->{gettext} ("OpenCA::OpenSSL->pkcs7Certs: Cannot open tmpfile __FILENAME__ for reading.",
                                      "__FILENAME__", $tmpfile));
		return undef;
	}
        $ret = "";
	while ( $tmp = <TMP> ) {
		$ret .= $tmp;
	}
	close( TMP );
	unlink $tmpfile if (not (defined($outfile)) or $outfile eq "");

        $self->_debug ("pkcs7Certs: finished successfully");
        return $ret;
}

sub updateDB {

	my $self = shift;
	my $keys = { @_ };

	my $cakey    = $keys->{CAKEY};
	$cakey = $self->{KEY} if (not $cakey);
	my $cacert   = $keys->{CACERT};
	$cacert = $self->{PEM_CERT} if (not $cacert);
	my $passwd   = $keys->{PASSWD};
	$passwd = $self->{PASSWD} if (not $passwd);
	my $outfile  = $keys->{OUTFILE};

	my ( $ret, $tmp );
	my $command = "ca -updatedb ";

	$command .= "-config " . $self->{cnf}. " " if ( defined($self->{'cnf'}) && $self->{cnf} ne "" );
	$command .= "-keyfile $cakey " if( defined($cakey) && $cakey ne "" );
	$command .= "-passin env:pwd " if ( defined($passwd) && $passwd ne "" );
	$command .= "-cert $cacert " if ( defined($cacert) && $cacert ne "" );

	$ENV{'pwd'} = "$passwd";
	$ret = $self->_execute_command (COMMAND => $command);
	delete( $ENV{'pwd'} );

	if( not $ret ) {
		$self->setError (7771071,
                    $self->{gettext} ("OpenCA::OpenSSL->updateDB: OpenSSL failed (__ERRNO__). __ERRVAL__",
                                      "__ERRNO__", $self->errno,
                                      "__ERRVAL__", $self->errval));
		return undef;
	}

	if( defined($outfile) && $outfile ne "" ) {
		if (not open( FD, ">$outfile" )) {
			$self->setError (7771081,
                            $self->{gettext} ("OpenCA::OpenSSL->updateDB: Cannot open outfile __FILENAME__ for writing.",
                                              "__FILENAME__", $outfile));
			return undef;
		}
		print FD "$ret";
		close( FD );
		return 1;
	}
	return "$ret";
}

sub getSMIME {

	## DECRYPT      => a true value
	## ENCRYPT      => a true value
	## SIGN         => a true value
	## CERT         => $cert
	## KEY          => $key
	## PASSWD       => $passwd
	## ENCRYPT_CERT => $enc_cert
	## SIGN_CERT    => $sign_cert
	## INFILE       => $infile
	## OUTFILE      => $outfile
	## DATA         => $message
	## MESSAGE      => $message (higher priority)
	## TO           => $to
	## FROM         => $from
	## SUBJECT      => $subject

	my $self = shift;
	my $keys = { @_ };

	my $decrypt     = $keys->{DECRYPT};
	my $encrypt     = $keys->{ENCRYPT};
	my $sign        = $keys->{SIGN};
	my $cert        = $keys->{CERT};
	$cert = $self->{PEM_CERT} if (not $cert);
	my $key         = $keys->{KEY};
	$key = $self->{KEY} if (not $key);
	my $enc_cert    = $keys->{ENCRYPT_CERT};
	my $sign_cert   = $keys->{SIGN_CERT};
	my $passwd      = $keys->{PASSWD};
	$passwd = $self->{PASSWD} if (not $passwd);
	my $infile      = $keys->{INFILE};
	my $outfile     = $keys->{OUTFILE};
	my $message     = $keys->{DATA};
	$message        = $keys->{MESSAGE} if ($keys->{MESSAGE});
	my $to          = $keys->{TO};
	my $cc          = $keys->{CC};
	my $from        = $keys->{FROM};
	my $subject     = $keys->{SUBJECT};

	my $engine      = $self->{ENGINE};

	my ( $ret, $tmp, $tmpfile );

	## smime can only handle file and not stdin
	if ($message) {
		$infile = $self->{tmpDir} . "/${$}_data.msg";
                $self->_debug ("getSMIME: create temporary infile $infile");
                $self->_debug ("getSMIME: the data is like follows\n$message");
		if (not  open FD, ">".$infile) {
			$self->setError (7752021,
			    $self->{gettext} ("OpenCA::OpenSSL->getSMIME: Cannot write message to tmpfile __FILENAME__.",
                                              "__FILENAME__", $infile));
			return undef;
		}
		print FD "From: $from\n";
		print FD "To: $to\n";
		foreach my $address (@{$cc})
		{
			print FD "Cc: $address\n";
		}
		print FD "Subject: $subject\n";
		my $encoding = setlocale (LC_MESSAGES);

		if ($encoding ne "C") {
                  $encoding =~ s/^.*\.//; ## remove language
                } else {
                  $encoding = 'UTF-8';
                }
                $encoding =~ s/(UTF|ISO|EUC)([^-]{1})/$1-$2/i;  ## on FreeBSD "locale" returns charset names
                                                                ## which do not comply with IANA standard for
                                                                ## MIME
                
	        print FD "Content-Type: text/plain; charset=$encoding; format=flowed\n".
                         "Content-Transfer-Encoding: 8bit\n";
		print FD "\n".$message;
		close FD;
	} else {
		$message = 0;
	}

	## setup file with smime-message
	if ($outfile) {
	  $tmpfile = $outfile;
	} else {
	  $tmpfile = $self->{tmpDir}."/".$$."_SMIME.msg";
	}

	$enc_cert  = $cert if (not $enc_cert);
	$sign_cert = $cert if (not $sign_cert);

	my ($enc_x509, $sign_x509);
	if ($enc_cert)
	{
		$enc_x509 = OpenCA::X509->new (
		                SHELL   => $self,
                                GETTEXT => $self->{gettext},
		                INFILE  => $enc_cert);
		if (not $enc_x509)
		{
			unlink $infile if ($message);
			return $self->setError ($OpenCA::X509::errno, $OpenCA::X509::errval);
		}
	}
        $self->_debug ("getSMIME: enccert object ready");
	if ($sign_cert) {
		$sign_x509 = OpenCA::X509->new (
		                SHELL   => $self,
                                GETTEXT => $self->{gettext},
		                INFILE  => $sign_cert);
		if (not $sign_x509) {
			unlink $infile if ($message);
			return $self->setError ($OpenCA::X509::errno, $OpenCA::X509::errval);
		}
	}
        $self->_debug ("getSMIME: signcert object ready");

	## use OpenCA::OpenSSL::SMIME
	## this is only a wrapper for old code !!!

	## decryption
	my $smime = OpenCA::OpenSSL::SMIME->new(
	                         INFILE  => $infile,
	                         SHELL   => $self,
	                         ENGINE  => $engine,
                                 KEYFORM => $self->{KEYFORM},
                                 GETTEXT => $self->{gettext},
                                 TMPDIR  => $self->{tmpDir},
                                 DEBUG   => $self->{DEBUG}
                                 # DEBUG   => 1
	                         );
	if (not $smime) {

                $self->_debug ("getSMIME: smime object failed");

		unlink $infile if ($message);
		return $self->setError ($OpenCA::OpenSSL::SMIME::errno, 
						$OpenCA::OpenSSL::SMIME::err);
	}

        $self->_debug ("getSMIME: smime object ready");

	if ($decrypt) {
		open(KEYF, '<', $key) or return;
		if (not $smime->decrypt(
		            CERTIFICATE  => $enc_x509,
		            KEY_PASSWORD => $passwd,
		            PRIVATE_KEY  => \*KEYF)) {
			close (KEYF);
			unlink $infile if ($message);
			return $self->setError ($smime->errno, $smime->errval);
		}
		close (KEYF);
	} else {
		## 1. signing
		if ( $sign eq "1" ) {
			open(KEYF, '<', $key) or return;
			if (not $smime->sign(
			            CERTIFICATE  => $sign_x509,
			            KEY_PASSWORD => $passwd,
			            PRIVATE_KEY  => \*KEYF)) {
				close (KEYF);

				$self->_debug("ERROR::Can not sign SMIME (" .
					$smime->errno . "::" .
						$smime->errval );

				unlink $infile if ($message);

				return $self->setError ($smime->errno, $smime->errval);
			}
			close (KEYF);
		}
		if ($encrypt) {
			if (not $smime->encrypt(CERTIFICATE  => $enc_x509))
			{
				unlink $infile if ($message);
				return $self->setError ($smime->errno, $smime->errval);
			}
		}
	}


        $self->_debug ("getSMIME: final steps ( $outfile / $smime )");

	unlink $infile if ($message);

        $self->_debug ("getSMIME: return data :: " . $smime->get_mime );

	## if the caller want a file then we can finish
	if( defined($outfile) && $outfile ne "" ) {
		open (OUT, ">", $outfile);
		$smime->get_mime->print(\*OUT);
		close (OUT);
		return 1;
	}

	if( defined ($smime) and defined($smime->get_mime)
				and defined($smime->get_mime->stringify) ) {
		return $smime->get_mime->stringify
	} else {
		return $message;
	}
}

sub getPIN {

	## PIN_LENGTH    => $pin_length
	## RANDOM_LENGTH => $random_length
	## LENGTH	 => $pin_length

	my $self = shift;
	my $keys = { @_ };

	my $pin_length = $keys->{LENGTH};
	$pin_length    = $keys->{PIN_LENGTH} if (defined $keys->{PIN_LENGTH});
	my $length     = $keys->{RANDOM_LENGTH};
	my $hex	       = $keys->{HEX};

	my $engine     = $self->{ENGINE};

	my ( $ret, $tmp, $tmpfile );

	my $command = " rand ";
	if ( $hex ) {
		$command .= " -hex ";
	} else {
		$command .= " -base64 ";
	}

        if( $engine ) {
          $command .= " -engine $engine ";
        }
	if ($length) {
	  $command .= $length;
	} elsif ($pin_length) {
	  $command .= $pin_length;
	} else {
	  return undef;
	}

	## create the PIN
	my $pin = $self->_execute_command (COMMAND => $command, 
							HIDE_OUTPUT => 1);

	if (not $pin) {
		$self->setError (7753071,
                    $self->{gettext} ("OpenCA::OpenSSL->getPIN: OpenSSL failed (__ERRNO). __ERRVAL__",
                                      "__ERRNO__", $self->errno,
                                      "__ERRVAL__", $self->errval));
		return undef;
	}

	## remove trailing newline
	$pin =~ s/\n//gs;
	$pin =~ s/=*$//gs;

	if ($pin_length) {
	  ## enforce the PIN-length
	  ## SECURITY ADVICE: it is more secure to only set the
	  ##                  number of randombytes
          $pin = substr ($pin, 0, $pin_length);
	} else {
	  ## 2*$length is enough to encode $length randombytes in base64
          my $hl = 2*$length;
          $pin = substr ($pin, 0, $hl);
	}

	if ($pin) {
		return $pin;
	} else {
		$self->setError (7753075,
                    $self->{gettext} ("OpenCA::OpenSSL->getPIN: PIN is empty."));
		return undef;
	}

}

sub getOpenSSLDate {
	my $self = shift;

	if (not defined $_[0]) {
		$self->setError (7754011,
                    $self->{gettext} ("OpenCA::OpenSSL->getOpenSSLDate: No date specified."));
		return undef;
	}
	my $date = $self->getNumericDate ( $_[0] );
	if (not defined $date) {
		$self->{errval} = $self->{gettext} ("OpenCA::OpenSSL->getOpenSSLDate: Errorcode 7754021: __ERRVAL__",
                                                    "__ERRVAL__", $self->{errval});
		return undef;
	}

	## remove century
	$date =~ s/^..//;

	## add trailing Z
	$date .= "Z";

	return $date; 
}

sub getNumericDate {
	my $self = shift;
	my %help;
	my $new_date;

	my $date = $_[0];

	# if (not defined $_[0]) {
		# $self->setError (7755011,
                  #   $self->{gettext} ("OpenCA::OpenSSL->getNumericDate: No argument specified."));
		# return undef;
	# }
	if (not $date) {
		$date = gmtime();

		# $self->setError (7755012,
                #     $self->{gettext} ("OpenCA::OpenSSL->getNumericDate: No date specified."));
		# return undef;
	}

	## remove leading days like SUN or MON
	if ( $date =~ /^\s*[^\s]+\s+(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)/i ) {
		$date =~ s/^\s*[^\s]+//;
	}

	##  Mar 10 19:36:45 2001 GMT

	## Month
	if ( $date =~ /^\s*JAN/i ) {
		##  january
		$help {MONTH} = "01";
	} elsif ( $date =~ /^\s*FEB/i ) {
		## february
		$help {MONTH} = "02";
	} elsif ( $date =~ /^\s*MAR/i ) {
		## march
		$help {MONTH} = "03";
	} elsif ( $date =~ /^\s*APR/i ) {
		## april
		$help {MONTH} = "04";
	} elsif ( $date =~ /^\s*MAY/i ) {
		## may
		$help {MONTH} = "05";
	} elsif ( $date =~ /^\s*JUN/i ) {
		## june
		$help {MONTH} = "06";
	} elsif ( $date =~ /^\s*JUL/i ) {
		## july
		$help {MONTH} = "07";
	} elsif ( $date =~ /^\s*AUG/i ) {
		## august
		$help {MONTH} = "08";
	} elsif ( $date =~ /^\s*SEP/i ) {
		## september
		$help {MONTH} = "09";
	} elsif ( $date =~ /^\s*OCT/i ) {
		## october
		$help {MONTH} = "10";
	} elsif ( $date =~ /^\s*NOV/i ) {
		## november
		$help {MONTH} = "11";
	} elsif ( $date =~ /^\s*DEC/i ) {
		## december
		$help {MONTH} = "12";
	} else {
		my @call = caller ( 1 );
		## return illegal
		$self->setError (7755022,
                    $self->{gettext} ("OpenCA::OpenSSL->getNumericDate: Illegal month."));
		print STDERR $call[2] . "::" . $call[1] . "->" .
			"[orig was $date]\n";

		return undef;
	}

	## day
	$date =~ s/^ *//;
	$date = substr ($date, 4, length ($date)-4);
	$help {DAY} = substr ($date, 0, 2);
	$help {DAY} =~ s/ /0/;

	## hour
	$help {HOUR} = substr ($date, 3, 2);

	## minute
	$help {MINUTE} = substr ($date, 6, 2);

	## second
	$help {SECOND} = substr ($date, 9, 2);

	## year
	$help {YEAR} = substr ($date, 12, 4);

	## build date
	$new_date =	$help {YEAR}.
			$help {MONTH}.
			$help {DAY}.
			$help {HOUR}.
			$help {MINUTE}.
			$help {SECOND};

	return $new_date; 

}

sub getNumericDateDays {
	my $self = shift;
	my $date = shift;
	my $tmpVal = undef;
	my @monVals = ( 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 );
	my $counter = 0;
	my $ret = 0;

	if( not $date ) {
		$date = gmtime();
	}

	$date = $self->getNumericDate ( $date ) if ( $date =~ /[a-zA-Z]+/ );

	# Years * 365
	$tmpVal = substr ( $date, 0, 4) * 365;
	$ret += $tmpVal;

	# Months
	$tmpVal = substr ( $date, 4, 2 );
	for ( my $counter = 1; $counter < $tmpVal ; $counter++ ) {
		$ret += $monVals[$counter - 1];
	}

	$tmpVal = substr ( $date, 6, 2 );
	$ret += $tmpVal;

	return $ret;
}

##############################################################
##             OpenSSL execution environment                ##
##                        BEGIN                             ##
##############################################################

sub _start_shell
{
    my $self = shift;
    $self->_debug ("_start_shell: try to start shell");
    my $keys = { @_ };

    return 1 if ($self->{OPENSSL});

    my $open = "| ".$self->{shell}.
               " 1>$self->{tmpDir}/${$}_stdout.log".
               " 2>$self->{tmpDir}/${$}_stderr.log";
    $self->_debug ("_start_shell: $open");
    if (not open $self->{OPENSSL}, $open)
    {
        my $msg = $self->{gettext} ("Cannot start OpenSSL shell. (__ERRVAL__)",
                                    "__ERRVAL__", $!);
        $self->setError (7777030, $msg);
        return undef;
    }
    $self->_debug ("_start_shell: shell started");

    if ($self->{ENGINE} and
        (
         exists $self->{PRE_ENGINE} or
         exists $self->{POST_ENGINE}
        )
       )
    {
        $self->_debug ("_start_shell: initializing engine");
        my $command;
        if ($self->{DYNAMIC_ENGINE}) {
            $command = "engine dynamic -pre ID:".$self->{ENGINE};
        } else {
            $command = "engine ".$self->{ENGINE};
        }
        $command .= $self->_build_engine_params(KEY_USAGE => $keys->{KEY_USAGE});
        $command .= "\n";
        if (not print {$self->{OPENSSL}} $command)
        {
            my $msg = $self->{gettext} ("Cannot write to the OpenSSL shell. (__ERRVAL__)",
                                        "__ERRVAL__", $!);
            $self->setError (7777040, $msg);
            return undef;
        }

        $self->_debug ("_start_shell: engine intialized");
    }

    return 1;
}

sub _stop_shell
{
    my $self = shift;
    $self->_debug ("_stop_shell: try to stop shell");

    return 1 if (not $self->{OPENSSL});

    print {$self->{OPENSSL}} "exit\n";
    close $self->{OPENSSL};
    $self->{OPENSSL} = undef;

    return 1;
}

sub _execute_command
{
    my $self = shift;
    $self->_debug ("_execute_command: entering function");
    my $keys = { @_ };

    ## initialize openssl (with engine if necessary)

    return undef if (not $self->_start_shell(KEY_USAGE => $keys->{KEY_USAGE}));

    ## run command

    my $command = $keys->{COMMAND}; 
    my $input  = undef;
    $input   = $keys->{INPUT} if (exists $keys->{INPUT});
    $command =~ s/\n*$//;
    $command .= "\n";
    $self->_debug ("_execute_command: $command");
    if (not print {$self->{OPENSSL}} $command)
    {
        my $msg = $self->{gettext} ("Cannot write to the OpenSSL shell. (__ERRVAL__)",
                                    "__ERRVAL__", $!);
        $self->setError (7777060, $msg);
        return undef;
    }
    $self->_debug ("_execute_command: executed");

    ## if key is used and pin callback is set then use it
 
    if ($keys->{KEY_USAGE} and
        $self->{PIN_CALLBACK} and
        $self->{CALLBACK_HANDLER})
    {
        $self->_debug ("_execute_command: executing pin callback");
        $self->{PIN_CALLBACK} ($self->{CALLBACK_HANDLER});
        $self->_debug ("_execute_command: pin callback executed");
    }

    ## send the input

    if ($input and not print {$self->{OPENSSL}} $input."\x00")
    {
        $self->_debug ("_execute_command: write input data");
        my $msg = $self->{gettext} ("Cannot write to the OpenSSL shell. (__ERRVAL__)",
                                    "__ERRVAL__", $!);
        $self->setError (7777065, $msg);
        return undef;
    }
    $self->_debug ("_execute_command: command executed - stopping shell");
    return undef if (not $self->_stop_shell());

    ## check for errors

    $self->_debug ("_execute_command: check for error");

    if (-e "$self->{tmpDir}/${$}_stderr.log")
    {
        $self->_debug ("_execute_command: detected error log");
        ## there was an error
        my $ret = "";
        if (open FD, "$self->{tmpDir}/${$}_stderr.log")
        {
            while( my $tmp = <FD> ) {
                $ret .= $tmp;
            }
            close(FD);
        }
        $self->_debug ("_execute_command: stderr: $ret");
        if ($self->{ENGINE} and
            (
             exists $self->{PRE_ENGINE} or
             exists $self->{POST_ENGINE}
            ) and
            $self->{STDERR_CALLBACK} and
            $self->{CALLBACK_HANDLER})
        {
            $self->_debug ("_execute_command: executing stderr callback");
            $ret = $self->{STDERR_CALLBACK} ($self->{CALLBACK_HANDLER}, $ret);
            $self->_debug ("_execute_command: stderr callback executed");
        }
        unlink ("$self->{tmpDir}/${$}_stderr.log");
        if ($ret =~ /error/i)
        {
            unlink ("$self->{tmpDir}/${$}_stdout.log");
            $self->setError (7777067, $ret);
            return undef;
        }
        
    }

    ## load the output

    my $ret = 1;
    if (-e "$self->{tmpDir}/${$}_stdout.log" and
        open FD, "$self->{tmpDir}/${$}_stdout.log")
    {
        ## there was an output
        $ret = "";
        while( my $tmp = <FD> ) {
            $ret .= $tmp;
        }
        close(FD);
        if ($self->{ENGINE} and
            (
             exists $self->{PRE_ENGINE} or
             exists $self->{POST_ENGINE}
            ) and
            $self->{STDOUT_CALLBACK} and
            $self->{CALLBACK_HANDLER})
        {
            $self->_debug ("_execute_command: executing stdout callback");
            $ret = $self->{STDOUT_CALLBACK} ($self->{CALLBACK_HANDLER}, $ret);
            $self->_debug ("_execute_command: stdout callback executed");
        }
        $ret =~ s/^(OpenSSL>\s)*//s;
        $ret =~ s/OpenSSL>\s$//s;
        $ret = 1 if ($ret eq "");
    }
    unlink ("$self->{tmpDir}/${$}_stdout.log");

    my $msg = $ret;
    $msg = "<NOT LOGGED>" if ($keys->{HIDE_OUTPUT});

    $self->_debug ("_execute_command: leaving successful (return: $msg)");
    return $ret;
}

sub _build_engine_params
{
    my $self = shift;
    my $keys = { @_ };

    my $command = "";

    ## set the pre init commands for the engine

    if (exists $self->{PRE_ENGINE})
    {
        if (ref $self->{PRE_ENGINE})
        {
            foreach my $item (@{$self->{PRE_ENGINE}})
            {
                $command .= " -pre $item";
            }
        } else
        {
            $command .= " -pre ".$self->{PRE_ENGINE};
        }
    }

    ## set the post init commands for the engine

    if (exists $self->{POST_ENGINE})
    {
        if (ref $self->{POST_ENGINE})
        {
            foreach my $item (@{$self->{POST_ENGINE}})
            {
                $command .= " -post $item";
            }
        } else
        {
            $command .= " -post ".$self->{POST_ENGINE};
        }
    }

    $self->_debug ("_build_engine_params: $command");

    ## set the pin if there is no pin callback for the engine
    ## this must be present after -pre SO_PATH:... because
    ## otherwise PIN is executed on
    ## the original pkcs11 engine for example which is from Bull and does
    ## not support PINs like OpenSC

    if ($keys->{KEY_USAGE} and
        $self->{GET_PIN_CALLBACK} and
        $self->{CALLBACK_HANDLER}
       )
    {
        $self->_debug ("_build_engine_params: GET_PIN_CALLBACK used");
        $command .= " ".$self->{GET_PIN_CALLBACK} ($self->{CALLBACK_HANDLER});
    } else {
        $self->_debug ("_build_engine_params: GET_PIN_CALLBACK not present or not used");
    }

    return $command;
}

##############################################################
##                         END                              ##
##             OpenSSL execution environment                ##
##############################################################

sub _debug
{
    my $self = shift;

    return 1 if (not $self->{DEBUG});

    my $text = join (" ", @_);
    $text =~ s/PIN:[^\s]*/PIN:ERASING_FOR_SECURITY/g;
    $text =~ s/-----BEGIN RSA PRIVATE KEY.*?END RSA PRIVATE KEY-----/RSA PRIVATE KEY ERASED FROM OUTPUT/gs;

    print STDERR "OpenCA::OpenSSL->$text\n";

    return 1;
}

sub DESTROY
{
    my $self = shift;

    $self->_stop_shell();
}

################################################################################
##                     OpenCA::OpenSSL::Fast area                             ##
################################################################################

require Exporter;
use AutoLoader;

our @ISA = qw(Exporter);

# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

# This allows declaration	use OpenCA::OpenSSL::Fast ':all';
# If you do not need this, moving things directly into @EXPORT or @EXPORT_OK
# will save memory.
our %EXPORT_TAGS = ( 'all' => [ qw(
	CTX_TEST
	EXFLAG_BCONS
	EXFLAG_CA
	EXFLAG_INVALID
	EXFLAG_KUSAGE
	EXFLAG_NSCERT
	EXFLAG_SET
	EXFLAG_SS
	EXFLAG_V1
	EXFLAG_XKUSAGE
	GEN_DIRNAME
	GEN_DNS
	GEN_EDIPARTY
	GEN_EMAIL
	GEN_IPADD
	GEN_OTHERNAME
	GEN_RID
	GEN_URI
	GEN_X400
	KU_CRL_SIGN
	KU_DATA_ENCIPHERMENT
	KU_DECIPHER_ONLY
	KU_DIGITAL_SIGNATURE
	KU_ENCIPHER_ONLY
	KU_KEY_AGREEMENT
	KU_KEY_CERT_SIGN
	KU_KEY_ENCIPHERMENT
	KU_NON_REPUDIATION
	NS_OBJSIGN
	NS_OBJSIGN_CA
	NS_SMIME
	NS_SMIME_CA
	NS_SSL_CA
	NS_SSL_CLIENT
	NS_SSL_SERVER
	X509V3_EXT_CTX_DEP
	X509V3_EXT_DYNAMIC
	X509V3_EXT_MULTILINE
	X509V3_F_COPY_EMAIL
	X509V3_F_COPY_ISSUER
	X509V3_F_DO_EXT_CONF
	X509V3_F_DO_EXT_I2D
	X509V3_F_HEX_TO_STRING
	X509V3_F_I2S_ASN1_ENUMERATED
	X509V3_F_I2S_ASN1_INTEGER
	X509V3_F_I2V_AUTHORITY_INFO_ACCESS
	X509V3_F_NOTICE_SECTION
	X509V3_F_NREF_NOS
	X509V3_F_POLICY_SECTION
	X509V3_F_R2I_CERTPOL
	X509V3_F_S2I_ASN1_IA5STRING
	X509V3_F_S2I_ASN1_INTEGER
	X509V3_F_S2I_ASN1_OCTET_STRING
	X509V3_F_S2I_ASN1_SKEY_ID
	X509V3_F_S2I_S2I_SKEY_ID
	X509V3_F_STRING_TO_HEX
	X509V3_F_SXNET_ADD_ASC
	X509V3_F_SXNET_ADD_ID_INTEGER
	X509V3_F_SXNET_ADD_ID_ULONG
	X509V3_F_SXNET_GET_ID_ASC
	X509V3_F_SXNET_GET_ID_ULONG
	X509V3_F_V2I_ACCESS_DESCRIPTION
	X509V3_F_V2I_ASN1_BIT_STRING
	X509V3_F_V2I_AUTHORITY_KEYID
	X509V3_F_V2I_BASIC_CONSTRAINTS
	X509V3_F_V2I_CRLD
	X509V3_F_V2I_EXT_KU
	X509V3_F_V2I_GENERAL_NAME
	X509V3_F_V2I_GENERAL_NAMES
	X509V3_F_V3_GENERIC_EXTENSION
	X509V3_F_X509V3_ADD_VALUE
	X509V3_F_X509V3_EXT_ADD
	X509V3_F_X509V3_EXT_ADD_ALIAS
	X509V3_F_X509V3_EXT_CONF
	X509V3_F_X509V3_EXT_I2D
	X509V3_F_X509V3_GET_VALUE_BOOL
	X509V3_F_X509V3_PARSE_LIST
	X509V3_F_X509_PURPOSE_ADD
	X509V3_R_BAD_IP_ADDRESS
	X509V3_R_BAD_OBJECT
	X509V3_R_BN_DEC2BN_ERROR
	X509V3_R_BN_TO_ASN1_INTEGER_ERROR
	X509V3_R_DUPLICATE_ZONE_ID
	X509V3_R_ERROR_CONVERTING_ZONE
	X509V3_R_ERROR_IN_EXTENSION
	X509V3_R_EXPECTED_A_SECTION_NAME
	X509V3_R_EXTENSION_NAME_ERROR
	X509V3_R_EXTENSION_NOT_FOUND
	X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED
	X509V3_R_EXTENSION_VALUE_ERROR
	X509V3_R_ILLEGAL_HEX_DIGIT
	X509V3_R_INVALID_BOOLEAN_STRING
	X509V3_R_INVALID_EXTENSION_STRING
	X509V3_R_INVALID_NAME
	X509V3_R_INVALID_NULL_ARGUMENT
	X509V3_R_INVALID_NULL_NAME
	X509V3_R_INVALID_NULL_VALUE
	X509V3_R_INVALID_NUMBER
	X509V3_R_INVALID_NUMBERS
	X509V3_R_INVALID_OBJECT_IDENTIFIER
	X509V3_R_INVALID_OPTION
	X509V3_R_INVALID_POLICY_IDENTIFIER
	X509V3_R_INVALID_SECTION
	X509V3_R_INVALID_SYNTAX
	X509V3_R_ISSUER_DECODE_ERROR
	X509V3_R_MISSING_VALUE
	X509V3_R_NEED_ORGANIZATION_AND_NUMBERS
	X509V3_R_NO_CONFIG_DATABASE
	X509V3_R_NO_ISSUER_CERTIFICATE
	X509V3_R_NO_ISSUER_DETAILS
	X509V3_R_NO_POLICY_IDENTIFIER
	X509V3_R_NO_PUBLIC_KEY
	X509V3_R_NO_SUBJECT_DETAILS
	X509V3_R_ODD_NUMBER_OF_DIGITS
	X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS
	X509V3_R_UNABLE_TO_GET_ISSUER_KEYID
	X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT
	X509V3_R_UNKNOWN_EXTENSION
	X509V3_R_UNKNOWN_EXTENSION_NAME
	X509V3_R_UNKNOWN_OPTION
	X509V3_R_UNSUPPORTED_OPTION
	X509V3_R_USER_TOO_LONG
	X509_PURPOSE_ANY
	X509_PURPOSE_CRL_SIGN
	X509_PURPOSE_DYNAMIC
	X509_PURPOSE_DYNAMIC_NAME
	X509_PURPOSE_MAX
	X509_PURPOSE_MIN
	X509_PURPOSE_NS_SSL_SERVER
	X509_PURPOSE_SMIME_ENCRYPT
	X509_PURPOSE_SMIME_SIGN
	X509_PURPOSE_SSL_CLIENT
	X509_PURPOSE_SSL_SERVER
	XKU_CODE_SIGN
	XKU_SGC
	XKU_SMIME
	XKU_SSL_CLIENT
	XKU_SSL_SERVER
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	CTX_TEST
	EXFLAG_BCONS
	EXFLAG_CA
	EXFLAG_INVALID
	EXFLAG_KUSAGE
	EXFLAG_NSCERT
	EXFLAG_SET
	EXFLAG_SS
	EXFLAG_V1
	EXFLAG_XKUSAGE
	GEN_DIRNAME
	GEN_DNS
	GEN_EDIPARTY
	GEN_EMAIL
	GEN_IPADD
	GEN_OTHERNAME
	GEN_RID
	GEN_URI
	GEN_X400
	KU_CRL_SIGN
	KU_DATA_ENCIPHERMENT
	KU_DECIPHER_ONLY
	KU_DIGITAL_SIGNATURE
	KU_ENCIPHER_ONLY
	KU_KEY_AGREEMENT
	KU_KEY_CERT_SIGN
	KU_KEY_ENCIPHERMENT
	KU_NON_REPUDIATION
	NS_OBJSIGN
	NS_OBJSIGN_CA
	NS_SMIME
	NS_SMIME_CA
	NS_SSL_CA
	NS_SSL_CLIENT
	NS_SSL_SERVER
	X509V3_EXT_CTX_DEP
	X509V3_EXT_DYNAMIC
	X509V3_EXT_MULTILINE
	X509V3_F_COPY_EMAIL
	X509V3_F_COPY_ISSUER
	X509V3_F_DO_EXT_CONF
	X509V3_F_DO_EXT_I2D
	X509V3_F_HEX_TO_STRING
	X509V3_F_I2S_ASN1_ENUMERATED
	X509V3_F_I2S_ASN1_INTEGER
	X509V3_F_I2V_AUTHORITY_INFO_ACCESS
	X509V3_F_NOTICE_SECTION
	X509V3_F_NREF_NOS
	X509V3_F_POLICY_SECTION
	X509V3_F_R2I_CERTPOL
	X509V3_F_S2I_ASN1_IA5STRING
	X509V3_F_S2I_ASN1_INTEGER
	X509V3_F_S2I_ASN1_OCTET_STRING
	X509V3_F_S2I_ASN1_SKEY_ID
	X509V3_F_S2I_S2I_SKEY_ID
	X509V3_F_STRING_TO_HEX
	X509V3_F_SXNET_ADD_ASC
	X509V3_F_SXNET_ADD_ID_INTEGER
	X509V3_F_SXNET_ADD_ID_ULONG
	X509V3_F_SXNET_GET_ID_ASC
	X509V3_F_SXNET_GET_ID_ULONG
	X509V3_F_V2I_ACCESS_DESCRIPTION
	X509V3_F_V2I_ASN1_BIT_STRING
	X509V3_F_V2I_AUTHORITY_KEYID
	X509V3_F_V2I_BASIC_CONSTRAINTS
	X509V3_F_V2I_CRLD
	X509V3_F_V2I_EXT_KU
	X509V3_F_V2I_GENERAL_NAME
	X509V3_F_V2I_GENERAL_NAMES
	X509V3_F_V3_GENERIC_EXTENSION
	X509V3_F_X509V3_ADD_VALUE
	X509V3_F_X509V3_EXT_ADD
	X509V3_F_X509V3_EXT_ADD_ALIAS
	X509V3_F_X509V3_EXT_CONF
	X509V3_F_X509V3_EXT_I2D
	X509V3_F_X509V3_GET_VALUE_BOOL
	X509V3_F_X509V3_PARSE_LIST
	X509V3_F_X509_PURPOSE_ADD
	X509V3_R_BAD_IP_ADDRESS
	X509V3_R_BAD_OBJECT
	X509V3_R_BN_DEC2BN_ERROR
	X509V3_R_BN_TO_ASN1_INTEGER_ERROR
	X509V3_R_DUPLICATE_ZONE_ID
	X509V3_R_ERROR_CONVERTING_ZONE
	X509V3_R_ERROR_IN_EXTENSION
	X509V3_R_EXPECTED_A_SECTION_NAME
	X509V3_R_EXTENSION_NAME_ERROR
	X509V3_R_EXTENSION_NOT_FOUND
	X509V3_R_EXTENSION_SETTING_NOT_SUPPORTED
	X509V3_R_EXTENSION_VALUE_ERROR
	X509V3_R_ILLEGAL_HEX_DIGIT
	X509V3_R_INVALID_BOOLEAN_STRING
	X509V3_R_INVALID_EXTENSION_STRING
	X509V3_R_INVALID_NAME
	X509V3_R_INVALID_NULL_ARGUMENT
	X509V3_R_INVALID_NULL_NAME
	X509V3_R_INVALID_NULL_VALUE
	X509V3_R_INVALID_NUMBER
	X509V3_R_INVALID_NUMBERS
	X509V3_R_INVALID_OBJECT_IDENTIFIER
	X509V3_R_INVALID_OPTION
	X509V3_R_INVALID_POLICY_IDENTIFIER
	X509V3_R_INVALID_SECTION
	X509V3_R_INVALID_SYNTAX
	X509V3_R_ISSUER_DECODE_ERROR
	X509V3_R_MISSING_VALUE
	X509V3_R_NEED_ORGANIZATION_AND_NUMBERS
	X509V3_R_NO_CONFIG_DATABASE
	X509V3_R_NO_ISSUER_CERTIFICATE
	X509V3_R_NO_ISSUER_DETAILS
	X509V3_R_NO_POLICY_IDENTIFIER
	X509V3_R_NO_PUBLIC_KEY
	X509V3_R_NO_SUBJECT_DETAILS
	X509V3_R_ODD_NUMBER_OF_DIGITS
	X509V3_R_UNABLE_TO_GET_ISSUER_DETAILS
	X509V3_R_UNABLE_TO_GET_ISSUER_KEYID
	X509V3_R_UNKNOWN_BIT_STRING_ARGUMENT
	X509V3_R_UNKNOWN_EXTENSION
	X509V3_R_UNKNOWN_EXTENSION_NAME
	X509V3_R_UNKNOWN_OPTION
	X509V3_R_UNSUPPORTED_OPTION
	X509V3_R_USER_TOO_LONG
	X509_PURPOSE_ANY
	X509_PURPOSE_CRL_SIGN
	X509_PURPOSE_DYNAMIC
	X509_PURPOSE_DYNAMIC_NAME
	X509_PURPOSE_MAX
	X509_PURPOSE_MIN
	X509_PURPOSE_NS_SSL_SERVER
	X509_PURPOSE_SMIME_ENCRYPT
	X509_PURPOSE_SMIME_SIGN
	X509_PURPOSE_SSL_CLIENT
	X509_PURPOSE_SSL_SERVER
	XKU_CODE_SIGN
	XKU_SGC
	XKU_SMIME
	XKU_SSL_CLIENT
	XKU_SSL_SERVER
);

## we take the version from OpenSSL.pm
## our $VERSION = '0.02';

sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.

    my $constname;
    our $AUTOLOAD;
    ($constname = $AUTOLOAD) =~ s/.*:://;
    croak "&OpenCA::OpenSSL::constant not defined" if $constname eq 'constant';
    my ($error, $val) = constant($constname);
    if ($error) { croak $error; }
    {
	no strict 'refs';
	# Fixed between 5.005_53 and 5.005_61
#XXX	if ($] >= 5.00561) {
#XXX	    *$AUTOLOAD = sub () { $val };
#XXX	}
#XXX	else {
	    *$AUTOLOAD = sub { $val };
#XXX	}
    }
    goto &$AUTOLOAD;
}

require XSLoader;
XSLoader::load('OpenCA::OpenSSL', $OpenCA::OpenSSL::VERSION);

# Autoload methods go after =cut, and are processed by the autosplit program.

1;

__END__
