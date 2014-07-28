package OpenCA::OpenSSL::SMIME;

##
## General Errorcodes:
##
## The errorcodes consists of seven numbers:
## 1234567
## 12: module
## 34: function
## 567: errorcode
##
## The modules errorcode is 80.
##
## The functions use the following errorcodes:
##
## new			00
## set_params		01
## errno		02
## err			03
## sign			10
## verify		11
## encrypt		12
## decrypt		13
## get_mime		14
## get_last_signer	15
## status		16
## status_code		17
##
## _setError		xx
## _set_status		94
## _strip_headers	95
## _exec		96
## _save_headers	97
## _sync_data		98
## _save_tmp		99

use 5.006;
use warnings;
use strict;
use File::Temp;
use MIME::Parser;

## our $VERSION = substr q$Revision: 1.2 $, 10;
($OpenCA::OpenSSL::SMIME::VERSION = '$Revision: 1.2 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;
our $errno = undef;
our $errval = undef;


####### Private subs and vars

my %smime = (
	backend		=> undef,
	file		=> undef,	# file containing message
	entity		=> undef,	# MIME::Entity representation
	ca_certs	=> {},		# Hash of OpenCA::X509
	ca_certs_file	=> undef,	# File containing the DER encodings
	DEBUG		=> undef,
	tmpDir		=> undef,
	status		=> [ 0, "" ],	# Status of last decrypt/verify
	header_cache	=> undef,	# MIME::Header for saving orig. headers
	needs_extract	=> undef,	# does actual state require extration
					# of headers?
					# 1: yes, priorize new headers
					# -1: yes, priorize old headers
	last_signer	=> undef,	# Filename for last received signer
					# cert (from verify)
	last_signer_x509=> undef,	# OpenCA::X509 for last received signer
	errno		=> 0,
	err		=> undef);

# Supported ciphers, first is default.
my @Ciphers = qw(des3 des rc2-40 rc2-64 rc2-128);

# Saves data on a temporary file, returns filename.
# Returns open filehandle, filename in list context.

my(@tmpfiles);
sub _save_tmp {
	my($self, $data);
	($self, $data, @_) = @_;

	$self->_setError(0, "");

	my($args) = { @_ };
	my($tfh, $tf) = File::Temp::tempfile(
			DIR => $self->{tmpDir},
			UNLINK => 0);
	push(@tmpfiles, $tf);

	if(ref($data) && ref($data) eq 'GLOB') {
		while(<$data>) {
			return $self->_setError(8099001,
					'OpenCA::OpenSSL::SMIME->_save_tmp: ' .
					'Error writing in tempfile')
				unless($tfh->print($_));
		}
	} else {
		return $self->_setError(8099001, 'OpenCA::OpenSSL::SMIME->_save_tmp: ' .
				'Error writing in tempfile')
			unless($tfh->print($data));
	}

	return ($tfh, $tf) if(wantarray);
	return $self->_setError(8099002, 'OpenCA::OpenSSL::SMIME->_save_tmp: ' .
			'Error closing tempfile')
		unless($tfh->close);
	return $tf;
}

# Sets and reports error states
sub _setError {
	my $self = shift;

	if (scalar (@_) == 4) {
		my $keys = { @_ };
		$self->{errno}	= $keys->{ERRNO};
		$self->{errval}	= $keys->{ERRVAL};
	} else {
		$self->{errno}	= $_[0];
		$self->{errval}	= $_[1];
	}

	$errno  = $self->{errno};
	$errval = $self->{errval};

	return undef unless($self->{errno});

        $self->_debug ("_setError: errno: $self->{errno}");
        $self->_debug ("_setError: errval: $self->{errval}");
	warn("$self->{errval} ($self->{errno})") if($^W);
	## support for: return $self->_setError (1234, "Something fails.") if (not $xyz);
	return undef;
}

sub _debug
{
    my $self = shift;

    return 1 if (not $self->{DEBUG});

    print STDERR "OpenCA::OpenSSL::SMIME->".join (" ", @_)."\n";

    return 1;
}

# Syncing textual and MIME::Entity representations of the object.
sub _sync_data {
	my($self) = shift;

	$self->_setError(0, "");

	if($self->{file} && ! $self->{entity}) {
		my($parser) = MIME::Parser->new();
		$parser->output_under($self->{tmpDir});
		$self->{entity} = $parser->parse_open($self->{file})
			or return $self->_setError(
					8098001,
					'OpenCA::OpenSSL::SMIME->_sync_data: ' .
					'Error parsing input file');
		undef($parser);
		
		return $self->_setError(8098002, 'OpenCA::OpenSSL::SMIME->_sync_data: ' .
				'Error parsing into MIME::Entity')
			unless($self->{entity});

	} elsif(! $self->{file} && $self->{entity}) {

		my($fh, $f) = $self->_save_tmp("") or return(undef);
		$self->{entity}->print($fh)
			or return $self->_setError(
					8098003,
					'OpenCA::OpenSSL::SMIME->_sync_data: ' .
					'Error saving MIME::Entity into ' .
					'tempfile');
		$fh->close
			or return $self->_setError(
					8098004,
					'OpenCA::OpenSSL::SMIME->_sync_data: ' .
					'Error closing tempfile');
		$self->{file} = $f;
	}

	return 1;
}

# Saves non-mime headers, to be restored at end of process. Syncs if no entity.
sub _save_headers {
	my($self) = shift;
	my($tag);

	$self->_setError(0, "");

	# Do we really need to extract any headers?
	return(1) unless($self->{needs_extract});

	# If we have no entity, get it.
	unless($self->{entity}) {
		$self->_sync_data() or return(undef);
	}

	# // If we have no headers' cache, create a new one.
	$self->{headers_cache} = MIME::Head->new()
		unless($self->{headers_cache});

	# Copy headers
	foreach($self->{entity}->head()->tags()) {
		next if(/^(content|MIME)/i);	# // don't save MIME headers
		$tag = $_;
		if($self->{needs_extract} < 0) {	# priority: old headers
			next if($self->{headers_cache}->count($tag));
						# it is in the cache, skip
		} else {			# priority: new headers
			$self->{headers_cache}->delete($tag);
		}
		foreach($self->{entity}->head()->get_all($tag)) {
			$self->{headers_cache}->add($tag, $_);
		}
	}

	$self->{needs_extract} = undef;
	return 1;
}

# Forks and execs subprocess, capturing stderr and exit code. returns
# (exit_code, stderr) in list context and exit_code on scalar context.
sub _exec {
    my($self, @arg) = @_;

    $self->_debug ("_exec: resetting errorcode");
    $self->_setError(0, "");

    my $command = join ' ', @arg;
    $self->_debug ("_exec: command $command");

    ## exexcution in parent environment

    my $res = $self->{backend}->_execute_command (COMMAND   => $command,
                                                  KEY_USAGE => $self->{ENGINE});
    if (not defined $res)
    {
        $self->_setError ($self->{backend}->errno,
                         $self->{backend}->errval);
        if(wantarray) {
            return($self->errno, $self->errval);
        } else {
            return($self->errno);
        }
    } else {
        $res = "" if ($res == 1);
        if (wantarray) {
            return(0, $res);
        } else {
            return(0);
        }
    }

#    my($child, $res);
#	defined($child = open(OUT, '-|'))
#		or return($self->_setError(8096001, 'OpenCA::OpenSSL::SMIME->_exec: Can\'t fork'));
#	if($child) {
#		$res = join('', <OUT>);
#		close(OUT) or not $! or return($self->_setError(8096002, 'OpenCA::OpenSSL::SMIME->_exec: Problems executing ' . join(' ', @arg)));
#
#	} else {
#		select(STDERR); $| = 1;		# make unbuffered
#		select(STDOUT); $| = 1;		# make unbuffered
#		open(STDERR, ">&STDOUT") or die "Can't dup stdout";
#		open(STDOUT, ">/dev/null") or die "Can't close stdout";
#
#		exec(@arg) or die "Can't exec";
#	}
#
#	if(wantarray) {
#		return($?, $res);
#	} else {
#		return($?);
#	}
}

# Strips non-mime headers.
sub _strip_headers {
	my($self) = shift;
	my($modified);

	$self->_setError(0, "");

	return($self->_setError(8095001, 'OpenCA::OpenSSL::SMIME->_strip_headers: no entity found')) unless ($self->{entity});

	$modified = 0;
	foreach($self->{entity}->head()->tags()) {
		next if(/^(content|MIME)/i);	# // don't touch MIME headers
		$self->{entity}->head()->delete($_);
		$modified++;
	}

	if($modified) {				# we made any changes?
		$self->{file} = undef;		# original file is no longer valid
	}
	return 1;
}

# Sets status for last operation
sub _set_status {
	my($self) = shift;

	confess("Invalid invocation") unless (@_ == 2);
	$self->{status} = [ @_ ];

	return 1;
}

###### Public methods

## Create an instance of the Class
sub new {
	my $that = shift;
	my $class = ref($that) || $that;

        my $self = {
		%smime,
	};
        bless $self, $class;

	if(ref($that)) {			# get some defaults from creator
		$self->{backend}	= $that->{backend};
		$self->{gettext}	= $that->{gettext};
		$self->{tmpDir}		= $that->{tmpDir};
		$self->{DEBUG}		= $that->{DEBUG};
		$self->{ca_certs}	= $that->{ca_certs};
		$self->{ca_certs_file}	= $that->{ca_certs_file};
	}
	$self->set_params( @_ ) or return(undef);

	return $self->_setError(8000000, 'OpenCA::OpenSSL::SMIME->new: Missing required parameter: GETTEXT')
		unless($self->{gettext});
	return $self->_setError(8000001,
                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->new: Missing required parameter: SHELL"))
		unless($self->{backend});
	return $self->_setError(8000002,
                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->new: Invalid required parameter: SHELL"))
		unless(ref($self->{backend}));

        return $self;
}

sub set_params {
	my $self = shift;
	my $params = { @_ };
	my $key;

	$self->_setError(0, "");

	foreach $key (keys %{$params}) {
		$self->{backend}   = $params->{$key} if ($key eq 'SHELL');
		$self->{gettext}   = $params->{$key} if ($key eq 'GETTEXT');
		$self->{tmpDir}    = $params->{$key} if ($key eq 'TMPDIR');
		$self->{DEBUG}     = $params->{$key} if ($key eq 'DEBUG');
		$self->{ENGINE}    = $params->{$key} if ($key =~ /ENGINE/i);
	}

	# Default for tmpDir.
	$self->{tmpDir} = File::Temp::tempdir(TMPDIR => 1, CLEANUP => 1)
		unless($self->{tmpDir});

	# Check and save CA_CERTS
	if($params->{CA_CERTS}) {
		return $self->_setError(8001001,
                           $self->{gettext} ("OpenCA::OpenSSL::SMIME->set_params: Invalid parameter for CA_CERTS"))
			unless(ref($params->{CA_CERTS}) eq 'ARRAY');

		my($data);
		foreach(@{$params->{CA_CERTS}}) {
			return $self->_setError(8001002,
                                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->set_params: Invalid array element for CA_CERTS"))
				unless(ref($_) && $_->getPEM());
			$self->{ca_certs}->{$_->getParsed()->{DN}} = $_;
			$data .= $_->getPEM() . "\n";
		}
		$self->{ca_certs_file} = $self->_save_tmp($data);
	}

	# Processing of input data
	if($params->{ENTITY}) {

		return $self->_setError(8001003,
                           $self->{gettext} ("OpenCA::OpenSSL::SMIME->set_params: Invalid data source"))
			unless(ref($params->{ENTITY}));

		$self->{entity} = $params->{ENTITY};
		$self->{file} = undef;
		$self->{headers_cache} = undef;
		$self->{needs_extract} = 1;

	} elsif($params->{DATA}) {

		if(! ref($params->{DATA}) || ref($params->{DATA}) eq 'GLOB') {
			$self->{file} = $self->_save_tmp($params->{DATA})
				or return(undef);
		} elsif(ref($params->{DATA}) && ref($params->{DATA}) eq 'ARRAY') {
			$self->{file} = $self->_save_tmp(join('', @{$params->{DATA}}))
				or return(undef);
		} else {
			return $self->_setError(8001003,
                                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->set_params: Invalid argument to DATA"));
		}

		$self->{entity} = undef;
		$self->{headers_cache} = undef;
		$self->{needs_extract} = 1;

	} elsif($params->{INFILE}) {

		$self->{file} = $params->{INFILE};
		$self->{entity} = undef;
		$self->{headers_cache} = undef;
		$self->{needs_extract} = 1;

	} elsif(! $self->{file} || ! $self->{entity}) {
		return $self->_setError(8001004,
                           $self->{gettext} ("OpenCA::OpenSSL::SMIME->set_params: Missing data source"));
	}

	return 1;
}

sub get_param {
	my $self   = shift;
	my $key    = shift;
	my $params = { @_ };

	return $params->{$key}    if $params->{$key};
	return $params->{uc $key} if $params->{uc $key};
        return $self->{$key}      if $self->{$key};
        return $self->{uc $key}   if $self->{uc $key};

	return undef;
}

sub errno {
        my $self = shift;
        if(ref($self)) {
		return $self->{errno};
	} else {
		return $errno;
	}
}

sub errval {
        my $self = shift;
        if(ref($self)) {
		return $self->{errval};
	} else {
		return $errval;
	}
}

sub sign {
	my($self, %params) = @_;
	my($certfile, $keyfile, $cafile, $oldentity, $oldfile, $oldhead);

	$self->_setError(0, "");

	return($self->_setError(8010001,
                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->sign: Missing required parameter: CERTIFICATE"))) unless($params{CERTIFICATE});

	return($self->_setError(8010002,
                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->sign: Invalid required parameter: CERTIFICATE"))) unless(ref($params{CERTIFICATE}));

	return($self->_setError(8010003,
                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->sign: Missing required parameter: PRIVATE_KEY"))) unless($params{PRIVATE_KEY});

	# If we have no entity, get it.
	unless($self->{entity}) {
		$self->_sync_data() or return(undef);
	}

	# Set up certificate and key.
	$certfile = $self->_save_tmp($params{CERTIFICATE}->getPEM())
		or return(undef);
	$keyfile = $self->_save_tmp($params{PRIVATE_KEY})
		or return(undef);
	
	# Generate chain of trust
	unless($params{NO_INCLUDE_CERTS}) {
		my(%cadata, $catext, $flag);
		$cadata{$params{CERTIFICATE}->getParsed->{ISSUER}} = undef;
		$flag = 1;
		while($flag) {
			$flag = 0;
			foreach(keys(%cadata)) {
				if(! $cadata{$_} && $self->{ca_certs}->{$_}) {
					$flag = 1;
					$cadata{$_} = $self->{ca_certs}->{$_};
					$cadata{$cadata{$_}->getParsed->{ISSUER}} ||= undef;
				}
			}
		}
		foreach(keys(%cadata)) {
			next unless($cadata{$_});
			$catext .= $cadata{$_}->getPEM() . "\n";
		}
		$cafile = $self->_save_tmp($catext) if($catext);
	}

	# Create a copy of the entity, the headers cache and the filename
	if($self->{headers_cache}) {
		$oldhead = $self->{headers_cache}->dup()
			or return($self->_setError(8010004,
                                      $self->{gettext} ("OpenCA::OpenSSL::SMIME->sign: Can't duplicate headers cache for backup")));
	}
	$oldentity = $self->{entity}->dup()
		or return($self->_setError(8010005,
                              $self->{gettext} ("OpenCA::OpenSSL::SMIME->sign: Can't duplicate message for backup")));
	$oldfile = $self->{file};

	# Save headers if necessary.
	unless($params{NO_COPY_HEADERS}) {
		$self->_save_headers() or return(undef);
	}

	# Strip non-MIME headers and sync
	unless($params{NO_STRIP_HEADERS}) {
		$self->_strip_headers() or return(undef);
	}
	$self->_sync_data() or return(undef);

	$ENV{'pwd'} = "$params{KEY_PASSWORD}"
		if (defined($params{KEY_PASSWORD}));

	my(@command, $outfile);
	$outfile = $self->_save_tmp("");
	push(@command, "smime", "-sign");

	push(@command, "-engine", $self->get_param ("ENGINE", %params),
                       "-keyform", $self->get_param ("KEYFORM", %params))
		if($self->get_param ("ENGINE", %params));

	push(@command, "-nocerts") if($params{NO_INCLUDE_CERTS});

	if($params{DETACH}) {
		# FIXME : find out why detached smime
		# get corrupted in transit
	} else {
		push(@command, "-nodetach");	
	}

	push(@command, "-passin", "env:pwd") if($params{KEY_PASSWORD});
	push(@command, "-certfile", $cafile) if($cafile);
	push(@command, "-signer", $certfile,
		       "-inkey", $keyfile,
		       "-in", $self->{file},
		       "-out", $outfile);

	my($ec, $res) = $self->_exec(@command);

	foreach my $oo ( @command ) {
		$self->_debug("SMIME COMMAND: $oo");
	}

	delete($ENV{'pwd'}) if (defined($params{KEY_PASSWORD}));

	unless(defined($ec) && $ec == 0) {
		# Restore
		unless($params{NO_COPY_HEADERS}) {
			if($oldhead) {
				$self->{headers_cache} = $oldhead;
			} else {
				$self->{headers_cache} = undef;
			}
		}
		unless($params{NO_STRIP_HEADERS}) {
			$self->{entity} = $oldentity;
			$self->{file} = $oldfile;
		}
		return($self->_setError(8010006,
                           $self->{gettext} ("OpenCA::OpenSSL::SMIME->sign: unknown problem signing: __ERRVAL__",
                                             "__ERRVAL__", $res)));
	}

	$self->{file} = $outfile;	# Save result
	$self->{entity} = undef;
	$self->{needs_extract} = -1;	# When signing we want the original
					# headers
	return 1;
}

sub verify {
	my($self, %params) = @_;
	my($certfile, $signerfile, @command, $outfile, $oldhead);

	$self->_setError(0, "");
	$self->_set_status(0, "");

	# Clear last signer
	$self->{last_signer} = undef;
	$self->{last_signer_x509} = undef;

	# Check parameters
	unless(! $params{CERTIFICATE} || ref($params{CERTIFICATE})) {
		return($self->_setError(8011001,
                           $self->{gettext} ("OpenCA::OpenSSL::SMIME->verify: Invalid argument for CERTIFICATE")));
	}

	unless($params{CERTIFICATE} || $params{USES_EMBEDDED_CERT}) {
		return($self->_setError(8011002,
                           $self->{gettext} ("OpenCA::OpenSSL::SMIME->verify: No certificate specified and not using embedded certificate")));
	}

	# Set up files
	if($params{CERTIFICATE}) {
		$certfile = $self->_save_tmp($params{CERTIFICATE}->getPEM())
			or return(undef);
	}
	$outfile = $self->_save_tmp("") or return(undef);
	$signerfile = $self->_save_tmp("") or return(undef);

	# Sync data
	$self->_sync_data() or return(undef);

	# Create a copy of the headers cache
	if($self->{headers_cache}) {
		$oldhead = $self->{headers_cache}->dup()
			or return($self->_setError(8011003,
                                      $self->{gettext} ("OpenCA::OpenSSL::SMIME->verify: Can't duplicate headers cache for backup")));
	}

	# Save headers if necessary.
	unless($params{NO_COPY_HEADERS}) {
		$self->_save_headers() or return(undef);
	}

	push(@command, "smime", "-verify");
	push(@command, "-engine", $self->get_param ("ENGINE", %params),
                       "-keyform", $self->get_param ("KEYFORM", %params))
		if($self->get_param ("ENGINE", %params));
	push(@command, "-nointern") unless($params{USES_EMBEDDED_CERT});
	push(@command, "-CAfile", $self->{ca_certs_file}) if($self->{ca_certs_file});
	push(@command, "-certfile", $certfile) if($certfile);
	push(@command, "-in", $self->{file},
		       "-out", $outfile,
		       "-signer", $signerfile);

	my($ec, $res) = $self->_exec(@command);
	unless(defined($ec) && $ec == 0) {
		# Restore headers
		unless($params{NO_COPY_HEADERS}) {
			if($oldhead) {
				$self->{headers_cache} = $oldhead;
			} else {
				$self->{headers_cache} = undef;
			}
		}
# Possible errors reported by openssl:
# :No such file or directory:
# 			fatal: file missing!
# :no content type:	fatal: not even a mime stream
# :invalid mime type:	not a smime content-type
# :wrong content type:	pkcs7 found but it is not a signed
# 			envelope
# :certificate verify error:
# 	Verify error:self signed certificate in certificate chain
# 			ca cert found, but not trusted
# 	Verify error:unable to get local issuer certificate
# 			missing chain of trust
# 	Verify error:certificate has expired
# 			exactly that
# :digest failure:
# :signature failure:	modified message
		if($res =~ /:invalid mime type:|:wrong content type:/si) {
			$self->_set_status(1100, 'message not signed');
		} elsif($res =~ /:certificate verify error:/si) {
			if($res =~ /Verify error:unable to get local issuer certificate/) {
				$self->_set_status(1110, 'invalid certificate chain');
			} elsif($res =~ /Verify error:unable to get local issuer certificate/) {
				$self->_set_status(1111, 'no chain of trust supplied');
			} elsif($res =~ /Verify error:certificate has expired/) {
				$self->_set_status(1112, 'certificate has expired');
			} elsif($res =~ /Verify error:certificate is not yet valid/) {
				$self->_set_status(1113, 'certificate is not yet valid');
			} else {
				$self->_set_status(1119, 'unknown certificate problem: '. ($res =~ /Verify error:(.*)/)[0]);
			}
		} elsif($res =~ /:digest failure:|:signature failure:/) {
			$self->_set_status(1105, 'corrupted message');
		} elsif($res =~ /:no content type:/) {
			return($self->_setError(8011004,
                                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->verify: found invalid mime stream")));
		} elsif($res =~ /:No such file or directory:/) {
			return($self->_setError(8011005,
                                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->verify: missing file")));
		} else {
			return($self->_setError(8011006,
                                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->verify: unknown error: __ERRVAL__",
                                                     "__ERRVAL__", $res)));
		}
		return undef;
	}

	# Save result
	$self->{file} = $outfile;
	$self->{entity} = undef;
	# When verifying we want the encapsulated headers
	$self->{needs_extract} = 1;
	# Save received signer certificate.
	$self->{last_signer} = $signerfile if(-s $signerfile);

	return 1;
}

sub encrypt {
	my($self, %params) = @_;
	my($certfile, $oldentity, $oldfile, $oldhead, $cipher);

	$self->_setError(0, "");

	return($self->_setError(8012001,
                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->encrypt: Missing required parameter: CERTIFICATE"))) unless($params{CERTIFICATE});
	return($self->_setError(8012002,
                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->encrypt: Invalid required parameter: CERTIFICATE"))) unless(ref($params{CERTIFICATE}));

	# Default for cipher, check correctness.
	$cipher = lc($params{CIPHER} || $Ciphers[0]);
	return $self->_setError(8012003,
                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->encrypt: Invalid cipher: __CIPHER__",
                                     "__CIPHER__", $cipher))
		unless(grep({ $_ eq $cipher } @Ciphers));


	# If we have no entity, get it.
	unless($self->{entity}) {
		$self->_sync_data() or return(undef);
	}

	# Set up certificate.
	$certfile = $self->_save_tmp($params{CERTIFICATE}->getPEM())
		or return(undef);
	
	# Create a copy of the entity, the headers cache and the filename
	if($self->{headers_cache}) {
		$oldhead = $self->{headers_cache}->dup()
			or return($self->_setError(8012004,
                                      $self->{gettext} ("OpenCA::OpenSSL::SMIME->encrypt: Can't duplicate headers cache for backup")));
	}
	$oldentity = $self->{entity}->dup()
		or return($self->_setError(8012005,
                              $self->{gettext} ("OpenCA::OpenSSL::SMIME->encrypt: Can't duplicate message for backup")));
	$oldfile = $self->{file};

	# Save headers if necessary.
	unless($params{NO_COPY_HEADERS}) {
		$self->_save_headers() or return(undef);
	}

	# Strip non-MIME headers and sync
	unless($params{NO_STRIP_HEADERS}) {
		$self->_strip_headers() or return(undef);
	}
	$self->_sync_data() or return(undef);

	my(@command, $outfile);
	$outfile = $self->_save_tmp("");
	push(@command, "smime", "-encrypt");

	push(@command, "-engine", $self->get_param ("ENGINE", %params),
                       "-keyform", $self->get_param ("KEYFORM", %params))
		if($self->get_param ("ENGINE", %params));

	push(@command, "-in", $self->{file},
		       "-out", $outfile,
		       "-$cipher",
		       $certfile);

	my($ec, $res) = $self->_exec(@command);

	unless(defined($ec) && $ec == 0) {
		# Restore
		unless($params{NO_COPY_HEADERS}) {
			if($oldhead) {
				$self->{headers_cache} = $oldhead;
			} else {
				$self->{headers_cache} = undef;
			}
		}
		unless($params{NO_STRIP_HEADERS}) {
			$self->{entity} = $oldentity;
			$self->{file} = $oldfile;
		}
		if (not defined $ec)
                {
                    $ec  = $self->errno;
                    $res = $self->errval;
                }
		return($self->_setError(8012006,
                           $self->{gettext} ("OpenCA::OpenSSL::SMIME->encrypt: unknown problem encrypting (__ERRNO__). __ERRVAL__",
		                             "__ERRNO__", $ec,
                                             "__ERRVAL__", $res)));
		return undef;
	}

	$self->{file} = $outfile;	# Save result
	$self->{entity} = undef;
	$self->{needs_extract} = -1;	# When encrypting we want the original
					# headers
	return 1;
}

sub decrypt {
	my($self, %params) = @_;
	my($certfile, $keyfile, $oldhead);

	$self->_setError(0, "");
	$self->_set_status(0, "");

	return($self->_setError(8013001,
                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->decrypt: Missing required parameter: CERTIFICATE"))) unless($params{CERTIFICATE});
	return($self->_setError(8013002,
                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->decrypt: Invalid required parameter: CERTIFICATE"))) unless(ref($params{CERTIFICATE}));
	return($self->_setError(8013003,
                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->decrypt: Missing required parameter: PRIVATE_KEY"))) unless($params{PRIVATE_KEY});

	# Set up certificate and key.
	$certfile = $self->_save_tmp($params{CERTIFICATE}->getPEM())
		or return(undef);
	$keyfile = $self->_save_tmp($params{PRIVATE_KEY})
		or return(undef);

	# If we have no entity, get it.
	unless($self->{entity}) {
		$self->_sync_data() or return(undef);
	}

	# Sync data
	$self->_sync_data() or return(undef);

	# Create a copy of the headers cache
	if($self->{headers_cache}) {
		$oldhead = $self->{headers_cache}->dup()
			or return($self->_setError(8013004,
                                      $self->{gettext} ("OpenCA::OpenSSL::SMIME->decrypt: Can't duplicate headers cache for backup")));
	}

	# Save headers if necessary.
	unless($params{NO_COPY_HEADERS}) {
		$self->_save_headers() or return(undef);
	}

	$ENV{'pwd'} = "$params{KEY_PASSWORD}"
		if (defined($params{KEY_PASSWORD}));

	my(@command, $outfile);
	$outfile = $self->_save_tmp("");
	push(@command, "smime", "-decrypt");

	push(@command, "-engine", $self->get_param ("ENGINE", %params),
                       "-keyform", $self->get_param ("KEYFORM", %params))
		if($self->get_param ("ENGINE", %params));

	push(@command, "-passin", "env:pwd") if($params{KEY_PASSWORD});
	push(@command, "-recip", $certfile,
		       "-inkey", $keyfile,
		       "-in", $self->{file},
		       "-out", $outfile);

	my($ec, $res) = $self->_exec(@command);
	unless(defined($ec) && $ec == 0) {
		# Restore headers
		unless($params{NO_COPY_HEADERS}) {
			if($oldhead) {
				$self->{headers_cache} = $oldhead;
			} else {
				$self->{headers_cache} = undef;
			}
		}
# Possible errors reported by openssl:
# :No such file or directory:
# 			fatal: file missing!
# :no content type:	fatal: not even a mime stream
# :invalid mime type:	not a smime content-type
# :wrong content type:	pkcs7 found but it is not a signed
# 			envelope
# :no recipient matches certificate:
# 			message not for us

		if($res =~ /:invalid mime type:|:wrong content type:/si) {
			$self->_set_status(1300, 'message not encrypted');
		} elsif($res =~ /:no recipient matches certificate:/) {
			$self->_set_status(1301, 'this certificate can\'t decrypt this message');
		} elsif($res =~ /:no content type:/) {
			return($self->_setError(8011004,
                                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->verify: found invalid mime stream")));
		} elsif($res =~ /:No such file or directory:/) {
			return($self->_setError(8011005,
                                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->verify: missing file")));
		} else {
			return($self->_setError(8011006,
                                   $self->{gettext} ("OpenCA::OpenSSL::SMIME->verify: unknown error: __ERRVAL__",
                                                     "__ERRVAL__", $res)));
		}
		return undef;
	}

	# Save result
	$self->{file} = $outfile;
	$self->{entity} = undef;
	# When decrypting we want the encapsulated headers
	$self->{needs_extract} = 1;

	return 1;
}

# Restores saved headers, in a duplicate of the entity. Returns new entity
sub get_mime {
	my($self) = shift;
	my($newe, $newf, $tfh, $tag);

	$self->_setError(0, "");

	# If we have no entity, get it.
	unless($self->{entity}) {
		$self->_sync_data() or return(undef);
	}

	# Duplicate entity
	$newe = $self->{entity}->dup() or return(undef);

	if ($self->{headers_cache}) {
		# Do we need to extract any header?
		unless($self->{needs_extract}) {
			$newe->head($self->{headers_cache});	# replace it
		} else {
			# Restore headers
			foreach($self->{headers_cache}->tags()) {
				$tag = $_;
				if($self->{needs_extract} < 0) {
					# priority: old headers, delete new ones
					$newe->head()->delete($tag);
				} else {
					# priority: new headers, skip if
					# already here
					next if($newe->head()->count($tag));
				}
				# copy
				foreach($self->{headers_cache}->get_all($tag)) {
					$newe->head()->add($tag, $_);
				}
			}
		}
	}

	# // In scalar context, we're done
	return($newe) unless(wantarray);

	# Save new file
	($tfh, $newf) = $self->_save_tmp("") or return(undef);
	$self->{entity}->print($tfh)
		or return $self->_setError(8014001,
                              $self->{gettext} ("OpenCA::OpenSSL::SMIME->get_mime: Error saving MIME::Entity into tempfile"));
	$tfh->close
		or return $self->_setError(8014002,
                              $self->{gettext} ("OpenCA::OpenSSL::SMIME->get_mime: Error closing tempfile"));
	return($newe, $newf);
}

# // Returns last seen signer's certificate in verify operation
# FIXME: should know how to handle multiple signers
sub get_last_signer {
	my($self) = shift;
	my($crt);

	return(undef) unless($self->{last_signer} && -s $self->{last_signer});

	$self->{last_signer_x509} = OpenCA::X509->new(
			SHELL   => $self->{backend},
                        GETTEXT => $self->{gettext},
			INFILE  => $self->{last_signer})
				unless($self->{last_signer_x509});
	return($self->{last_signer_x509});
}

# Return last operation status string, when unsuccessful
sub status {
	my($self) = shift;

	return($self->{status}->[1]);
}

# Return last operation status code, when unsuccessful
sub status_code {
	my($self) = shift;

	return($self->{status}->[0]);
}

#------------------------------
1;

__END__
