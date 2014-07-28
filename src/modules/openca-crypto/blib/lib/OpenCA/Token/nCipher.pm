## OpenCA::Token::nCipher.pm 
##
## Written by Michael Bell for the OpenCA project 2003
## Adapted by Martin Bartosch for the OpenCA project 2004
## Copyright (C) 2003-2004 The OpenCA Project
## All rights reserved.
##
## Adapted to nCipher HSM: 2004-05-25 Martin Bartosch <m.bartosch@cynops.de>
## code based on OpenCA::Token::OpenSSL and others
##
## 2004-08-13 Martin Bartosch
##   - added HSM and key online tests
## 2004-08-16 Martin Bartosch
##   - added timeout for external programs
##   - added extensive error checking
##   - documentation and sample configuration
## 2005-05-10 Martin Bartosch
##   - added dynamic engine support (for OpenSSL 0.9.8):
##     If the token configuration includes at least one PRE_ENGINE key
##     then dynamic engine is used, otherwise this module falls back to
##     static engine support.
##     For dynamic engine support the following option must be added as
##     a minimum:
##     <option>
##       <name>PRE_ENGINE</name>
##       <value>SO_PATH:/usr/local/openssl/lib/engines/libncipher.so</value>
##     </option>
##     The following defaults will be added if not explicitly overridden in
##     the token configuration file:
##     ID:chil, LIST_ADD:1, LOAD, THREAD_LOCKING:1
## 2005-07-12 Martin Bartosch
##   - added persistant caching to infrastructure and key online tests
## 2005-08-10 Martin Bartosch
##   - added missing alarm() calls
##   - autoloaded calls to OpenSSL are timed out via alarm()
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
##
##
## #########################################################################
##
## Error codes:
##   7151010 Crypto Layer not defined
##   7151012 Token name not defined
##   7151013 NFAST_HOME not defined (configuration problem)
##   7151014 NFAST_HOME not accessible (directory does not exist or permission
##           denied)
##   7151015 Unexpected exception during program execution
##   7151016 PRE_ENGINE: SO_PATH not defined (configuration problem)
##
##   7153050 Key is not preloaded/usable
##   7153051 nCipher 'hardserver' process is not running
##   7153052 nCipher 'hardserver' process is not operational
##   7153053 Could not execute 'enquiry' program
##   7153054 Could not execute 'nfkminfo' program
##   7153055 Could not execute 'nfkmverify' program
##   7153056 No operational nCipher modules online
##   7153057 nCipher security world is not initialized / is not usable
##   7153058 No preloaded objects found
##   7153059 External program call timed out
##
##   7154001 Key generation not supported

use strict;

###############################################################
##        ============    nCipher Token    =============     ##
###############################################################

package OpenCA::Token::nCipher;

use OpenCA::OpenSSL;

use FileHandle;
our ($STDERR, $STDOUT);
$STDOUT = \*STDOUT;
$STDERR = \*STDERR;

our ($errno, $errval);
our $AUTOLOAD;

($OpenCA::Token::nCipher::VERSION = '$Revision: 1.1.1.1 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

# Errorcode prefix: 715*
# 71 token modules
# 5  nCipher module

# Preloaded methods go here.

## create a new OpenSSL tokens
sub new {
    my $that = shift;
    my $class = ref($that) || $that;

    my $self = {
                DEBUG     => 0,
                debug_fd  => $STDERR,
                ## debug_msg => (),
		# if online() is called within the grace period return
		# the cached result if it was successful last time
		ONLINECHECKGRACEPERIOD => 60,

		# timeout for external nCipher utilities.
		# there are several error conditions that may lead to
		# nCipher tools not terminating (such as switching off
		# a SCSI attached module). in order to gracefully handle
		# this we introduce a sensible timeout after which the
		# command will be terminated.
		CHECKCMDTIMEOUT => 15,

		# temporary directory
		TMPDIR => "/tmp",
               };

    bless $self, $class;

    my $keys = { @_ };
    $self->{CRYPTO}       = $keys->{OPENCA_CRYPTO};
    $self->{gettext}      = $keys->{GETTEXT};
    $self->{NAME}         = $keys->{OPENCA_TOKEN};
    $self->{MODE}         = $keys->{TOKEN_MODE};
    $self->{DEBUG}        = $keys->{DEBUG};
    $self->{KEY}          = $keys->{KEY};

    foreach (qw(CHECKCMDTIMEOUT ONLINECHECKGRACEPERIOD TMPDIR)) {
        if (exists $keys->{$_} and ($keys->{$_} ne "")) {
            $self->{$_} = $keys->{$_};
        }
    }

    return $self->setError (7151013,
               $self->{gettext} ("NFAST_HOME not defined."))
        if (not $keys->{NFAST_HOME});
    return $self->setError (7151014,
               $self->{gettext} ("NFAST_HOME not accessible."))
        if (! (-d $keys->{NFAST_HOME} and -x $keys->{NFAST_HOME}));
  
    $self->{NFAST_HOME}   = $keys->{NFAST_HOME};

     # provide sensible default for wrapper if not explicitly defined
    $keys->{WRAPPER} = $keys->{NFAST_HOME} . "/bin/with-nfast -M" 
	unless (exists $keys->{WRAPPER} and ($keys->{WRAPPER} ne ""));

    $self->{WRAPPER}      = $keys->{WRAPPER};

    return $self->setError (7151010,
               $self->{gettext} ("Crypto layer is not defined."))
        if (not $self->{CRYPTO});
    return $self->setError (7151012,
               $self->{gettext} ("The name of the token is not defined."))
        if (not $self->{NAME});

    $keys->{ENGINE} = "chil";
    $keys->{CERT} = $keys->{PEM_CERT};

    # check if we are configured as a dynamic engine
    if (exists $keys->{PRE_ENGINE}) {
	$keys->{DYNAMIC_ENGINE}   = 1;
	# $keys->{GET_PIN_CALLBACK} = \&_get_pin_callback;
	$keys->{STDOUT_CALLBACK}  = \&_stdout_callback;
	$keys->{CALLBACK_HANDLER} = $self;

	# convert scalar to arrayref
	my $pre_ref;
	if (ref $keys->{PRE_ENGINE}) {
	    $pre_ref = $keys->{PRE_ENGINE};
	} else {
	    push(@{$pre_ref}, $keys->{PRE_ENGINE});
	}
	$keys->{PRE_ENGINE} = $pre_ref;

	return $self->setError (7151016,
				$self->{gettext} ("7151016 PRE_ENGINE: SO_PATH not defined (configuration problem)"))
	    unless (grep(/SO_PATH/, @{$keys->{PRE_ENGINE}}));
	
	
	# check if we have to provide PRE_ENGINE defaults
	# unshift -> add to the beginning of the list
	unshift @{$keys->{PRE_ENGINE}}, "LIST_ADD:1"
	    unless (grep(/^LIST_ADD:/, @{$keys->{PRE_ENGINE}}));

	unshift @{$keys->{PRE_ENGINE}}, "ID:chil"
	    unless (grep(/^ID:/, @{$keys->{PRE_ENGINE}}));

	# push -> add to the end of the list
	push @{$keys->{PRE_ENGINE}}, "LOAD"
	    unless (grep(/^LOAD/, @{$keys->{PRE_ENGINE}}));

	push @{$keys->{PRE_ENGINE}}, "THREAD_LOCKING:1"
	    unless (grep(/^THREAD_LOCKING:/, @{$keys->{PRE_ENGINE}}));
    }

    $self->{OPENSSL} = OpenCA::OpenSSL->new ( %{$keys} );

    return $self->setError ($OpenCA::OpenSSL::errno, $OpenCA::OpenSSL::errval)
        if (not $self->{OPENSSL});

    $self->debug("new:  KEY: " . $self->{KEY});
    $self->debug("new:  NFAST_HOME: " . $self->{NFAST_HOME});
    $self->debug("new:  WRAPPER: " . $self->{WRAPPER});
    $self->debug("new:  TMPDIR: " . $self->{TMPDIR});

    return $self;
}

# Handle persistant caching of status information.
# If TIMEOUT is not specified, records the current timestamp in the
# state file.
# If TIMEOUT is specified the method checks if the state file exists.
# If the state file as a mtime that is younger than TIMEOUT (in seconds),
# the actual age (seconds) of the last write operation is returned (1 or 
# higher)
# If the state file is older than TIMEOUT, 0 is returned.
#
# arguments:
# ID => name of the cache item, required
# TIMEOUT => number of seconds to accept cached status, optional
# RETRIGGER => update cached result on success
# return:
# undef: error or no previous status present
# 0: timeout expired
# positive number: timeout not expired (age of last status write)
sub cachestatus {
    my $self = shift;
    my $keys = { @_ };

    return undef unless defined $keys->{ID};

    my $filename = $self->{TMPDIR} . "/openca_cache_nCipher_" . $keys->{ID};

    if (defined $keys->{RESET}) {
	# reset cache for this id
	unlink $filename;
	return 1;
    } elsif (defined $keys->{TIMEOUT}) {
	return undef unless (-e $filename);
	my $age = time - (stat($filename))[9];
	$self->debug("cachestatus: state file $filename age: $age");
	return undef if ($age < 0);
	$age = 1 if ($age == 0);
	if ($age < $keys->{TIMEOUT}) {
	    $self->debug("cachestatus: status was updated within configured timeout of " . $keys->{TIMEOUT} . " seconds ($age seconds ago)");
	    $self->cachestatus(ID => $keys->{ID}) if (exists $keys->{RETRIGGER} and $keys->{RETRIGGER});
	    return $age;
	}
	$self->debug("cachestatus: timeout expired for " . $keys->{ID});
	unlink $filename;
	return 0;
    } else {
	$self->debug("cachestatus: caching online status in $filename");
	local *HANDLE;
	open HANDLE, ">$filename";
	close HANDLE;
    }
}



# get object hash for our private key and store it in an internal
# data structure for later reference. returns cached value if it has
# been called before.
# ret: object hash value of the private key for this token
#      undef on error
sub getKeyHash {
    my $self = shift;

    return $self->{KEYINFO}->{$self->{KEY}}->{OCS}->{HASH} 
	if (exists $self->{KEYINFO}->{$self->{KEY}}); 

    $self->debug("getKeyHash: Getting object hash for key " . $self->{KEY});

    # get object hash for private key
    my @cmd = (qq("$self->{NFAST_HOME}/bin/nfkmverify"),
	 	"hwcrhk",
		qq("$self->{KEY}"));

    my $keyid = "";
    my $keyinfo;
    my @keys;
    eval {
	local $SIG{ALRM} = sub { die "alarm\n" };
	alarm $self->{CHECKCMDTIMEOUT};

	# call nfkmverify to get object hash for key
	$self->debug("getKeyHash: exec: " . join (' ', @cmd));
	if (! open HANDLE, join (' ', @cmd) . "|") {
            $self->debug("getKeyHash: nCipher nfkmverify: could not run command '" . join (' ', @cmd) . "'");
       	    $self->setError (7153055,
			$self->{gettext} ("Could not execute nCipher nfkmverify command"));
	    alarm 0;
            return undef;
	}

	# parse nfkmverify output
	while (<HANDLE>) {
	    chomp;
	    if (/^\*\* \[Application key hwcrhk (.*)\]/) {
                $keyid = $1;
	        # $self->debug("getKeyHash: key id: $keyid");
	        push (@keys, $keyid);
	    } else {
		if ($keyid ne "") {
		    if (/^\s*Cardset protected:\s+(\d+)\/(\d+)\s*(.*?)\s*\[(\d+)s\s+`(.*?)'\]/) { # ` make emacs happy
		        $keyinfo->{$keyid}->{OCS}->{QUORUM}->{K} = $1;
		        $keyinfo->{$keyid}->{OCS}->{QUORUM}->{N} = $2;
		        $keyinfo->{$keyid}->{OCS}->{TYPE} = $3;
		        $keyinfo->{$keyid}->{OCS}->{TIMEOUT} = $4;
		        $keyinfo->{$keyid}->{OCS}->{NAME} = $5;
		    }
		    if (/^\s*Cardset hash\s+(.*)/) {
		        $keyinfo->{$keyid}->{OCS}->{HASH} = $1;
		    }
		    if (/^\s*Type\s+(.*)\s+(\d+)/) {
		        $keyinfo->{$keyid}->{TYPE} = $1;
		        $keyinfo->{$keyid}->{BIT} = $2;
		    }
	        }
	    }
        }
        close HANDLE;

	alarm 0;
    };
    # handle exceptions
    if ($@) {
	if ($@ ne "alarm\n") {
	    $self->setError(7151015,
			    $self->{gettext} ("Unexpected exception during program execution"));
	    return undef;
	}
        $self->debug("getKeyHash: nCipher nfkmverify did not terminate within timeout and was interrupted administratively");
       	$self->setError (7153059,
			$self->{gettext} ("External program call timed out"));
        return undef;
    }

    if ($? != 0) {
        $self->debug("getKeyHash: nCipher nfkmverify returned error code $?");
       	$self->setError (7153055,
			$self->{gettext} ("Could not execute nCipher nfkmverify command"));
        return undef;
    }

    $self->debug("getKeyHash: Key information summary");
    foreach (@keys) {
	my $k = \$keyinfo->{$_};
	$self->debug("getKeyHash: Key $_:");
	$self->debug("getKeyHash:   Type: $$k->{TYPE} ($$k->{BIT} bit)");
	$self->debug("getKeyHash:   OCS name: $$k->{OCS}->{NAME}");
	$self->debug("getKeyHash:   OCS hash: $$k->{OCS}->{HASH}");
	$self->debug("getKeyHash:   OCS type: $$k->{OCS}->{TYPE}");
	$self->debug("getKeyHash:   OCS quorum: $$k->{OCS}->{QUORUM}->{K}/$$k->{OCS}->{QUORUM}->{N}");
	$self->debug("getKeyHash:   OCS timeout: $$k->{OCS}->{TIMEOUT}");
    }

    $self->{KEYINFO} = $keyinfo;
    return $keyinfo->{$keyid}->{OCS}->{HASH};
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
    
    print $STDERR "PKI Master Alert: OpenCA::Token::nCipher error\n";
    print $STDERR "PKI Master Alert: Aborting all operations\n";
    print $STDERR "PKI Master Alert: Error:   $errno\n";
    print $STDERR "PKI Master Alert: Message: $errval\n";
    print $STDERR "PKI Master Alert: debugging messages of empty token follow\n"
;
    $self->{debug_fd} = $STDERR;
    $self->debug ();
    $self->{debug_fd} = $STDOUT;

    # clear cached key status information
    $self->cachestatus(ID => 'key_' . $self->{KEY},
		       RESET => 1);

    ## support for: return $self->setError (1234, "Something fails.") if (not $xyz);
    return undef;
}

sub errno {
    my $self = shift;
    return $self->{errno};
}

sub errval {
    my $self = shift;
    return $self->{errval};
}

sub debug {

    my $self = shift;
    if ($_[0]) {
        $self->{debug_msg}[scalar @{$self->{debug_msg}}] = $_[0];
        $self->debug () if ($self->{DEBUG});
    } else {
        my $oldfh;
        if ($self->{errno})
        {
            $oldfh = select $self->{debug_fd};
            print "PKI Debugging: OpenCA::Token::nCipher error\n";
            print "PKI Debugging: Aborting all operations\n";
            print "PKI Debugging: Error:   ".$self->{errno}."\n";
            print "PKI Debugging: Message: ".$self->{errval}."\n";
            print "PKI Debugging: debugging messages of OpenSSL token follow\n";
            select $oldfh;
        }
        my $msg;
        foreach $msg (@{$self->{debug_msg}}) {
            $msg =~ s/ /&nbsp;/g if ($self->{debug_fd} eq $STDOUT);
            my $oldfh = select $self->{debug_fd};
            print "OpenCA::Token::nCipher->$msg<br>\n";
            select $oldfh;
        }
        $self->{debug_msg} = ();
    }
}

sub login {
    my $self = shift;

    # check if key is online
    if ($self->online() and $self->keyOnline()) {
	$self->{ONLINE} = 1;
	return 1;
    }
    return undef;
}

# fake logout function
sub logout {
    my $self = shift;
    $self->{ONLINE} = 0;
    return 1;
}

# check if HSM is attached, online and hardserver process is running
# the following tests are performed:
# - hardserver daemon is running and reports that nCipher is operational
# - at least one nCipher module is online
sub online {
    my $self = shift;
    $self->debug("online: nCipher HSM online check");

    # if the last check was performed successfully within our grace period
    # simply return the cached result
#    if (defined $self->{HSMONLINE} and (time - $self->{HSMONLINE} < $self->{ONLINECHECKGRACEPERIOD})) {
    if ($self->cachestatus(ID => 'ncipher_module',
			   TIMEOUT => $self->{ONLINECHECKGRACEPERIOD},
			   RETRIGGER => 1)) {
	$self->debug("online: Last HSM online check was performed less than " . $self->{ONLINECHECKGRACEPERIOD} . " seconds ago. Returning cached result.");
	return 1;
    }

    $self->debug("online: Checking nCipher infrastructure");
    # call enquiry to collect information for hardserver and attached modules


    my $section = "";
    my $enquiry;
    my @modules;
    eval {
	local $SIG{ALRM} = sub { die "alarm\n" };
	alarm $self->{CHECKCMDTIMEOUT};
	
	my @cmd = (qq("$self->{NFAST_HOME}/bin/enquiry"));
	$self->debug("online: exec: " . join (' ', @cmd));
	if (! open HANDLE, join (' ', @cmd) . "|") {
	    $self->debug("online: nCipher enquiry: could not run command '" . join (' ', @cmd) . "'");
	    $self->setError (7153053,
			     $self->{gettext} ("Could not execute nCipher enquiry command"));
	    alarm 0;
	    return undef;
	}
	
	# parse enquiry output
	while (<HANDLE>) {
	    chomp;
	    if (/^\S/) {
		s/[: \#]//g;
		$section = lc($_);
		# $self->debug("online:   section: " . lc($_));
		push (@modules, $section) if ($section =~ /^module/);
	    } else {
		if (($section ne "") and
		    (/^\s+(mode|version)\s\s+(\S+)/)) {
		    # $self->debug("online:     property: $1, value: $2");
		    $enquiry->{$section}->{lc($1)} = $2;
		}
	    }
	}
	close HANDLE;
	alarm 0;
    };
    
    # handle exceptions
    if ($@) {
	if ($@ ne "alarm\n") {
	    $self->setError(7151015,
			    $self->{gettext} ("Unexpected exception during program execution"));
	    return undef;
	}
        $self->debug("online: nCipher enquiry did not terminate within timeout and was interrupted administratively");
       	$self->setError (7153059,
			 $self->{gettext} ("External program call timed out"));
        return undef;
    }

    if ($? != 0) {
        $self->debug("online: nCipher enquiry: hardserver is not running (error code $?)");
       	$self->setError (7153051,
			$self->{gettext} ("nCipher hardserver process is not running"));
        return undef;
    }

    $self->debug("online: nCipher hardserver information");
    my $operational_modules = 0;
    foreach (('server', @modules)) {
	$self->debug("online:   '$_' (version: $enquiry->{$_}->{version}) is $enquiry->{server}->{mode}");
	$operational_modules++ if (($_ ne "server") and ($enquiry->{$_}->{mode} eq "operational")); 
    }

    if ($enquiry->{server}->{mode} ne "operational") {
       	$self->setError (7153052,
			$self->{gettext} ("nCipher hardserver process is not operational"));
	return undef;
     }

     if ($operational_modules < 1) {
	$self->debug("online: No operational nCipher modules are online.");
       	$self->setError (7153056,
			$self->{gettext} ("No operational nCipher modules online"));
	return undef;
     }

    $self->cachestatus(ID => 'ncipher_module');

    return 1;
}


# check if our private key is currently preloaded and usable
sub keyOnline {
    my $self = shift;
    $self->debug("keyOnline: nCipher key online check");

    # if the last check was performed successfully within our grace period
    # simply return the cached result
#    if (defined $self->{KEYONLINE} and (time - $self->{KEYONLINE} < $self->{ONLINECHECKGRACEPERIOD})) {
    if ($self->cachestatus(ID => 'key_' . $self->{KEY},
			   TIMEOUT => $self->{ONLINECHECKGRACEPERIOD},
			   RETRIGGER => 1)) {
	$self->debug("keyOnline: Last key online check was performed less than " . $self->{ONLINECHECKGRACEPERIOD} . " seconds ago. Returning cached result.");
	return 1;
    }
    
    # check security world and get information about preloaded objects
    my @cmd = ($self->{WRAPPER},
		"$self->{NFAST_HOME}/bin/nfkminfo");

    my $section = "";
    my $worldinfo;
    eval {
	local $SIG{ALRM} = sub { die "alarm\n" };
	alarm $self->{CHECKCMDTIMEOUT};

	$self->debug("keyOnline: exec: " . join (' ', @cmd));
	if (! open HANDLE, join (' ', @cmd) . "|") {
	    $self->debug("keyOnline: nCipher nfkminfo: could not run command '" . join (' ', @cmd) . "'");
	    $self->setError (7153054,
			     $self->{gettext} ("Could not execute nCipher nfkminfo command"));
	    alarm 0;
	    return undef;
	}
	
	# parse nfkminfo output
	while (<HANDLE>) {
	    chomp;
	    if (/^\S/) {
		s/[: \#\-]//g;
		$section = lc($_);
		# $self->debug("keyOnline:   section: " . lc($_));
	    } else {
		if (($section ne "") and
		    (/^\s+(state)\s\s+(.*)/)) {
		    # $self->debug("keyOnline:     property: $1, value: $2");
		    $worldinfo->{$section}->{lc($1)} = $2;
		}
		if ($section =~ /preloadedobjects/) {
		    /\s+([0-9A-Fa-f]+)/;
		    # $self->debug("keyOnline:     hash: $1");
		    $worldinfo->{$section}->{preloaded}->{$1}++;
		}
	    }
	}
	close HANDLE;
	alarm 0;
    };

    # handle exceptions
    if ($@) {
	if ($@ ne "alarm\n") {
	    $self->setError(7151015,
			    $self->{gettext} ("Unexpected exception during program execution"));
	    return undef;
	}
        $self->debug("keyOnline: nCipher nfkminfo did not terminate within timeout and was interrupted administratively");
       	$self->setError (7153059,
			 $self->{gettext} ("External program call timed out"));
        return undef;
    }
    
    if ($? != 0) {
        $self->debug("keyOnline: nCipher nfkminfo returned error code $?");
       	$self->setError (7153054,
			$self->{gettext} ("Could not execute nCipher nfkminfo command"));
        return undef;
    }

    $self->debug("keyOnline: nCipher security world information");
    $self->debug("keyOnline:   state:" . $worldinfo->{world}->{state});
    my $initialized = 0;
    my $usable = 0;
    foreach (split(/\s+/, $worldinfo->{world}->{state})) {
	$initialized++ if ($_ eq "Initialised");
	$usable++ if ($_ eq "Usable");
    }

    if (! $initialized) {
	$self->debug("keyOnline: Security world is not initialized.");
       	$self->setError (7153057,
			$self->{gettext} ("Security world not initialized/usable"));
        return undef;
    }
    if (! $usable) {
	$self->debug("keyOnline: Security world is not usable.");
       	$self->setError (7153057,
			$self->{gettext} ("Security world not initialized/usable"));
        return undef;
    }

    if (! exists $worldinfo->{$section}->{preloaded}) {
	$self->debug("keyOnline: No preloaded objects found");
       	$self->setError (7153058,
			$self->{gettext} ("No preloaded objects found"));
        return undef;
    }

    $self->debug("keyOnline: Preloaded objects:");
    foreach (keys %{$worldinfo->{$section}->{preloaded}}) {
	$self->debug("keyOnline:   $_");
    } 

    # now we have got a list of preloaded objects. verify it against
    # the object hash of the desired private key.
    # so first find out what the hash of the key is.


    my $ocshash = $self->getKeyHash();
    $self->debug("keyOnline: Verify if key ocs object hash $ocshash is preloaded");
    if (! exists $worldinfo->{$section}->{preloaded}->{$ocshash}) {
	$self->debug("keyOnline: Object is not preloaded, key is not usable");
        $self->setError (7153050,
			$self->{gettext} ("Required object is not preloaded, key is not usable"));
        return undef;
    }
    $self->debug("keyOnline: Key seems to be usable");

    # remember key online status
    $self->cachestatus(ID => 'key_' . $self->{KEY});

    return 1;
}

sub getMode {
    return "daemon";
}

# # failover to default token OpenSSL which uses -engine
# # see new to get an idea what is going on
sub AUTOLOAD {
    my $self = shift;
    if ($AUTOLOAD =~ /OpenCA::OpenSSL/)
    {
        print STDERR "PKI Master Alert: OpenCA::OpenSSL is missing a function\n";
        print STDERR "PKI Master Alert: $AUTOLOAD\n";
        $self->setError (666,
			 $self->{gettext} ("OpenCA::OpenSSL is missing a function. __FUNCTION
__",
					   "__FUNCTION__", $AUTOLOAD));
        return undef;
    }
    $self->debug ("OpenCA::Token::nCipher: AUTOLOAD => $AUTOLOAD");
    return 1 if ($AUTOLOAD eq 'OpenCA::Token::nCipher::DESTROY');

    my $function = $AUTOLOAD;
    $function =~ s/.*:://g;

    $self->debug ("nCipher AUTOLOAD function $function");

    my $ret;
    eval {
	local $SIG{ALRM} = sub { die "alarm\n" };
	alarm $self->{CHECKCMDTIMEOUT};
	
	$ret = $self->{OPENSSL}->$function ( @_ );
	alarm 0;
    };
    # handle exceptions
    if ($@) {
	if ($@ ne "alarm\n") {
	    $self->setError(7151015,
			    $self->{gettext} ("Unexpected exception during program execution"));
	    return undef;
	}
        $self->debug("AUTOLOAD: OpenCA::OpenSSL::$function did not terminate within timeout and was interrupted administratively");
       	$self->setError (7153059,
			 $self->{gettext} ("External program call timed out"));
        return undef;
    }

    $self->setError ($OpenCA::OpenSSL::errno, $OpenCA::OpenSSL::errval);
    return $ret;
 }


sub genKey {
    my $self = shift;

    my $keys = { @_ };

    return $self->setError (7154001,
			    $self->{gettext} ("Key generation not supported."));
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
