## OpenCA::AC.pm 
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
##    Includes a new database "ldap" which implements authentication and role 
##    mapping via ldap (or Active Directory). 
##    Written by Peter Gietz, DAASI International GmbH, for the Evangelische
##    Landeskirche Wuerttemberg

 
use strict;

package OpenCA::AC;

use XML::Twig;
use OpenCA::TRIStateCGI;
use OpenCA::Tools;
use OpenCA::Log::Message;

use FileHandle;
use Digest::SHA1 qw( sha1_hex );

my $is_ldaps;

eval ( "use Net::LDAPS;" );
if ($@) {
    $is_ldaps=0;
} else {
    $is_ldaps=1;
}

use Net::LDAP;

use Net::LDAP::Util qw(ldap_error_text
		   ldap_error_name
		   ldap_error_desc
		   );

our ($ldapoperation, $ldapmsg);
our ($errno, $errval);

($OpenCA::AC::VERSION = '$Revision: 1.17 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

# Preloaded methods go here.

## Create an instance of the Class
sub new {
    my $that = shift;
    my $class = ref($that) || $that;

    my $self = {
                DEBUG		=> 0,
                DEBUG_STDERR	=> 0,
                DEBUG_CT  	=> 0,
                ## debug_msg => ()
               };

    bless $self, $class;

    my $keys = { @_ };
    ## FIXME: this is really dangerous
    $self->{configfile}  = $keys->{CONFIG};
    $self->{CRYPTO}      = $keys->{CRYPTO};
    $self->{cryptoShell} = $self->{CRYPTO}->getToken;
    $self->{db}          = $keys->{DB};
    $self->{cgi}         = $keys->{CGI};
    $self->{DEBUG}       = 1 if ($keys->{DEBUG} ne "");
    $self->{DEBUG_STDERR} = 1 if ($keys->{DEBUG_STDERR} ne "" );
    $self->{log}         = $keys->{LOG};
    $self->{gui}         = $keys->{GUI};
    $self->{gettext}     = $keys->{GETTEXT};
    $self->{session}     = $keys->{SESSION};
    $self->{cache}       = $keys->{CACHE};

    $self->{tools} = new OpenCA::Tools ("GETTEXT" => $self->{gettext});

    if (not $self->{log}) {
        $self->setError (6211005,
            $self->{gettext} ("There is no log facility defined."));
        return undef;
    }

    if ($self->{configfile} eq "") {
        $self->setError (6211010,
            $self->{gettext} ("The configfile was not specified."));
        return undef;
    }

    return undef if (not $self->loadConfig ());

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

    if ($self->{errno} == 6211005) {
        $self->debug("OpenCA Log error: ".$self->{errno}.": ".
						$self->{errval}."\n");
    } else {
        $self->{log}->addMessage (OpenCA::Log::Message->new (HASHREF => $self->{journal}));
    }

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

sub checkAccess {

    my $self = shift;

    ## init new session if configuration caching is used

    my $keys =  { @_ };
    $self->{db}      = $keys->{DB}      if (exists $keys->{DB});
    $self->{cgi}     = $keys->{CGI}     if (exists $keys->{CGI});
    $self->{gui}     = $keys->{GUI}     if (exists $keys->{GUI});
    $self->{session} = $keys->{SESSION} if (exists $keys->{SESSION});

    ## start the real checking

    $self->init_journal ();

    return undef if (not $self->checkChannel());
    return undef if (not $self->checkIdent());
    return undef if (not $self->checkACL());
    return undef if (not $self->initToken());

    $self->{journal}->{LEVEL}   = "info";
    return $self->setError ($self->{log}->errno, $self->{log}->errval)
        if (not $self->{log}->addMessage (OpenCA::Log::Message->new (HASHREF => $self->{journal})));

    return 1;
}

sub init_journal {

    my $self = shift;

    $self->{journal}->{CLASS}   = "access_control";
    $self->{journal}->{LEVEL}   = "critical";
    $self->{journal}->{message} = "";

    foreach my $param ($self->{cgi}->param())
    {
        if ($param =~ /(pass|_get_token_param_)/i)
        {
            $self->{journal}->{cgi}->{params}->{$param}->{"value position=\"0\""} = "********";
        } else {
            my @values = $self->{cgi}->param($param);
            for (my $i=0; $i < scalar @values; $i++)
            {
                $self->{journal}->{cgi}->{params}->{$param}->{"value position=\"$i\""} = $values [$i];
            }
        }
    }

    return 1;
}

sub debug {

    my $self = shift;
    if ($_[0]) {
        $self->{debug_msg}[scalar @{$self->{debug_msg}}] = $_[0];
        $self->debug () if ($self->{DEBUG});
    } else {
        my $msg;
	if ( $self->{DEBUG_STDERR} ) {
        	foreach $msg (@{$self->{debug_msg}}) {
        	    print STDERR "OpenCA::AC->$msg\n";
        	}
	}
        $self->{debug_msg} = ();
    }

}

#############################################################################
##                         load the configuration                          ##
##                            (caching support)                            ##
#############################################################################

sub loadConfig
{
    my $self = shift;
    $self->debug ("loadConfig: entering function");

    return undef if (not $self->loadChannel);
    return undef if (not $self->loadLoginConfig);
    return undef if (not $self->loadModuleID);
    return undef if (not $self->loadRoleConfig);
    return undef if (not $self->loadOperationConfig);
    return undef if (not $self->loadACL);

    $self->debug ("loadConfig: leaving function successfully");
    return 1;
}

sub loadChannel
{
    my $self = shift;

    $self->debug ("    loading channel configuration ...");

    $self->{channel}->{config}->{channel_type} =
        $self->{cache}->get_xpath (
                                   FILENAME => $self->{configfile},
                                   XPATH    => 'access_control/channel/type'
                                  );
    $self->{channel}->{config}->{security_protocol} =
        $self->{cache}->get_xpath (
                                   FILENAME => $self->{configfile},
                                   XPATH    => 'access_control/channel/protocol'
                                  );
    $self->{channel}->{config}->{source} =
        $self->{cache}->get_xpath (
                                   FILENAME => $self->{configfile},
                                   XPATH    => 'access_control/channel/source'
                                  );
    $self->{channel}->{config}->{asymmetric_cipher} =
        $self->{cache}->get_xpath (
                                   FILENAME => $self->{configfile},
                                   XPATH    => 'access_control/channel/asymmetric_cipher'
                                  );
    $self->{channel}->{config}->{asymmetric_keylength} =
        $self->{cache}->get_xpath (
                                   FILENAME => $self->{configfile},
                                   XPATH    => 'access_control/channel/asymmetric_keylength'
                                  );
    $self->{channel}->{config}->{symmetric_cipher} =
        $self->{cache}->get_xpath (
                                   FILENAME => $self->{configfile},
                                   XPATH    => 'access_control/channel/symmetric_cipher'
                                  );
    $self->{channel}->{config}->{symmetric_keylength} =
        $self->{cache}->get_xpath (
                                   FILENAME => $self->{configfile},
                                   XPATH    => 'access_control/channel/symmetric_keylength'
                                  );

    if (not defined $self->{channel}->{config}->{channel_type} or
        not defined $self->{channel}->{config}->{security_protocol} or
        not defined $self->{channel}->{config}->{source} or
        not defined $self->{channel}->{config}->{asymmetric_cipher} or
        not defined $self->{channel}->{config}->{asymmetric_keylength} or
        not defined $self->{channel}->{config}->{symmetric_cipher} or
        not defined $self->{channel}->{config}->{symmetric_keylength})
    {
        $self->setXMLerror (6251021, "Connection verification");
        return undef;
    }

    $self->{channel}->{config}->{asymmetric_keylength} = 0
        if (not $self->{channel}->{config}->{asymmetric_keylength});
    $self->{channel}->{config}->{symmetric_keylength}  = 0
        if (not $self->{channel}->{config}->{symmetric_keylength});

    $self->debug ("        channel type ... $self->{channel}->{config}->{channel_type}");
    $self->debug ("        security protocol ... $self->{channel}->{config}->{security_protocol}");
    $self->debug ("        source ... $self->{channel}->{config}->{source}");
    $self->debug ("        asymmetric cipher ... $self->{channel}->{config}->{asymmetric_cipher}");
    $self->debug ("        asymmetric keylength ... $self->{channel}->{config}->{asymmetric_keylength}");
    $self->debug ("        symmetric cipher ... $self->{channel}->{config}->{symmetric_cipher}");
    $self->debug ("        asymmetric keylength ... $self->{channel}->{config}->{symmetric_keylength}");

    return 1;
}

sub loadLoginConfig
{
    my $self = shift;
    $self->debug ("loadLoginConfig: entering function");

    ## determine the used login mechanism

    $self->{ident}->{type} = $self->{cache}->get_xpath (
                                 FILENAME => $self->{configfile},
                                 XPATH    => 'access_control/login/type'
                                                       );
    if (not defined $self->{ident}->{type})
    {
        $self->setXMLerror (6271008, "Authentication verification");
        return undef;
    }

    $self->debug ("loadLoginConfig: leaving function successfully");
    return 1;
}


sub loadLDAPLoginConfig
{
    my $self = shift;
    $self->debug ("loadLDAPLoginConfig: entering function");

    ## get the configdata <ldapdata>...</ldapdata>
    $self->{ident}->{ldaphost} =
	$self->{cache}->get_xpath (
			FILENAME => $self->{configfile},
			XPATH    => 'access_control/login/ldapdata/host'
				   );
    $self->debug ("        LDAP host: $self->{ident}->{ldaphost}");

    $self->{ident}->{ldapport} = 
	$self->{cache}->get_xpath (
			FILENAME => $self->{configfile},
			XPATH    => 'access_control/login/ldapdata/port'
				   );
    $self->debug ("        LDAP port: $self->{ident}->{ldapport}");

    $self->{ident}->{ldapbase} =
	$self->{cache}->get_xpath (
			 FILENAME => $self->{configfile},
                         XPATH    => 'access_control/login/ldapdata/base'
				   );
    $self->debug ("        LDAP base: $self->{ident}->{ldapbase}");
    
    $self->{ident}->{ldapversion} =
	$self->{cache}->get_xpath (
			   FILENAME => $self->{configfile},
			   XPATH    => 'access_control/login/ldapdata/version'
				   );
    if (! $self->{ident}->{ldapversion} ) { 
	$self->{ident}->{ldapversion} = 3;
    }
    $self->debug ("        LDAP base: $self->{ident}->{ldapversion}");
    
    $self->{ident}->{ldapbinddn} =
	$self->{cache}->get_xpath (
			  FILENAME => $self->{configfile},
			  XPATH    => 'access_control/login/ldapdata/binddn'
				   );
    $self->debug ("        LDAP binddn: $self->{ident}->{ldapbinddn}");

    $self->{ident}->{ldapbindpw} =
	$self->{cache}->get_xpath (
			 FILENAME => $self->{configfile},
                         XPATH    => 'access_control/login/ldapdata/bindpw'
				   );
    $self->debug ("        LDAP bindpw: XXXXXXXX");


    my $ldapusetls =
	$self->{cache}->get_xpath (
			 FILENAME => $self->{configfile},
			 XPATH    => 'access_control/login/ldapdata/usetls'
				   );
    $self->debug ("        LDAP use TLS: |$ldapusetls|");	
		
    $self->{ident}->{ldapcacertpath} = 
		    $self->{cache}->get_xpath (
			 FILENAME => $self->{configfile},
                         XPATH    => 'access_control/login/ldapdata/cacertpath'
					       );
    $self->debug ("        CA Cert path: |$self->{ident}->{ldapcacertpath}|");
		
	       
#    my $is_tls=undef;

    if ( lc($ldapusetls) eq "yes" || lc($ldapusetls) eq "starttls" ) {
	## Access to the ca certificate is prerequisite for TLS:
	if ( not $self->{ident}->{ldapcacertpath} ) {
	    $self->setError (6273150,
			     $self->{gettext} ("LDAP Login config error: you need to specify cacertpath for TLS."));
	    return undef;
	}
	if ( lc($ldapusetls) eq "yes" ) {
	    $self->{ident}->{is_tls}=1;
	} else {
	    $self->{ident}->{is_tls}=2;
	} 
    } else {
	$self->{ident}->{is_tls}=0;
    }
		
    $self->debug ("        LDAP IS_TLS: |$self->{ident}->{is_tls}|");

    $self->{ident}->{ldapsearchattr} =
	$self->{cache}->get_xpath (
			FILENAME => $self->{configfile},
			XPATH    => 'access_control/login/ldapdata/searchattr'
				   );
    $self->debug ("        LDAP search attrib: " .
		  $self->{ident}->{ldapsearchattr});

    $self->{ident}->{ldapsearchvalueprefix} =
	$self->{cache}->get_xpath (
  		  FILENAME => $self->{configfile},
                  XPATH    => 'access_control/login/ldapdata/searchvalueprefix'
				   );
    $self->debug ("        LDAP search value prefix: " . 
		  $self->{ident}->{ldapsearchvalueprefix});

    $self->{ident}->{ldapauthmethattr} = 
	$self->{cache}->get_xpath (
		   FILENAME => $self->{configfile},
		   XPATH    => 'access_control/login/ldapdata/ldapauthmethattr'
				   );
    $self->debug ("        LDAP authmeth attribute: " . 
		  $self->{ident}->{ldapauthmethattr});
								  

    $self->{ident}->{ldapdefaultauthmethod} = $self->{cache}->get_xpath (
		  FILENAME => $self->{configfile},
                  XPATH    => 'access_control/login/ldapdata/ldapdefaultauthmeth'
									    );
    $self->debug ("        LDAP defaultauthmeth: " .
		  $self->{ident}->{ldapdefaultauthmethod} );

    $self->{ident}->{ldappwattr} =
	$self->{cache}->get_xpath (
		      FILENAME => $self->{configfile},
		      XPATH    => 'access_control/login/ldapdata/ldappwattr'
				   );
    $self->debug ("        LDAP PW attr: $self->{ident}->{ldappwattr}");

    $self->{ident}->{ldappwattrhash} =
	$self->{cache}->get_xpath (
		      FILENAME => $self->{configfile},
                      XPATH    => 'access_control/login/ldapdata/ldappwattrhash'
				   );
    $self->debug ("        LDAP PW attr hash: $self->{ident}->{ldappwattrhash}");

    $self->{ident}->{ldaproleattr} =
	$self->{cache}->get_xpath (
			FILENAME => $self->{configfile},
                        XPATH    => 'access_control/login/passwd/roleattribute'
				   );
    $self->debug ("        LDAP role attribute: $self->{ident}->{ldaproleattr}");
    
    my $ii = 0;   # constant
    

    $self->{ident}->{ldaprole_count} = 
	$self->{cache}->get_xpath_count (
		FILENAME => $self->{configfile},
                XPATH    => [ 'access_control/login/passwd/rolemapping' ]);

    $self->debug ("        number of roles defined: ".
		  $self->{ident}->{ldaprole_count});



    if (not defined $self->{ident}->{type})
    {
        $self->setXMLerror (6271008, "Authentication verification");
        return undef;
    }

    $self->debug ("loadLoginConfig: leaving function successfully");
    return 1;
}



sub loadModuleID {

    my $self = shift;
    $self->{acl}->{module_id} = $self->{cache}->get_xpath (
                                    FILENAME => $self->{configfile},
                                    XPATH    => 'access_control/acl_config/module_id');
    if (not defined $self->{acl}->{module_id}) {
        $self->setXMLerror (6292009, "Module ID loading");
        return undef;
    } elsif (not $self->{acl}->{module_id} and
             $self->{acl}->{module_id} != 0) {
        $self->setError (6292010,
            $self->{gettext} ("The module ID is empty (__FILENAME__: access_control/acl_config/module_id).",
                              "__FILENAME__", $self->{configfile}));
        return undef;
    }

    if ($self->{acl}->{module_id} != 0 and ( not $self->{acl}->{module_id} or $self->{acl}->{module_id} < 0)) {
        return undef;
    }

    return 1;
}

sub loadRoleConfig
{
    my $self = shift;
    $self->debug ("loadRoleConfig: entering function");

    ## should we map the user to a role?
    $self->{acl}->{map_role} = $self->{cache}->get_xpath (
                                    FILENAME => $self->{configfile},
                                    XPATH    => 'access_control/acl_config/map_role');
    if (not $self->{acl}->{map_role}) {
        $self->setError (6293005,
            $self->{gettext} ("The xml path to the access control is missing (__FILENAME__: access_control/acl_config/map_role).",
                              "__FILENAME__", $self->{configfile}));
        return undef;
    }

    $self->debug ("loadRoleConfig: leaving function successfully");
    return 1;
}

sub loadOperationConfig
{
    my $self = shift;
    $self->debug ("loadOperationConfig: entering function");

    ## should we map the command to an operation
    $self->{acl}->{map_operation} = $self->{cache}->get_xpath (
                                    FILENAME => $self->{configfile},
                                    XPATH    => 'access_control/acl_config/map_operation');
    if (not $self->{acl}->{map_operation}) {
        $self->setError (6294005,
            $self->{gettext} ("The xml path to the access control is missing (__FILENAME__: access_control/acl_config/map_operation).",
                              "__FILENAME__", $self->{configfile}));
        return undef;
    }

    $self->debug ("loadOperationConfig: leaving function successfully");
    return 1;
}

sub loadACL {

    my $self = shift;

    ## check ACL for activation

    $self->{acl}->{mode} = "on";
    my $acl_mode = $self->{cache}->get_xpath (
                       FILENAME => $self->{configfile},
                       XPATH    => 'access_control/acl_config/acl');
    if (not defined $acl_mode)
    {
        $self->setXMLerror (6290004, "ACL mode determination");
        return undef;
    } elsif (not $acl_mode) {
        $self->setError (6290005,
            $self->{gettext} ("The xml path to the access control is missing (__FILENAME__: access_control/acl_config/acl).",
                              "__FILENAME__", $self->{configfile}));
        return undef;
    } elsif ( $acl_mode =~ /^no$/i) {
        $self->{journal}->{acl}->{mode} = "off";
        return 1;
    } elsif ( $acl_mode !~ /^yes$/i) {
        $self->setError (6290010,
            $self->{gettext} ("The mode of the access control list (ACL) cannot be determined."));
        return undef;
    } ## else is an activated ACL
    $self->{journal}->{acl} = $self->{acl};
    $self->debug ("    ACL found");

    ## load name of the ACL file

    $self->{acl_file}  = $self->{cache}->get_xpath (
                        FILENAME => $self->{configfile},
                        XPATH    => 'access_control/acl_config/list');
    if (not defined $self->{acl_file})
    {
        $self->xsetXMLerror (6291004, "Loading ACL");
        return undef;
    } elsif (not $self->{acl_file}) {
        $self->setError (6291005,
            $self->{gettext} ("The xml path to the access control is missing (__FILENAME__: access_control/acl_config/list).",
                              "__FILENAME__", $self->{configfile}));
        return undef;
    }

    ## load the complete list

    my $all = $self->{cache}->get_xpath_count (
                   FILENAME => $self->{acl_file},
                   XPATH    => 'access_control/acl/permission');

    ## do not accept an empty list

    if (not defined $all) {
        $self->setXMLerror (6296011, "ACL loading");
        return undef;
    }
    if (not $all) {
        $self->setError (6296010,
            $self->{gettext} ("The access control list is empty."));
        return undef;
    }

    my $ok = 0;
    ## load each entry
    for (my $i=0; $i<$all; $i++) {
        $self->{acl}->{list}->[$i]->{module} = $self->{cache}->get_xpath (
                         FILENAME => $self->{acl_file},
                         XPATH    => [ 'access_control/acl/permission', 'module' ],
                         COUNTER  => [ $i, 0 ]);
        $self->{acl}->{list}->[$i]->{role} = $self->{cache}->get_xpath (
                         FILENAME => $self->{acl_file},
                         XPATH    => [ 'access_control/acl/permission', 'role' ],
                         COUNTER  => [ $i, 0 ]);
        $self->{acl}->{list}->[$i]->{operation} = $self->{cache}->get_xpath (
                         FILENAME => $self->{acl_file},
                         XPATH    => [ 'access_control/acl/permission', 'operation' ],
                         COUNTER  => [ $i, 0 ]);
        $self->{acl}->{list}->[$i]->{owner} = $self->{cache}->get_xpath (
                         FILENAME => $self->{acl_file},
                         XPATH    => [ 'access_control/acl/permission', 'owner' ],
                         COUNTER  => [ $i, 0 ]);
    }
    $self->{acl}->{length} = $all;

    return 1;
}

#############################################################################
##                         check the channel                               ##
#############################################################################

sub checkChannel {

    my $self = shift;

    $self->debug ("Checking the channel ...");

    $self->debug ("    loading channel data ... ");

    $self->{channel}->{type}                 = "";
    $self->{channel}->{security_protocol}    = "";
    $self->{channel}->{source}               = "";
    $self->{channel}->{asymmetric_cipher}    = "";
    $self->{channel}->{asymmetric_keylength} = 0;
    $self->{channel}->{symmetric_cipher}     = "";
    $self->{channel}->{symmetric_keylength}  = 0;
    $self->{journal}->{channel} = $self->{channel};

    ## looks senseless but good for the future
    if ($self->{cgi}->param ("OPENCA_AC_CHANNEL_SERVER_SOFTWARE") =~ /mod_ssl/)
    {
        $self->{channel}->{type} = "mod_ssl";
    } elsif ($self->{cgi}->param ("OPENCA_AC_CHANNEL_SERVER_SOFTWARE") =~ /apache_ssl/) {
        $self->{channel}->{type} = "apache_ssl";
    } else {
	# Default to mod_ssl (is it safe ?)
        $self->{channel}->{type} = "mod_ssl";
    }

    $self->debug ("        channel type ... ".$self->{channel}->{type});

    if ($self->{channel}->{type} =~ /mod_ssl/) {
        if ($self->{cgi}->param ("OPENCA_AC_CHANNEL_HTTPS_MODE") =~ /^on$/i) {
            $self->{channel}->{security_protocol} = "ssl";
            if ($self->{channel}->{security_protocol} eq "ssl") {
                $self->{channel}->{symmetric_cipher}     =
                    $self->{cgi}->param ("OPENCA_AC_CHANNEL_SSL_CIPHER");
                $self->{channel}->{symmetric_keylength}  =
                    $self->{cgi}->param ("OPENCA_AC_CHANNEL_SSL_CIPHER_USEKEYSIZE");
            }
        } else {
            $self->{channel}->{security_protocol} = "http";
        }
        $self->{channel}->{source} =
            $self->{cgi}->param ("OPENCA_AC_CHANNEL_REMOTE_ADDRESS");
    } elsif ($self->{channel}->{type} =~ /apache_ssl/) {
        if ($self->{cgi}->param ("OPENCA_AC_CHANNEL_HTTPS_MODE") =~ /^on$/i) {
            $self->{channel}->{security_protocol} = "ssl";
            if ($self->{channel}->{security_protocol} eq "ssl") {
                $self->{channel}->{symmetric_cipher}     =
                    $self->{cgi}->param ("OPENCA_AC_CHANNEL_SSL_CIPHER");
                $self->{channel}->{symmetric_keylength}  =
                    $self->{cgi}->param ("OPENCA_AC_CHANNEL_HTTPS_SECRETKEYSIZE");
            }
        } else {
            $self->{channel}->{security_protocol} = "http";
        }
        $self->{channel}->{source} =
            $self->{cgi}->param ("OPENCA_AC_CHANNEL_REMOTE_ADDRESS");
    }

    $self->debug ("    check channel data ...");

    if ($self->{channel}->{type} =~ /$self->{channel}->{config}->{channel_type}/) {
        $self->debug ("        channel type ... ok");
    } else {
        $self->setError (6251023,
            $self->{gettext} ("Aborting connection - you are using a wrong channel (__CHANNEL__).",
                              "__CHANNEL__", $self->{channel}->{type}));
        return undef;
    }
    if ($self->{channel}->{security_protocol} =~ /$self->{channel}->{config}->{security_protocol}/) {
        $self->debug ("        security protocol ... ok");
    } else {
        $self->setError (6251026,
            $self->{gettext} ("Aborting connection - you are using a wrong security protocol (__PROTOCOL__).",
                              "__PROTOCOL__", $self->{channel}->{security_protocol}));
        return undef;
    }
    if ($self->{channel}->{source} =~ /$self->{channel}->{config}->{source}/) {
        $self->debug ("        source ... ok");
    } else {
        $self->setError (6251029,
            $self->{gettext} ("Aborting connection - you are using the wrong computer (__SOURCE__).",
                              "__SOURCE__", $self->{channel}->{source}));
        return undef;
    }
    if ($self->{channel}->{asymmetric_cipher} =~ /$self->{channel}->{config}->{asymmetric_cipher}/) {
        $self->debug ("        asymmetric cipher ... ok");
    } else {
        $self->setError (6251033,
            $self->{gettext} ("Aborting connection - you are using a wrong asymmetric cipher (__CIPHER__).",
                              "__CIPHER__", $self->{channel}->{asymmetric_cipher}));
        return undef;
    }
    if ($self->{channel}->{asymmetric_keylength} >= $self->{channel}->{config}->{asymmetric_keylength}) {
        $self->debug ("        asymmetric keylength ... ok");
    } else {
        $self->setError (6251036,
            $self->{gettext} ("Aborting connection - you are using a too short asymmetric keylength (__LENGTH__).",
                              "__LENGTH__", $self->{channel}->{asymmetric_keylength}));
        return undef;
    }
    if ($self->{channel}->{symmetric_cipher} =~ /$self->{channel}->{config}->{symmetric_cipher}/) {
        $self->debug ("        symmetric cipher ... ok");
    } else {
        $self->setError (6251039,
            $self->{gettext} ("Aborting connection - you are using a wrong symmetric cipher (__CIPHER__).",
                              "__CIPHER__", $self->{channel}->{symmetric_cipher}));
        return undef;
    }
    if ($self->{channel}->{symmetric_keylength} >= $self->{channel}->{config}->{symmetric_keylength}) {
        $self->debug ("        symmetric keylength ... ok");
    } else {
        $self->setError (6251043,
            $self->{gettext} ("Aborting connection - you are using a too short symmetric keylength (__LENGTH__).",
                              "__LENGTH__", $self->{channel}->{symmetric_keylength}));
        return undef;
    }

    $self->debug ("Channel is ok");
    return 1;

}

########################################################################
##                          identify the user                         ##
########################################################################

sub checkIdent {

    my $self = shift;

    $self->debug ("Starting authentication ... ");

    $self->debug ("    channel type ... ".$self->{channel}->{type});

    ## FIXME
    ## we cannot check the channel if an independent backend server is in use
    ## if ($self->{channel}->{type} eq "mod_ssl") {
    ##     ##
    ## } else {
    ##     $self->setError (6271013, "You use an unsupported channel (".$self->{channel}->{type}.").");
    ##     return undef;
    ## }

    my @not_vulnerable_cmds = 
    		qw( genMenu serverInfo getStaticPage scepGetCACert 
			scepPKIOperation viewCert verifyPIN getParams getcert);
    my @pub_vulnerable_cmds = 
    		qw( authenticated_csr advanced_csr basic_csr revoke_req );

    if (not $self->getSession ()) {
        if (not $self->login ()) {
		$self->setError( 740201, "No login" );
		$self->debug("DEBUG => 740201");
        	return undef;
        } else {
            my $h = $self->{session}->start();
            ## set the correct values after a successful login
            $self->{session}->setParam ('name', $self->{ident}->{name});
            $self->{session}->setParam ('role', $self->{ident}->{role});
            $self->{session}->setParam ('entrydn', $self->{ident}->{entrydn});
            $self->{session}->setParam ('valid', '1');
            $self->{journal}->{login}->{name} = $self->{ident}->{name};
            $self->{journal}->{login}->{role} = $self->{ident}->{role};
            $self->{journal}->{session_id}    = $self->{session}->getID();
            $self->{journal}->{session_type}  = "cookie";
            if ((defined $self->{cgi}->param('cmd')) &&
                (! grep { $_ eq $self->{cgi}->param('cmd')} @not_vulnerable_cmds)) {
                # only the above commands should be called after a login
		# $self->setError( 7402011, "Only (@not_vulnerable_cmds) " .
		# 	"should be called after a login - $_ :: " . 
		# 		$self->{cgi}->param('cmd') . " )");
		$self->setError( 7402011, "Because your session changed, there ".
			"might be possible security risks. Please start a new " .
			"session to continue.");
                return undef;
            }
            return $h;
        }
    } else {
	if ($self->{cgi}->param ('cmd') eq 'logout')
        {
            $self->{cgi}->delete ('cmd');
            $self->stopSession;
            return $self->checkIdent;
        }

        # XSRF checks
        my $potentially_vulnerable = 0;

        if (defined $self->{cgi}->param('cmd')) {
            $potentially_vulnerable = 1;
        };

        if (grep {$_ eq $self->{cgi}->param('cmd')} @not_vulnerable_cmds) {
            $potentially_vulnerable = 0;
        };

	if ($self->{cgi}->param('OPENCA_AC_INTERFACE') =~ /PUBLIC/i ) {
		if (grep {$_ eq $self->{cgi}->param('cmd')} @pub_vulnerable_cmds) {
			$potentially_vulnerable = 1;
		} else {
			$potentially_vulnerable = 0;
		}
	}

        if ($potentially_vulnerable &&
            ($self->{cgi}->param('xsrf_protection_token')
                		ne sha1_hex($self->{session}->getID()))) {
            # potential XSRF attack
            $self->debug('Potential XSRF attack');
            $self->debug('XSRF token: ' .  
	    			$self->{cgi}->param('xsrf_protection_token'));
            $self->debug('SHA1 hash of session ID: ' .  
	    				sha1_hex($self->{session}->getID()));
	    $self->setError( 740202, $self->{gettext} ("[ Security Protection ] ".
			"Because your session changed, there ".
			"might be security problems with the connection with " .
			"your computer. Please start a new session to continue." ));

            return undef;
        }
        return $self->{session}->update();
    }

    ## unexpected error because never reached
    return undef;
}

sub getSession {
    my $self = shift;
    $self->debug ("    Try to get a session ...");

    return undef if (not $self->{session}->load());

    ## name can be a false value
    ## valid is a protection against expired sessions
    $self->{ident}->{name}          = $self->{session}->getParam("name");
    $self->{ident}->{role}          = $self->{session}->getParam("role");
    $self->{ident}->{entrydn}       = $self->{session}->getParam("entrydn");
    $self->{ident}->{valid}         = $self->{session}->getParam("valid");
    $self->{ident}->{prepare_ident} = $self->{session}->getParam("prepare_ident");

    if (not $self->{ident}->{valid}) {
        $self->{session}->stop();
        return undef;
    }
    $self->{journal}->{login}->{name} = $self->{ident}->{name};
    $self->{journal}->{login}->{role} = $self->{ident}->{role};
    $self->{journal}->{login}->{prepare_ident} = "TRUE";
    $self->{journal}->{session_id}    = $self->{session}->getID();
    $self->{journal}->{session_type}  = "cookie";

    return undef if ($self->{ident}->{prepare_ident});
    delete $self->{journal}->{login}->{prepare_ident};

    return 1;
}

sub login {
    my $self = shift;
    $self->debug ("    Try to login .....");

    if ($self->{ident}->{type} =~ /^none$/i) {
        $self->debug ("        type ... none");
        $self->debug ("        identification disabled");
        $self->{journal}->{login}->{type} = "none";
        return 1;
    } elsif ($self->{ident}->{type} =~ /^passwd$/i) {
        $self->debug ("        type ..... passwd");
        $self->{journal}->{login}->{type} = "passwd";

	my $database =
	    $self->{cache}->get_xpath (
				       FILENAME => $self->{configfile},
				       XPATH    => 'access_control/login/database'
				       );
	$self->debug ("    database ..... $database");

        if ($self->{cgi}->param ('login')) {
            $self->debug ("        credentials ... present");
            $self->{ident}->{name} = $self->{cgi}->param ('login');
            $self->debug ("        name ... ".$self->{ident}->{name});


	    # external database source
            if ($database =~ /^externalcommand$/i) {
                $self->debug("        database ... externalcommand");

		my $password = $self->{cgi}->param ('passwd');

		# see security warning below (near $out=`$cmd`)
		my $cmd = 
		    $self->{cache}->get_xpath (
					       FILENAME => $self->{configfile},
					       XPATH    => 'access_control/login/command'
					       );
		
		$self->debug("        cmd: $cmd")
		    if (defined $cmd);
		
		# get environment settings
		$self->debug ("loading environment variable settings");

		my @clearenv;
		my $ii = 0;   # constant
		my $option_count = 
		    $self->{cache}->get_xpath_count (
						     FILENAME => $self->{configfile},
						     XPATH    => [ 'access_control/login/setenv', 'option' ],
						     COUNTER  => [ $ii ]);
		
		for (my $kk = 0; $kk < $option_count; $kk++)
		{
		    my $variable = 
			$self->{cache}->get_xpath (
						   FILENAME => $self->{configfile},
						   XPATH    => [ 'access_control/login/setenv', 'option', 'name' ],
						   COUNTER  => [ $ii, $kk, 0 ]);
		    $self->debug("setenv: option name: $variable");
		    
		    my $value = 
			$self->{cache}->get_xpath (
						   FILENAME => $self->{configfile},
						   XPATH    => [ 'access_control/login/setenv', 'option', 'value' ],
						   COUNTER  => [ $ii, $kk, 0 ]);
		    
		    $value =~ s/__USER__/$self->{ident}->{name}/g;

		    # we don't want to see expanded passwords in the log file,
		    # so we just replace the password after logging it
		    $self->debug("setenv: option value (expanded): $value");
		    $value =~ s/__PASSWD__/$password/g;

		    # set environment for executable
		    $ENV{$variable} = $value;
		    
		    # remember to purge environment
		    push (@clearenv, $variable);
		}
		
		$self->debug("execute: $cmd");

		# execute external program. this is safe, since cmd
		# is taken literally from the configuration.
		# NOTE: do not extend this code to allow login parameters
		# to be passed on the command line.
		# - the credentials may be visible in the OS process 
		#   environment
		# - worse yet, it is untrusted user input that might
		#   easily be used to execute arbitrary commands on the
		#   system.
		# SO DON'T EVEN THINK ABOUT IT!
		my $out = `$cmd`;
		map { undef $ENV{$_} } @clearenv; # clear environment

		$self->debug("command returned $?, STDOUT was: $out");
		
		if ($? != 0) {
		    $self->setError (6273166,
				     $self->{gettext} ("Login failed."));
		    return undef;
		}

#               Disabled for now, but may be used in the future
# 		if ($out =~ /^Role\s*=\s*(.*)/) {
# 		    $self->debug("external program returned role '$1'");
# 		    $self->{ident}->{role} = lc($1);
# 		}
	    }
	    ## LDAP database source (user/password stored in LDAP or AD server)        
            elsif ($database =~ /^ldap$/i) {
                $self->debug ("        database ... LDAP");

                $self->loadLDAPLoginConfig;
		## some more config stuff:
		my $ldapauthmeth_count = $self->{cache}->get_xpath_count (
                          FILENAME => $self->{configfile},
                          XPATH    => 'access_control/login/ldapdata/ldapauthmethmapping');

		my %methods;
		
		for (my $i=0; $i<$ldapauthmeth_count; $i++)
		{
		    my $condition = $self->{cache}->get_xpath (
			       FILENAME => $self->{configfile},
			       XPATH    => [ 'access_control/login/ldapdata/ldapauthmethmapping', 'ldapauthmethattrvalue' ],
			       COUNTER  => [ $i, 0 ]
							       );
		    
		    my $method = $self->{cache}->get_xpath (
	         	       FILENAME => $self->{configfile},
			       XPATH    => [ 'access_control/login/ldapdata/ldapauthmethmapping', 'ldapauthmeth' ],
			       COUNTER  => [ $i, 0 ]
							    );

		    $methods{$condition} = $method;
		}       

		## now start an LDAP connection
		my $bindmsg = undef;
		my $ldap = undef;

		if ( $self->{ident}->{is_tls} == 1 && ! $is_ldaps ) {
		    $self->debug("no ldaps installed, thus switching to start_tls");
		    $self->{ident}->{is_tls}=2;
		}

		if ( $self->{ident}->{is_tls} == 1) {  
		    $self->debug("    starting a SSL (ldaps) session on ".
				 "$self->{ident}->{ldaphost}:$self->{ident}->{ldapport} certpath: $self->{ident}->{ldapcacertpath}");
		    
		    $ldap = Net::LDAPS->new ($self->{ident}->{ldaphost},
			     port    => $self->{ident}->{ldapport},
			     async   => 0,
			     version => 3, 
			     capath => $self->{ident}->{ldapcacertpath}
					     );
		} else {
		    $ldap = Net::LDAP->new ($self->{ident}->{ldaphost},
			    port    => $self->{ident}->{ldapport},
			    async   => 0,
			    version => 3 
					    );
		}
		
		if (not $ldap)
		{
		    $self->setError(6273153, 
		     $self->{gettext}("LDAP Login: connect to server failed."));
		    return undef;
		}
		else
		{
		    $self->debug ("        LDAP connect successfull");
		    my $starttls_OID = "1.3.6.1.4.1.1466.20037";
		    my $is_rootdse = undef;
		    
		    if ($self->{ident}->{is_tls} == 2) {
			
			my $root_dse = $ldap->root_dse();
			
			if ($root_dse) {
			    my @namingContext = 
				$root_dse->get_value( 'namingContexts', 
				           asref => 0 );
			    $self->debug("        naming contexts are:");

			    foreach (0..$#namingContext) {
				$self->debug("             $namingContext[$_]");
			    }
			    $is_rootdse = 1;
			} else {
			    $self->debug("root_dse unsuccessfull");
			}
	

			if ( $is_rootdse && 
			     ! $root_dse->supported_extension ($starttls_OID)) {

			    $self->debug("Server does not support START_TLS");
			    $self->debug("Please reconfigure your LDAP ".
					 "Authentication settings");
			    self->setError(6273161, 
			          $self->{gettext}("LDAP Login: Server does not support TLS."));
			    
			    return undef;
			}
	
			$self->debug("        starting a Start_TLS session on $self->{ident}->{ldaphost}:$self->{ident}->{ldapport} certpath: $self->{ident}->{ldapcacertpath}");

			my $tlsmsg = $ldap->start_tls ( 
                                     verify =>'require',
				     capath => $self->{ident}->{ldapcacertpath} 
							);

			if ( $tlsmsg->is_error() ) {
			    $self->print_ldaperror("Start TLS", $tlsmsg);
			    $self->debug("        Possible reason: The directory in \"capath\" must contain certificates ");
			    $self->debug("            named using the hash value of the certificates\' subject names. ");
			    $self->debug("            To generate these names, use OpenSSL like this in Unix:");
			    $self->debug("            ln -s cacert.pem \`openssl x509 -hash -noout \< cacert.pem\`.0");
			    $self->setError(6273162, 
					    $self->{gettext}("LDAP Login: Start TLS did not succeed."));
			    return(undef);
			} else {
			    $self->debug("        starttls successful");
			}
			
		    }
    
    
		    ## now OpenCA authenticates itself by binding to the 
		    ## entry configured in ldapbinddn
		    my $bindmsg = $ldap->bind( $self->{ident}->{ldapbinddn}, 
					       'password' => $self->{ident}->{ldapbindpw} );
		    
		    if ($bindmsg->is_error())
		    {
			if ( $bindmsg->code() == 49 ) {
			    $self->debug("invalid ldap credentials\n");
			} else {  
			    $self->print_ldaperror("LDAP bind", $bindmsg);
			}
			$self->setError( 6273154, $self->{gettext}("OpenCA LDAP Authentication failed."));
			return undef;
		    }
		    
		    $self->debug("        LDAP Openca Login successfull");	  
		}
		
## now search for an entry with an ID-attribute containing 
## the value inputted by the user
		
		
		my $ldapsearchfilter = 
		    "($self->{ident}->{ldapsearchattr}=$self->{ident}->{ldapsearchvalueprefix}$self->{ident}->{name})";
		$self->debug("        search filter: $ldapsearchfilter");
		
		
		my $searchmesg = $ldap->search( 
				      base   => $self->{ident}->{ldapbase},
				      filter => $ldapsearchfilter
						);
		
		if ($searchmesg->is_error())
		{
		    $self->print_ldaperror("LDAP search", $searchmesg);
		    setError(6273154, $self->{gettext}("OpenCA LDAP Authentication failed."));
		    return undef;
		}
		

		my $entrycount = $searchmesg->count();
		
## no user found?
		if ( not $entrycount ) {
		    $self->setError(6273120, 
			     $self->{gettext}("LDAP Login: user not found."));
		    return undef;
}

## more than one user found?
		if ( $entrycount > 1 ) {
		    $self->setError(6273157, 
		     $self->{gettext}("LDAP Login: more than one user found."));
		    return undef;
		}

		## ok lets analyse the entry found:
                my $value = undef;
                my @rolevalues = undef;
                my @ldapauthmethattrvalues = undef;
                my @ldappwattrvalues = undef;
                my $rolevaluecount = 0;
                my $ldapauthmethattrvaluecount = 0;
                my $ldappwattrvaluecount = 0;

		my $entry = $searchmesg->entry ( 0 );
		$self->{ident}->{entrydn} = $entry->dn();

		$self->debug("analysing entry $self->{ident}->{entrydn}");

		foreach my $attr ( $entry->attributes ) {
		    foreach $value ( $entry->get_value( $attr ) ) { 
#			$self->debug("attr: |$attr| = $value");
			if ( lc($attr) eq lc($self->{ident}->{ldaproleattr}) ) {
#			    $self->debug ("Roleattribute = $value");
			    $rolevalues[$rolevaluecount] = $value;
			    $rolevaluecount ++;
			} elsif ( lc($attr) eq 
				  lc($self->{ident}->{ldapauthmethattr}) ) {
#			    $self->debug ("ldapauthmethattribute = $value");
			    $ldapauthmethattrvalues[$ldapauthmethattrvaluecount] = $value;
			    $ldapauthmethattrvaluecount ++;
			} elsif ( lc($attr) eq 
				  lc($self->{ident}->{ldappwattr}) ) {
#			    $self->debug ("ldappwattribute = $value");
			    $ldappwattrvalues[$ldappwattrvaluecount] = $value;
			    $ldappwattrvaluecount ++;
			}
		    } 
		}

		$self->debug("rolecount: $rolevaluecount; authmethcount: $ldapauthmethattrvaluecount; ldappwattrcount: $ldappwattrvaluecount");


		## lets see which auth method to use:
		my $is_found = 0;
		my $valuekey;
		my $ldapauthmeth = undef;
		for (my $ii = 0; $ii < $ldapauthmethattrvaluecount; $ii++) {
		    foreach $valuekey (keys %methods) {
			if ( $valuekey eq $ldapauthmethattrvalues[$ii] ) {
			    $is_found = 1;
			    $ldapauthmeth = $methods{$valuekey};
			    last;
			}
		    }
		    if ($is_found ) { last;}
		}
		    
		if ($is_found) {
		    $self->debug ("       Found auth meth");		    
		    if ($ldapauthmeth eq "pwattr" && not $ldappwattrvaluecount ) {
			# Error no value of ldap pw attribute 
			$self->debug ("Error pwattr method chosen without pw attr in entry");
			$self->setError (6273158,
				   $self->{gettext} ("LDAP Login: password attribute is missing in the entry."));
			return undef;
		    }
		} else {
		    $ldapauthmeth = $self->{ident}->{ldapdefaultauthmethod};
		}

		$self->debug("ldapauthmeth: $ldapauthmeth");
		
		## Method pwattr 
                ## (use a configurable password attribute for authentication)
		if ( $ldapauthmeth eq "pwattr" ) {
		    my $algorithm = undef;
		    my $digest = undef;
		    
		    my $ldapdigest = $ldappwattrvalues[0];
		    
		    $self->debug("ldapdigest : |$ldapdigest| ");
		    
		    ## create comparable value
		    $self->{ident}->{algorithm} = 
			lc ($self->{ident}->{ldappwattrhash});
		    
		    my $pw = $self->{cgi}->param ('passwd');
		    
		    ## compute the digest
		    if ($self->{ident}->{algorithm} =~ /^sha1$/i)
		    {
			use Digest::SHA1;
			my $digest = Digest::SHA1->new;
			$digest->add ($pw);
			$self->debug( "Digest: SHA1\n");
			$self->debug( "String: ".$pw."\n" );
			my $b64digest = $digest->b64digest;
			$self->debug( "SHA1:   ".$b64digest."\n");
			$self->{ident}->{digest} = $b64digest;
			
		    } elsif ($self->{ident}->{algorithm} =~ /^md5$/i) {
			use Digest::MD5;
			$digest = Digest::MD5->new;
			$digest->add($self->{cgi}->param ('passwd'));
			$self->{ident}->{digest} = $digest->b64digest;

		    } elsif ($self->{ident}->{algorithm} =~ /^crypt$/i) {
			$self->{ident}->{digest} = 
			    crypt ($self->{cgi}->param ('passwd'), $ldapdigest);
		    } elsif ($self->{ident}->{algorithm} =~ /^none$/i) {
			$self->{ident}->{digest} = $ldapdigest;
		    } else {
			$self->setError (6273151,
					 $self->{gettext} ("LDAP Login config error: unknown passphrasehashing algorithm."));
			return undef;
		    }               
		    
		    $self->debug ("        ident name ... ".$self->{ident}->{name});
		    $self->debug ("        ident algorithm ... ".$self->{ident}->{algorithm});
		    $self->debug ("        ident digest ... ".$self->{ident}->{digest});
		    
		    ## compare passphrases
		    
		    ## sometimes hash creators put the algorithm used in front of 
		    ## the value and a '=' at its end. We will strip that for 
                    ## comparision
		    if ( $ldapdigest =~ /^\{\w+\}(.+)=$/ ) {
			$ldapdigest = $1;
			$self->debug ("value contains {X}Y=");
		    }
		    $self->debug ("        comparing |".$self->{ident}->{digest}."| with |".$ldapdigest."|");

		    if ($self->{ident}->{digest} ne $ldapdigest) {
			$self->setError (6273155,
					 $self->{gettext} ("LDAP Login failed."));
			return undef;
		    }
		} elsif ( $ldapauthmeth eq "bind" ) {
		    ## do simple ldap bind for authentication 
                    my $passwd = $self->{cgi}->param ('passwd');
		    
		    my $bindmsg = $ldap->bind( $self->{ident}->{entrydn}, 
					       'password' => $passwd );
		    
		    if ($bindmsg->is_error())
		    {
			my $msg = $self->{gettext} ("LDAP-bind failed: __ERRVAL__",
						    "__ERRVAL__", $self->errval) ;
			if ( $bindmsg->code() == 49 ) {
			    $self->debug ("invalid ldap credentials in configuration");
			} else {   
			    $self->debug ("LDAP Login: Cannot bind to server.");
			    $self->debug ("bind error:     ". $bindmsg->error());
			    $self->debug ("bind servererr: ".$bindmsg->server_error());
			    $self->debug ("bind mesg code: ".$bindmsg->code());
			}
			$self->setError (6273155,
					 $self->{gettext} ("LDAP Login failed."));
			return undef;
		    }
    
		    $self->debug ("        LDAP Login successfull");

###		    $self->{ident}->{dn} = $entrydn;

		    my $unbindmesg = $ldap->unbind;
		    if (not $unbindmesg->is_error ) {
			$self->debug ("        ldap unbind success ");
		    }

		} else {

		    $self->debug ("unknown ldap auth meth $ldapauthmeth");
		    $self->setError (6273152,
				     $self->{gettext} ("LDAP Login config error: unknown authentication method."));
		    return undef;
		}
 
		## OK the user seems to be authenticated properly, let's see if we can
                ## map her to a role:
                my $found = 0;
                my $rolefound = undef;

		$self->debug ("looking for the role");

                for (my $kk = 0; $kk < $self->{ident}->{ldaprole_count}; $kk++)
                {
                    my $roleattributevalue =
                        $self->{cache}->get_xpath (
                               FILENAME => $self->{configfile},
                               XPATH    => [ 'access_control/login/passwd/rolemapping', 'roleattributevalue' ],
                               COUNTER  => [ $kk, 0 ]);
                    $self->debug(" role attribute value: $roleattributevalue");

		    for (my $ii =0; $ii < $rolevaluecount; $ii++) {
                        if ( $roleattributevalue eq $rolevalues[$ii] ) {
			    $rolefound = 
				$self->{cache}->get_xpath (
				   FILENAME => $self->{configfile},
                                   XPATH    => [ 'access_control/login/passwd/rolemapping', 'role' ],
				   COUNTER  => [ $kk, 0 ]);
			    $found=1;
			    last;
			}
		    }
		    if ($found) { last; }
		}

		if ( not $found ) {
		    $self->debug ("no role found for user.");
		    $self->setError (6273159,
			     $self->{gettext} ("LDAP Login: no role found for user."));
		    return undef;
		} else {
		    $self->debug ("    found role: $rolefound ");
		    $self->{ident}->{role}= lc($rolefound);
		}

		## Everything is done for now

		$self->debug("end of LDAP Auth Module");
	    }
	    # internal database source (user/password stored in XML file)
            elsif ($database =~ /^internal$/i) {
                $self->debug ("        database ... internal");

                my $user = undef;
                my $name = undef;
                my $algorithm = undef;
                my $digest = undef;
                my $role   = undef;

                ## scan for login
                my $user_count = $self->{cache}->get_xpath_count (
                                FILENAME => $self->{configfile},
                                XPATH    => 'access_control/login/passwd/user');
                for (my $i=0; $i<$user_count; $i++)
                {
                    $name = $self->{cache}->get_xpath (
                                FILENAME => $self->{configfile},
                                XPATH    => [ 'access_control/login/passwd/user', 'name' ],
                                COUNTER  => [ $i, 0 ]);
                    $self->debug ("        scanned user ... ".$name);
                    next if ($name ne $self->{ident}->{name});
                    $self->debug ("        scanned user matchs searched user");
                    $user = $i;
                    last;
                }

                if (not defined $user or
                    ($name ne $self->{ident}->{name}))
                {
                    $self->setError (6273120,
                        $self->{gettext} ("Login failed."));
                    return undef;
                }

                $digest = $self->{cache}->get_xpath (
                            FILENAME => $self->{configfile},
                            XPATH    => [ 'access_control/login/passwd/user', 'digest' ],
                            COUNTER  => [ $user, 0 ]);
                $algorithm = $self->{cache}->get_xpath (
                            FILENAME => $self->{configfile},
                            XPATH    => [ 'access_control/login/passwd/user', 'algorithm' ],
                            COUNTER  => [ $user, 0 ]);
                $role = $self->{cache}->get_xpath (
                            FILENAME => $self->{configfile},
                            XPATH    => [ 'access_control/login/passwd/user', 'role' ],
                            COUNTER  => [ $user, 0 ]);

                ## create comparable value
                $self->{ident}->{algorithm} = lc ($algorithm);
                $self->{ident}->{role}      = lc ($role);
                if ($self->{ident}->{algorithm} =~ /^sha1$/i)
                {
                    use Digest::SHA1;
                    my $digest = Digest::SHA1->new;
                    $digest->add($self->{cgi}->param ('passwd'));
                    $self->{ident}->{digest} = $digest->b64digest;
                } elsif ($self->{ident}->{algorithm} =~ /^md5$/i) {
                    use Digest::MD5;
                    my $digest = Digest::MD5->new;
                    $digest->add($self->{cgi}->param ('passwd'));
                    $self->{ident}->{digest} = $digest->b64digest;
                } elsif ($self->{ident}->{algorithm} =~ /^crypt$/i) {
                    $self->{ident}->{digest} = crypt ($self->{cgi}->param ('passwd'),
                                                      $digest);
                } else {
                    $self->setError (6273130,
                        $self->{gettext} ("An unknown algorithm was specified for the passphrasehashing in the configuration!"));
                    return undef;
                }

                $self->debug ("        ident name ... ".$self->{ident}->{name});
                $self->debug ("        ident algorithm ... ".$self->{ident}->{algorithm});
                $self->debug ("        ident digest ... ".$self->{ident}->{digest});
                $self->debug ("        ident role ... ".$self->{ident}->{role});
                $self->{journal}->{login}->{name} = $self->{ident}->{name};

                ## compare passphrases
                if ($self->{ident}->{digest} ne $digest) {
                    $self->setError (6273166,
                        $self->{gettext} ("Login failed."));
                    return undef;
                }

            } elsif (not defined $self->{cache}->get_xpath (
                                     FILENAME => $self->{configfile},
                                     XPATH    => 'access_control/login/database'))
            {
                $self->setXMLerror (6273170, "Login database determination");
                return undef;
            } else {
                $self->setError (6273180,
                    $self->{gettext} ("An unknown database type was specified in the configuration!"));
                return undef;
            }
        } else {

            my ($hidden_list, $info_list, $cmd_panel) = (undef, undef, undef);

	    # Frame Managing Hack
            if( $self->{cgi}->param('redir') eq "" ) {
                # Let us see if this hack brings the login screen
                # on the principal frame - it is an hell of a hack!
		# I hope it work with most browsers!
                my $target = $self->{cgi}->url(-full=>0, -relative=>1);
                $target .= "?redir=1";
                ## bugfix for server
                $target = "?redir=1";
                print "Content-type: text/html\n\n";
                print $self->{cgi}->start_html( -onLoad=>"top.location.href='$target'" ) . $self->{cgi}->end_html() . "\n\n";
                exit 0;
            }
                                                                                
            $hidden_list->{"cmd"}  = "getStaticPage";
            $hidden_list->{"name"} = "index";

            $cmd_panel->[0] = '<input type="submit" value="'.
                              $self->{gettext}('OK').'">';
            $cmd_panel->[1] = '<input type="reset" value="'.
                              $self->{gettext}('Reset').'">';
	    my $gui_name = undef;

## new code outside of the ldap login module: 
	    my $loginheadline =
		$self->{cache}->get_xpath (
			  FILENAME => $self->{configfile},
			  XPATH    => 'access_control/login/loginheadline'
                                               );
	    my $loginprompt =
		$self->{cache}->get_xpath (
			  FILENAME => $self->{configfile},
			  XPATH    => 'access_control/login/loginprompt'
                                               );
	    if ($loginheadline) {
		$gui_name = $loginheadline;
	    } else {
		$gui_name = $self->{gettext}('Login to OpenCA');
	    }

	    if ($loginprompt) {
		$info_list->{BODY}->[0]->[0] = $loginprompt;
	    } else {
		$info_list->{BODY}->[0]->[0] = $self->{gettext}('Login');
	    }
## end of new code
            $info_list->{BODY}->[0]->[1] = '<input type="text" name="login" value=""';
            $info_list->{BODY}->[1]->[0] = $self->{gettext}('Password');
            $info_list->{BODY}->[1]->[1] = '<input type="password" name="passwd" value=""';

            $self->{gui}->libSendReply (
#                                  "NAME" => $self->{gettext}('Login to OpenCA'),
                                  "NAME" => $gui_name,
                                  "HIDDEN_LIST" => $hidden_list,
                                  "INFO_LIST"   => $info_list,
                                  "CMD_PANEL"   => $cmd_panel,
				  "TARGET"	=> "_top",
				  "MENU"	=> 0
                                 );
            exit (0);
        }
    } elsif ($self->{ident}->{type} =~ /^x509$/i) {
        $self->debug ("        type ... x509");
        $self->{journal}->{login}->{type} = "x509";

        use OpenCA::OpenSSL;
        use OpenCA::PKCS7;

        if ($self->{cgi}->param ('signature') and $self->{session}) {
            $self->debug ("        signature ... present");

            ## starting verification of the signature

            my $challenge = $self->{session}->getParam( 'challenge' );
            my $signature = $self->{cgi}->param( 'signature' );

            $signature =~ s/\n*$//;

            my $h;
            if ($signature !~ /^\s*$/) {
                $h .= "-----BEGIN PKCS7-----\n";
                $h .= "$signature\n";
                $h .= "-----END PKCS7-----\n";
                $signature = $h;
            }

            ## Build a new PKCS7 object
            my $sig = new OpenCA::PKCS7( SHELL     => $self->{cryptoShell},
                                         GETTEXT   => $self->{gettext},
                                         SIGNATURE => $signature,
                                         DATA      => $challenge,
                                         CA_DIR    => $self->{cache}->get_xpath (
                                                          FILENAME => $self->{configfile},
                                                          XPATH    => 'access_control/login/chain'
                                                                                ));

            if (not $sig) {
                $self->{session}->stop();
                $self->setError (6273250,
                    $self->{gettext} ("Cannot build PKCS#7-object from extracted signature! OpenCA::PKCS7 returns errorcode __ERRNO__. (__ERRVAL__)",
                                      "__ERRNO__", $OpenCA::PKCS7::errno,
                                      "__ERRVAL__", $OpenCA::PKCS7::errval));
                return undef;
            }

            if( $sig->status() != 0 ) {
                $self->{session}->stop();
                $self->setError (6273260, 
                    $self->{gettext} ("The PKCS#7-object signals an error. The signature is not valid. PKCS#7-Error __ERRNO__: __ERRVAL__",
                                      "__ERRNO__", $OpenCA::PKCS7::errno,
                                      "__ERRVAL__", $OpenCA::PKCS7::errval));
                return undef;
            }

            ## // now the signature is correctly verified with the CA's own certchain
            ## // the certificate's serial is uniqe in PKI
            $self->{ident}->{name} = $sig->getSigner()->{SERIAL};
            $self->{journal}->{login}->{name} = $self->{ident}->{name};

        } else {

            ## start a new session
            $self->{session}->start();
            $self->{session}->setParam ('name', '');
            $self->{session}->setParam ('valid', '1');
            $self->{session}->setParam ('prepare_ident', '1');
            $self->{journal}->{login}->{prepare_ident} = "TRUE";
            $self->{session}->setParam ('challenge', $self->{session}->getID());

            my ($hidden_list, $info_list, $cmd_panel) = (undef, undef, undef);

            $hidden_list->{"cmd"}       = "getStaticPage";
            $hidden_list->{"name"}      = "index";
            $hidden_list->{"signature"} = "";
            $hidden_list->{"text"}      = $self->{session}->getID();

            $cmd_panel->[0] = '<input TYPE="Button" Name="Submit" Value="'.
                              $self->{gettext}('Sign and Login').
                              '" onClick="signForm( this.form, window)">';

            $info_list->{BODY}->[0]->[0] = $self->{gettext}('Challenge');
            $info_list->{BODY}->[0]->[1] = $self->{session}->getID();

            $self->{gui}->libSendReply (
                                  "NAME"        => $self->{gettext}('Login to OpenCA'),
                                  "EXPLANATION" => $self->{gettext}('Please sign the challenge'),
                                  "SIGN_FORM"   => 1,
                                  "HIDDEN_LIST" => $hidden_list,
                                  "INFO_LIST"   => $info_list,
                                  "CMD_PANEL"   => $cmd_panel,
				  "MENU"	=> 0
                                 );
            exit (0);
        }
    } else {
        $self->setError (6273966,
            $self->{gettext} ("An unknown login type was specified in the configuration!"));
        return undef;
    }
    $self->debug ("    Logged in ...");
    return 1;
}


sub mybind {
    my $self = shift;
    my ( $logtext, $ldapbinddn, $ldapbindpw, $ldap ) = @_;

    my $bindmsg = $ldap->bind( $ldapbinddn, 
			       'password' => $ldapbindpw );
    
    if ($bindmsg->is_error())
    {
	my $msg = $self->{gettext} ("LDAP-bind failed: __ERRVAL__",
				    "__ERRVAL__", $self->errval) ;
	if ( $bindmsg->code() == 49 ) {
	    $self->debug ("invalid ldap credentials in configuration");
	} else {   
	    $self->debug ("$logtext: Cannot bind to server.");
	    $self->debug ("bind error:     ". $bindmsg->error());
	    $self->debug ("bind servererr: ".$bindmsg->server_error());
	    $self->debug ("bind mesg code: ".$bindmsg->code());
	}
	$self->setError (6273166,
			 $self->{gettext} ("LDAP Login failed."));
#	$self->setError (6273166,
#			 "$logtext fehlgeschlagen: Konfigurationsfehler");
	return undef;
    }
    
    $self->debug ("        $logtext successfull");
    
}





sub stopSession {
    my $self = shift;
    $self->debug ("    Remove session ...");

    $self->{CRYPTO}->stopSession;

    $self->{journal}->{session_id}   = $self->{session}->getID();
    $self->{journal}->{session_type} = "cookie";

    $self->{session}->stop();
    $self->{journal}->{message} .= $self->{gettext} ("Session killed (normal logout).")."\n";

    return 1;
}

##################################################################
##                 control the access rights                    ##
##################################################################

## we know the following files:
##
##     roles.xml
##     operations.xml
##     acl.xml
##     modules.xml
## //  every cmds has it's own configfile
##
## we can support the following twig-handles
##
##     twig_roles      (useless for ACL checking)
##     twig_acl
##     twig_modules    (useless for ACL checking)
##     twig_operations (useless for ACL checking)
##     twig_cmd

sub checkACL {

    my $self = shift;
    $self->debug ("    checkACL ...");

    ## load xml files
    return undef if (not $self->getConfigsRBAC());
    $self->debug ("    RBAC loaded");

    ## get role
    return undef if (not $self->getRole());
    $self->debug ("    role loaded");

    ## get operation
    return undef if (not $self->getOperation());
    $self->debug ("    operation loaded");

    ## getOwner
    return undef if (not $self->getOwner());
    $self->debug ("    owner loaded");

    ## search a positive entry
    return undef if (not $self->getAccess());
    $self->debug ("    access granted");

    return 1;
}

sub getConfigsRBAC {

    my $self = shift;

    my $twig_cmds = $self->{cache}->get_xpath (
                        FILENAME => $self->{configfile},
                        XPATH    => 'access_control/acl_config/command_dir');
    if (not defined $twig_cmds)
    {
        $self->xsetXMLerror (6291024, "Loading directory with command configuration");
        return undef;
    } elsif (not $twig_cmds) {
        $self->setError (6291025,
            $self->{gettext} ("The xml path to the access control is missing (__FILENAME__: access_control/acl_config/command_dir).",
                              "__FILENAME__", $self->{configfile}));
        return undef;
    }
    my $cmd = $self->{cgi}->param ('cmd');
    $self->{cmdfile} = $twig_cmds."/".$cmd.".xml";
    my $cmp_cmd = $self->{cache}->get_xpath (
                        FILENAME => $self->{cmdfile},
                        XPATH    => 'command_config/command/name');
    if (not defined $cmp_cmd)
    {
        $self->setXMLerror (6291049, "Loading command name");
        return undef;
    } elsif (not $cmp_cmd) {
        $self->setError (6291050,
            $self->{gettext} ("The xml path to the access control is missing (__FILENAME__: command_config/command/name).",
                              "__FILENAME__", $self->{cmdfile}));
        return undef;
    }
    if ($cmp_cmd ne $cmd) {
        $self->setError (6291060,
            $self->{gettext} ("The filename of the command configuration do not match the included command configuration (__INCLUDED_CMD__/__FILE_CMD__).",
                              "__INCLUDED_CMD__", $cmp_cmd,
                              "__FILE_CMD__", $cmd));
        return undef;
    }

    return 1;
}

sub getModule {

    my $self = shift;

    ## the error was configured in loadModuleID

    return undef if (not exists $self->{acl});
    return undef if (not exists $self->{acl}->{module_id});
    return $self->{acl}->{module_id};

}

sub getUser
{
    my $self = shift;
    return undef if (not exists $self->{ident});
    return undef if (not exists $self->{ident}->{name});
    return $self->{ident}->{name};
}

sub getDN
{
    my $self = shift;
    return undef if (not exists $self->{ident});
    return undef if (not exists $self->{ident}->{dn});
    return $self->{ident}->{dn};
}

sub getRole {

    my $self = shift;

    if ($self->{acl}->{map_role} =~ /^no$/i) {
        $self->{acl}->{role} = $self->{ident}->{name};
        return 1;
    } elsif ($self->{acl}->{map_role} !~ /^yes$/i) {
        $self->setError (6293010,
            $self->{gettext} ("There is a problem with the configuration. Should the user be mapped to a role?"));
        return undef;
    } ## else --> we map the user to a role

    ## can we map the user to a role?

    if ($self->{ident}->{type} =~ /^passwd$/i)
    {
        if (not $self->{ident}->{role})
        {
            $self->setError (6293013,
                $self->{gettext} ("There is a problem with the configuration. A user can only be mapped to a role if the role was explicitly specified in the access control configuration."));
            return undef;
        } else {
            $self->{acl}->{role} = $self->{ident}->{role};
            return 1;
        }
    }

    ## we need the serial of a cert to do this
    ## this requires that ident performs a x509 identification
    if ($self->{ident}->{type} !~ /^x509$/i) {
        $self->setError (6293017,
            $self->{gettext} ("There is a problem with the configuration. A user can only be mapped to a role if the identification uses certificates."));
        return undef;
    }

    ## load the certificate
    my $cert = $self->{db}->getItem (KEY => $self->{ident}->{name}, DATATYPE => "VALID_CERTIFICATE");
    if (not $cert) {
        $self->setError (6293020,
            $self->{gettext} ("Cannot load certificate __SUBJECT__ from the database.",
                              "__SUBJECT__", $self->{ident}->{name}));
        return undef;
    }

    ## get role
    $self->{acl}->{role} = $cert->getParsed()->{HEADER}->{ROLE};

    return 1;
}

sub getOperation {

    my $self = shift;

    $self->{acl}->{cmd} = $self->{cgi}->param ('cmd');

    if ($self->{acl}->{map_operation} =~ /^no$/i) {
        $self->{acl}->{operation} = $self->{acl}->{cmd};
        return 1;
    } elsif ($self->{acl}->{map_operation} !~ /^yes$/i) {
        $self->setError (6294010,
            $self->{gettext} ("There is a problem with the configuration. Should the command be mapped to an operation?"));
        return undef;
    } ## else --> we map the command to an operation

    ## get the operation from the commands configuration
    $self->{acl}->{operation} = $self->{cache}->get_xpath (
                        FILENAME => $self->{cmdfile},
                        XPATH    => 'command_config/command/operation');

    ## check that we have the correct file
    ## already done after initial loading of the file

    return 1;
}

sub getOwner {

    my $self = shift;

    ## check the configuration
    $self->{acl}->{owner_method} = $self->{cache}->get_xpath (
                        FILENAME => $self->{cmdfile},
                        XPATH    => 'command_config/command/owner_method');
    $self->{acl}->{owner_argument} = $self->{cache}->get_xpath (
                        FILENAME => $self->{cmdfile},
                        XPATH    => 'command_config/command/owner_argument');
    if (not defined $self->{acl}->{owner_method}) {
        $self->setError (6295010,
            $self->{gettext} ("The xml path to the access control is missing (__FILENAME__: command_config/command/owner_method).",
                              "__FILENAME__", $self->{cmdfile}));
        return undef;
    }
    if (not defined $self->{acl}->{owner_argument}) {
        $self->setError (6295015,
            $self->{gettext} ("The xml path to the access control is missing (__FILENAME__: command_config/command/owner_argument).",
                              "__FILENAME__", $self->{cmdfile}));
        return undef;
    }

    ## if we sign our configfiles then we must verify them here

    ## what we have for owners ?
    ##
    ## Certification Authority (empty owner_method)
    ## CERTIFICATE_SERIAL
    ## CSR_SERIAL
    ## CRR_SERIAL
    ## CGI
    ## ANY

    ## check for certificates
    if ( not $self->{acl}->{owner_method}) {
        $self->{acl}->{object} = "";
        $self->{acl}->{owner}  = "";
    } elsif ( $self->{acl}->{owner_method} =~ /^CERTIFICATE_SERIAL$/i ) {
        ## load serial
        if ( $self->{cgi}->param ($self->{acl}->{owner_argument}) < 1 ) {
            ## CA_CERTIFICATE detected
            ## owner is CA 
            ## wrong --> method
            $self->{acl}->{object} = "";
            $self->{acl}->{owner}  = "";
        } else {
            $self->{acl}->{object} = $self->{cgi}->param ($self->{acl}->{owner_argument});
    
            ## load the certificate
            my @certs;
            my $certtype = "CERTIFICATE";
            if( not (@certs = $self->{db}->searchItems (
			KEY => $self->{acl}->{object}, 
			DATATYPE => "CERTIFICATE"))) {
            # if (length ($self->{acl}->{object}) < 60 ) {
            #    @certs = $self->{db}->searchItems (KEY => $self->{acl}->{object}, DATATYPE => "CERTIFICATE");
            #} else {
                $certtype = "CA_CERTIFICATE";
                @certs = $self->{db}->searchItems (
			KEY => $self->{acl}->{object}, 
			DATATYPE => "CA_CERTIFICATE");
            }
            # if (length ($self->{acl}->{object}) < 60 ) {
            #     @certs = $self->{db}->searchItems (KEY => $self->{acl}->{object}, DATATYPE => "CERTIFICATE");
            # } else {
            #     $certtype = "CA_CERTIFICATE";
            #     @certs = $self->{db}->searchItems (KEY => $self->{acl}->{object}, DATATYPE => "CA_CERTIFICATE");
           #  }
            my $cert;
            $cert = $certs[0] if (@certs);
            if (not $cert) {
                $self->setError (6295020,
                    $self->{gettext} ("Cannot load certificate __SERIAL__ from the database.",
                                      "__SERIAL__", $self->{acl}->{object}));
                return undef;
            }

            if ($certtype eq "CA_CERTIFICATE")
            {
                ## superuser required
                $self->{acl}->{owner} = "";
            } else {
                ## normal certificate --> load a real role
                $self->{acl}->{owner} = $cert->getParsed()->{HEADER}->{ROLE};
            }
        }

    ## check for certificate signing requests
    } elsif ( $self->{acl}->{owner_method} =~ /^CSR_SERIAL$/i ) {
        $self->{acl}->{object} = $self->{cgi}->param ($self->{acl}->{owner_argument});
        my $req = $self->{db}->getItem ( DATATYPE => "REQUEST",
                                 KEY      => $self->{acl}->{object} );
        if (not $req) {
                $self->setError (6295035,
                    $self->{gettext} ("Cannot load CSR __SERIAL__ from the database.",
                                      "__SERIAL__", $self->{acl}->{object}));
                return undef;
        }

        ## this is actually the only part of the RBAC where the
        ## role is not protected by a signature
        $self->{acl}->{owner} = $req->getParsed()->{HEADER}->{ROLE};

    ## check for CRRs
    } elsif ( $self->{acl}->{owner_method} =~ /^CRR_SERIAL$/i ) {
        $self->{acl}->{object} = $self->{cgi}->param ($self->{acl}->{owner_argument});
        my $req = $self->{db}->getItem ( DATATYPE => "CRR",
                                 KEY      => $self->{acl}->{object} );
        if (not $req) {
                $self->setError (6295040,
                    $self->{gettext} ("Cannot load CRR __SERIAL__ from the database.",
                                      "__SERIAL__", $self->{acl}->{object}));
                return undef;
        }

        ## load the certificate
        my $cert = $self->{db}->getItem (KEY => $req->getParsed()->{REVOKE_CERTIFICATE_SERIAL},
                                 DATATYPE => "CERTIFICATE");
        if (not $cert) {
            $self->setError (6295050,
                $self->{gettext} ("Cannot load certificate __SERIAL__ from the database.",
                                  "__SERIAL__", $req->getParsed()->{REVOKE_CERTIFICATE_SERIAL}));
            return undef;
        }

        $self->{acl}->{owner} = $cert->getParsed()->{HEADER}->{ROLE};

    ## owner will be directly identified by the user
    ## FIXME: how can I trust the recommendation of a user during ACL evaluation?
    } elsif ( $self->{acl}->{owner_method} =~ /^CGI$/i ) {
        $self->{acl}->{owner} = $self->{cgi}->param ($self->{acl}->{owner_argument});

    ## ignore the owner
    } elsif ( $self->{acl}->{owner_method} =~ /^ANY$/i ) {
        ## "superuser"
        ## this is no problem because there are no regular objects which can
        ## be owned by the CA or a normal role
        $self->{acl}->{owner} = "";
    } else {
        $self->setError (6295090,
            $self->{gettext} ("The used owner method __METHOD__ is unknown so there is a misconfiguration of the command __CMD__.",
                              "__METHOD__", $self->{acl}->{owner_method},
                              "__CMD__", $self->{acl}->{cmd}));
        return undef;
    }

    return 1;
}

sub getAccess {

    my $self = shift;

    $self->debug ("getAccess: real module: $self->{acl}->{module_id}");
    $self->debug ("getAccess: real role: $self->{acl}->{role}");
    $self->debug ("getAccess: real operation: $self->{acl}->{operation}");
    $self->debug ("getAccess: real owner: $self->{acl}->{owner}");

    my $ok = 0;
    ## check each entry
    for (my $i=0; $i<$self->{acl}->{length}; $i++) {
        $self->debug ("getAccess: module: $self->{acl}->{list}->[$i]->{module}");
        $self->debug ("getAccess: role: $self->{acl}->{list}->[$i]->{role}");
        $self->debug ("getAccess: operation: $self->{acl}->{list}->[$i]->{operation}");
        $self->debug ("getAccess: owner: $self->{acl}->{list}->[$i]->{owner}");
        next if (not defined $self->{acl}->{list}->[$i]->{module});
        next if (not defined $self->{acl}->{list}->[$i]->{role});
        next if (not defined $self->{acl}->{list}->[$i]->{operation});
        next if (not defined $self->{acl}->{list}->[$i]->{owner});
        next if ($self->{acl}->{module_id} !~ /^$self->{acl}->{list}->[$i]->{module}$/);
        next if ($self->{acl}->{role}      !~ /^$self->{acl}->{list}->[$i]->{role}$/);
        next if ($self->{acl}->{operation} !~ /^$self->{acl}->{list}->[$i]->{operation}$/);
        next if ($self->{acl}->{owner}     !~ /^$self->{acl}->{list}->[$i]->{owner}$/);
        $self->debug ("getAccess: access granted");
        $ok = 1;
        last;
    }
    if (not $ok) {
	$self->{session}->stop();
        $self->setError (6296060,
            $self->{gettext} ("Permission denied."));
        return undef;
    }

    return 1;
}

#######################################################################
##                    remove old sessions                            ##
#######################################################################

sub cleanupSessions {

    my $self = shift;

    my $expired = 0;
    my $dir = $_[0];
    $dir = $self->{cache}->get_xpath (
                  FILENAME => $self->{configfile},
                  XPATH    => 'access_control/session/directory')
        if (not $dir);
    $self->debug ("cleanupSessions: dir: $dir");

    ## load all sessions
    opendir DIR, $dir;
    my @session_files = grep /^(?!\.\.$).*/, grep /^(?!\.$)./, readdir DIR;
    closedir DIR;

    return $expired if (not scalar @session_files);

    ## check every session
    foreach my $session_file (@session_files)
    {
        $self->debug ("cleanupSessions: scanning file: ${session_file}");
        ## directories handled recursively
        if (-d $dir."/".$session_file)
        {
            $expired += $self->cleanupSessions ($dir."/".$session_file);
            next;
        }

        ## extract session_id
        $session_file =~ s/cgisess_//;

        ## load session
        my $session = new CGI::Session(
                             undef,
                             $session_file,
                             {Directory=>$dir});

        ## check expiration
        $self->{journal}->{session_cleanup}->{$session_file} = "ok";
        if (not $session->param ('valid')) {
            ## delete session if not valid
            $session->delete;
            $expired++;
            $self->{journal}->{session_cleanup}->{$session_file} = "deleted";
        }
    }

    ## return the number of expired sessions
    return $expired;
}

#######################################################################
##                    load data for tokens                           ##
#######################################################################

sub initToken {
    my $self = shift;

    $self->debug ("initToken: starting");

    $self->getTokenParam ($self->{session}->getParam ('ACCESS_CONTROL_TOKEN_NAME'))
        if ($self->{session}->getParam ('ACCESS_CONTROL_TOKEN_LOGIN'));

    $self->debug ("initToken: successfully finished");

    return 1;
}

sub getTokenParam {

    my $self = shift;

    $self->debug ("    OpenCA::AC->getTokenParam ...");

    ## check the name of the token
    my $name;
    if (scalar @_)
    {
        $name = shift;
    } else {
        $name = $self->{session}->getParam ('ACCESS_CONTROL_TOKEN_NAME');
    }
    $self->{journal}->{token}->{name} = $name;
    $self->debug ("    OpenCA::AC->getTokenParam: name=".$name);

    ## get the number of arguments
    my $argc;
    if (scalar @_)
    {
        $argc = shift;
    } else {
        $argc = $self->{session}->getParam ('ACCESS_CONTROL_TOKEN_LOGIN');
    }
    $self->{journal}->{token}->{param_counter} = $argc;
    $self->debug ("    OpenCA::AC->getTokenParam: argc=".$argc);

    ## are the arguments present?
    my $argv = "";
    my $is_login = 0;

    for (my $i=0; $i < $argc; $i++)
    {
        $argv .= $self->{cgi}->param ($name.'_GET_TOKEN_PARAM_'.$i);
        $is_login = 1 if (defined $self->{cgi}->param ($name.'_GET_TOKEN_PARAM_'.$i));
    }

    $self->debug ("    OpenCA::AC->getTokenParam: argv=".$argv);

    ## if ($argv)
    if ($is_login)
    {
        ## restore the CGI data if initial request
        $self->debug ("    OpenCA::AC->getTokenParam: restore CGI data");
        if ($self->{session}->getParam ('ACCESS_CONTROL_TOKEN_LOGIN'))
        {
            $self->{session}->loadParams();
            $self->{session}->setParam ('ACCESS_CONTROL_TOKEN_LOGIN', '0');
            $self->{session}->clear();
            $self->{session}->setParam('name', $self->{ident}->{name});
            $self->{session}->setParam('role', $self->{ident}->{role});
            $self->{session}->setParam('valid', '1');
        }

        ## build the returned array
        my @res = undef;
        for (my $i=0; $i<$argc; $i++)
        {
            push @res, $self->{cgi}->param ($name.'_GET_TOKEN_PARAM_'.$i);
        }
        $self->{journal}->{token}->{result} = "returned params";
        return @res;
    } else {
        $self->debug ("    OpenCA::AC->getTokenParam: ask for passphrase(s)");

        ## prepare session
        $self->{session}->saveParams ();
        $self->{session}->setParam ('ACCESS_CONTROL_TOKEN_NAME',  $name);
        $self->{session}->setParam ('ACCESS_CONTROL_TOKEN_LOGIN', $argc);

        $self->debug ("    OpenCA::AC->getTokenParam: getTokenConfig");

        ## ask for passphrase
        $self->getTokenConfig;

        $self->debug ("    OpenCA::AC->getTokenParam: get Tokens");

        my $tokens = $self->{cache}->get_xpath_count (
                         FILENAME => $self->{tokenfile},
                         XPATH    => 'token_config/token');

        for (my $i=0; $i<$tokens; $i++)
        {
            my $token_name = $self->{cache}->get_xpath (
                         FILENAME => $self->{tokenfile},
                         XPATH    => [ 'token_config/token', 'name' ],
                         COUNTER  => [ $i, 0 ]);
            next if ($token_name ne $name);

						if ($self->{session}->getType() eq "CGI")
						{
            	my ($hidden_list, $info_list, $cmd_panel) = (undef, undef, undef);

            	$hidden_list->{"cmd"}  = "getStaticPage";
            	$hidden_list->{"name"} = "index";

            	$cmd_panel->[0] = '<input type="submit" value="'.
                              $self->{gettext}('OK').'">';
            	$cmd_panel->[1] = '<input type="reset" value="'.
                              $self->{gettext}('Reset').'">';

            	my $rows;
            	for (my $i=0; $i<$argc; $i++)
            	{
                if ($_[$i])
                {
                    $info_list->{BODY}->[$i]->[0] = $self->{gettext}($_[$i]);
                    $info_list->{BODY}->[$i]->[1] = '<input type="password" name="'.
                                                    "${name}_GET_TOKEN_PARAM_${i}".
                                                    '" value=""';
                } else {
                    $info_list->{BODY}->[$i]->[0] = $self->{gettext}('Password');
                    $info_list->{BODY}->[$i]->[0] .= " $i" if ($argc > 1);
                    $info_list->{BODY}->[$i]->[1] = '<input type="password" name="'.
                                                    "${name}_GET_TOKEN_PARAM_${i}".
                                                    '" value=""';
                }
            	}

            	$self->{gui}->libSendReply (
                                  "NAME"        => $token_name." ".$self->{gettext}('Token Login'),
                                  "EXPLANATION" => $self->{gettext}('Please enter your credentials.'),
                                  "HIDDEN_LIST" => $hidden_list,
                                  "INFO_LIST"   => $info_list,
                                  "CMD_PANEL"   => $cmd_panel,
				  		"MENU"	=> 0
                                 );
            	$self->{journal}->{token}->{result} = "printed login page";
            	exit (0);
						}
        	}
        	$self->setError (6245080,
            	$self->{gettext} ("The requested token is not configured (__NAME__).",
                              "__NAME__", $name));
        	return undef;
    	}
}

sub getTokenConfig 
{
    my $self = shift;

    ## check for token_config
    my $token_config_ref = $self->{cache}->get_xpath (
                           FILENAME => $self->{configfile},
                           XPATH    => 'token_config_file');
    return $self->setError (6247010,
               $self->{gettext} ("The xml path to the token configuration is missing (__FILENAME__: token_config).",
                                 "__FILENAME__", $self->{configfile}))
        if (not defined $token_config_ref);

    ## is token_config a reference?
    if ($token_config_ref)
    {
        $self->{tokenfile} = $token_config_ref;
    } else {
        $self->{tokenfile} = $self->{configfile};
    }

    return 1;
}

sub setXMLerror
{
    my $self = shift;
    my $errno  = $_[0];
    my $errval = $_[1];

    $errval =~ s/<br>([^\n])/$1/g;
    $errval =~ s/\n/<br>/g;

    $self->setError ($_[0],
        $self->{gettext} ("__MSG_CREATOR__: There is a problem with the XML cache (__ERRNO__). __ERRVAL__.",
                          "__MSG_CREATOR__", $_[1],
                          "__ERRNO__", $self->{cache}->errno(),
                          "__ERRVAL__", $self->{cache}->errval()));
    return undef;
}


sub print_ldaperror {
    my $self = shift;
    my ($operation, $msg) = @_;

    $self->debug ("        $operation unsuccessful:");
    $self->debug ("             msg code: " . $msg->code() );
    $self->debug ("             msg error: " . $msg->error() );
    $self->debug ("             msg error name: " . ldap_error_name($msg) );
    $self->debug ("             msg error text: " . ldap_error_text($msg) );
    $self->debug ("             msg error desc: " . ldap_error_desc($msg) );
#    if ( $ldapmsg->server_error() ) {
#	$self->debug ("        msg server error: " . $ldapmsg->server_error() );
#    }
}


1;
