## OpenCA::LDAP
##
## (c) 1999-2002 by Massimiliano Pala
## (c) 2002-2004 The OpenCA Project
## All rights reserved.
##

use strict;

package OpenCA::LDAP;

use X500::DN;
use Net::LDAP;

our ($errno, $errval);

($OpenCA::LDAP::VERSION = '$Revision: 1.1.1.1 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

my %params = ();

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

    $self->debug ("setError: $errno: $errval");

    ## support for: return $self->setError (1234, "Something fails.") if (not $xyz);
    return undef;
}

sub debug
{
    my $self = shift;

    return 1 if (not $self->{debug});

    print STDERR "OpenCA::LDAP->".$_[0]."\n";

    return 1;
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

sub new {
    my $that = shift;
    my $class = ref($that) || $that;

    my $self = { %params };

    bless $self, $class;

    my $keys = { @_ };

    ## load config parameters

    $self->{xml_cache}   = $keys->{XML_CACHE};
    $self->{ldap_config} = $keys->{LDAP_CONFIG};
    $self->{gui}         = $keys->{GUI};
    $self->{gettext}     = $keys->{GETTEXT};
    $self->{cgi}         = $keys->{CGI};
    $self->{debug}       = $keys->{DEBUG};

    ## ldap init
    $self->{ldap} = undef;
    $self->{bind} = undef;

    ## check config parameters

    return $self->setError (8411010, "OpenCA::LDAP->new: The translation function must be specified.")
        if( not $self->{gettext} );
    return $self->setError (8411011,
               $self->{gettext} ("OpenCA::LDAP->new: The XML cache must be specified."))
        if( not $self->{xml_cache} );
    return $self->setError (8411012,
               $self->{gettext} ("OpenCA::LDAP->new: The LDAP configuration file must be specified."))
        if( not $self->{ldap_config} );

    ## read ldap specs

    ## suffix/dn and excluded_roles/role are multivalued
    ## all others are single valued

    $self->{debug}    = $self->get_config ("debug") if (not $self->{debug});
    $self->{suffix}   = $self->get_config ("suffix/dn");
    $self->{excluded_roles} = $self->get_config ("excluded_roles/role");
    $self->{passwd}   = $self->get_config ("passwd");
    $self->{login}    = $self->get_config ("login");
    $self->{host}     = $self->get_config ("host");
    $self->{port}     = $self->get_config ("port");
    $self->{protocol_version} = $self->get_config ("protocol_version");
    $self->{tls}      = $self->get_config ("tls");
    $self->{sasl}     = $self->get_config ("sasl");
    $self->{chain}    = $self->get_config ("chain");

    $self->load_schema ();

    return $self;
}

sub get_config
{
    my $self = shift;
    $self->debug ("get_config: xml path is ".$_[0]);

    if ($_[0] =~ /(suffix\/dn|excluded_roles\/role)/i)
    {
        my $result = undef;
        my $count = $self->{xml_cache}->get_xpath_count (
                        FILENAME => $self->{ldap_config},
                        XPATH    => [ "ldap/".$_[0] ]);
        return $result if (not $count);
        $self->debug ("get_config: count is $count");
        for (my $k=0; $k<$count; $k++)
        {
            $result->[$k] = $self->{xml_cache}->get_xpath (
                              FILENAME => $self->{ldap_config},
                              XPATH    => [ "ldap/".$_[0] ],
                              COUNTER  => [ $k ]);
            $self->debug ("get_config: value $k is ".$result->[$k]);
        }
        return $result;
    } else {
        return $self->{xml_cache}->get_xpath (
                    FILENAME => $self->{ldap_config},
                    XPATH    => [ "ldap/".$_[0] ],
                    COUNTER  => [ 0 ]);
    }
}

sub load_schema
{
    my $self = shift;

    ##  file        ::= certificate . ca
    ##  certificate ::= rdn*
    ##  ca          ::= rdn*
    ##  rdn         ::= attributetype . must? . may? . structural? . auxiliary?
    ##  must        ::= attributetype+
    ##  may         ::= attributetype+
    ##  structural  ::= objectclass+
    ##  auxiliary   ::= objectclass+

    my $schema_prefix = "ldap/schema";
    my @cert_types = ("default", "certificate", "ca");
    foreach my $cert_type (@cert_types)
    { ## block: certificate | ca
        $self->debug ("load_schema: loading $cert_type block");
        my $rdn_count = $self->{xml_cache}->get_xpath_count (
                        FILENAME => $self->{ldap_config},
                        XPATH    => [ $schema_prefix."/".$cert_type."/rdn" ]);
        $self->debug ("load_schema: rdns: $rdn_count");
        next if (not $rdn_count);
        for (my $rdn=0; $rdn < $rdn_count; $rdn++)
        { ## block: rdns
            ## attributetype
            my $attr_type = $self->{xml_cache}->get_xpath (
                    FILENAME => $self->{ldap_config},
                    XPATH    => [ $schema_prefix."/".$cert_type."/rdn", "attributetype" ],
                    COUNTER  => [ $rdn, 0 ]);
            $self->{"schema"}->{$cert_type}->{lc ($attr_type)}->{attributetype} =
                $attr_type;
            $attr_type = lc ($attr_type);
            $self->debug ("load_schema: loading attributetype $attr_type");

            my $count = $self->{xml_cache}->get_xpath_count (
                    FILENAME => $self->{ldap_config},
                    XPATH    => [ $schema_prefix."/".$cert_type."/rdn", "must/attributetype" ],
                    COUNTER  => [ $rdn ]);
            $self->debug ("load_schema: count: $count");
            $count = 0 if (not $count);
            for (my $i=0; $i < $count; $i++)
            { ## block: must
                $self->{schema}->{$cert_type}->{$attr_type}->{must}->[$i] =
                    $self->{xml_cache}->get_xpath (
                        FILENAME => $self->{ldap_config},
                        XPATH    => [ $schema_prefix."/".$cert_type."/rdn", "must/attributetype" ],
                        COUNTER  => [ $rdn, $i ]);
                $self->debug ("load_schema: must ".
                              $self->{schema}->{$cert_type}->{$attr_type}->{must}->[$i]);
            } ## block: must

            $count = $self->{xml_cache}->get_xpath_count (
                    FILENAME => $self->{ldap_config},
                    XPATH    => [ $schema_prefix."/".$cert_type."/rdn", "may/attributetype" ],
                    COUNTER  => [ $rdn ]);
            $self->debug ("load_schema: count: $count");
            $count = 0 if (not $count);
            for (my $i=0; $i < $count; $i++)
            { ## block: may
                $self->{schema}->{$cert_type}->{$attr_type}->{may}->[$i] =
                    $self->{xml_cache}->get_xpath (
                        FILENAME => $self->{ldap_config},
                        XPATH    => [ $schema_prefix."/".$cert_type."/rdn", "may/attributetype" ],
                        COUNTER  => [ $rdn, $i ]);
                $self->debug ("load_schema: may ".
                              $self->{schema}->{$cert_type}->{$attr_type}->{may}->[$i]);
            } ## block: may

            $count = $self->{xml_cache}->get_xpath_count (
                    FILENAME => $self->{ldap_config},
                    XPATH    => [ $schema_prefix."/".$cert_type."/rdn", "structural/objectclass" ],
                    COUNTER  => [ $rdn ]);
            $self->debug ("load_schema: count: $count");
            $count = 0 if (not $count);
            for (my $i=0; $i < $count; $i++)
            { ## block: structural
                $self->{schema}->{$cert_type}->{$attr_type}->{structural}->[$i] =
                    $self->{xml_cache}->get_xpath (
                        FILENAME => $self->{ldap_config},
                        XPATH    => [ $schema_prefix."/".$cert_type."/rdn", "structural/objectclass" ],
                        COUNTER  => [ $rdn, $i ]);
                $self->debug ("load_schema: structural ".
                              $self->{schema}->{$cert_type}->{$attr_type}->{structural}->[$i]);
            } ## block: structural

            $count = $self->{xml_cache}->get_xpath_count (
                    FILENAME => $self->{ldap_config},
                    XPATH    => [ $schema_prefix."/".$cert_type."/rdn", "auxiliary/objectclass" ],
                    COUNTER  => [ $rdn ]);
            $self->debug ("load_schema: count: $count");
            $count = 0 if (not $count);
            for (my $i=0; $i < $count; $i++)
            { ## block: auxiliary
                $self->{schema}->{$cert_type}->{$attr_type}->{auxiliary}->[$i] =
                    $self->{xml_cache}->get_xpath (
                        FILENAME => $self->{ldap_config},
                        XPATH    => [ $schema_prefix."/".$cert_type."/rdn", "auxiliary/objectclass" ],
                        COUNTER  => [ $rdn, $i ]);
                $self->debug ("load_schema: auxiliary ".
                              $self->{schema}->{$cert_type}->{$attr_type}->{auxiliary}->[$i]);
            } ## block: auxiliary
        } ## block: rdns
    } ## block: certificate | ca
}
#################################################################
#################################################################
##         LDAP insertion stuff for valid certs and CRLs       ##
#################################################################
#################################################################

sub add_object {

  ######################################################
  ## only certs makes sense because a CRL can only be ##
  ## produced if a valid CA-cert exists               ##
  ######################################################

  my $self = shift;
  my $keys = { @_ };
  my ( $obj, $parsed, $serID, $ldapadd_result, $ret, $dn, $cn, $sn, $email );

  $self->debug ("add_object: Started add_object ...");

  ## check the type of the attribute
  $obj   = $keys->{CERTIFICATE};
  return { STATUS => 0,
           CODE => -1,
           DESC => $self->{gettext} ("No object specified.")
         } if ( not $obj );
  $self->debug ("add_object: certificate present ...");

  ## reject certificates of special roles
  if (not $obj->getParsed()->{IS_CA}) {
      $self->debug ("add_object: no CA-cert ...");
      $self->debug ("add_object: IS_CA ...".$obj->getParsed()->{IS_CA});
      my $roles = join '\n', @{$self->{excluded_roles}};
      my $role  = $obj->getParsed ()->{HEADER}->{ROLE};
      return { STATUS => 1,
               CODE => -2,
               DESC => $self->{gettext} ("Excluded because of the role.")
             } if ($roles =~ /^${role}$/m);
  }
  $self->debug ("add_object: role ok ...");

  ## get the needed data
  my $cert_dn    = $obj->getParsed ()->{DN};
  my $cert_cn    = $obj->getParsed ()->{DN_HASH}->{CN}[0];
  my $cert_sn    = $obj->getParsed ()->{DN_HASH}->{SN}[0];
  my $cert_serID = $obj->getParsed ()->{SERIAL};
  my $cert_email = $obj->getParsed ()->{EMAILADDRESS};
  my $cert_ou    = $obj->getParsed ()->{DN_HASH}->{OU};
  my $cert_o     = $obj->getParsed ()->{DN_HASH}->{O}[0];
  my $cert_l     = $obj->getParsed ()->{DN_HASH}->{L}[0];
  my $cert_st    = $obj->getParsed ()->{DN_HASH}->{ST}[0];
  my $cert_c     = $obj->getParsed ()->{DN_HASH}->{C}[0];

  ## debugging
  $self->debug ("add_object: Information of the Object:");
  $self->debug ("add_object: dn    ".$cert_dn);
  $self->debug ("add_object: cn    ".$cert_cn);
  $self->debug ("add_object: serID ".$cert_serID);
  $self->debug ("add_object: email ".$cert_email);
  $self->debug ("add_object: ou    ".$cert_ou);
  $self->debug ("add_object: o     ".$cert_o);
  $self->debug ("add_object: l     ".$cert_l);
  $self->debug ("add_object: st    ".$cert_st);
  $self->debug ("add_object: c     ".$cert_c);
  $self->debug ("add_object: End of the information of the Object");

  ## if cn is not present but email is then we calculate a cn
  $cert_cn = $cert_sn if (not $cert_cn and $cert_sn);
  if (not $cert_cn and $cert_email) {
      $cert_cn = $cert_email;
      $cert_cn =~ s/\@.*$//;
      $cert_cn =~ s/\./ /;
  }

  ## sn is not the real sn sometimes but you can find
  ## the person via a search with a wildcard
  if (not $cert_sn and $cert_cn) {
      $cert_sn = $cert_cn;
      $cert_sn =~ s/\s*$//;
      $cert_sn =~ s/^[^ ]* //;
  }

  ## Get the Connection to the Server
  if ( not $self->connect() ) {
    $self->debug ("add_object: Connection refused by server.");
    return { STATUS => 0,
             CODE => -3,
             DESC => $self->{gettext} ("Connection refused by server.") };
  };

  ##// Let's bind for a predetermined User
  if (not $self->bind())
  {
    my $msg = $self->{gettext} ("LDAP-bind failed: __ERRVAL__",
                                "__ERRVAL__", $self->errval) ;
    $self->debug ("add_object: Cannot bind to server.");
    return { STATUS => 0, CODE => $self->errno, DESC => $msg };
  };

  ## determine the distinguished name for the directory
  ## we support the DirName attribute in subject alt name

  my $dn_object = undef;
  foreach my $line (@{$obj->getParsed()->{OPENSSL_EXTENSIONS}->{"X509v3 Subject Alternative Name"}})
  {
      my @pairs = split /,\s*/, $line;
      foreach my $pair (@pairs)
      {
          next if ($pair =~ /:/);
          my $name = $pair;
          $name =~ s/^\s*//;
          $name =~ s/:.*$//;
          next if ($name ne "DirName");
          my $value = $pair;
          $value =~ s/^[^:]*://;
          $dn_object = $self->get_dn ($value);
          last;
      }
      last if ($dn_object);
  }
  $dn_object = $self->get_dn ($obj->getParsed ()->{DN})
      if (not $dn_object);

  my $suffix_object = $self->get_suffix ($dn_object);
  if (not $suffix_object)
  {
      $self->debug ("add_object: dn conflicts with basedn(s)");
      return { STATUS => 0 , 
               DESC => $self->{gettext} ("Distinguished name conflicts with basedn(s)."),
               CODE => -4 };
  }
  ## add an empty string to create the basedn if necessary
  my @dn_array = reverse $self->get_path ($dn_object, $suffix_object);
  push @dn_array, ["",""];

  ## setup the tree for the DN
  ## attention only the last ldapadd must be successful !!!
  $self->debug ("add_object: Building the missing nodes of the LDAP-tree ...");
  my $add_dn = $suffix_object->getRFC2253String;
  my $actual_element;
  my $use_ldap_add = 0;
  ## stores information which is available at this hierarchy level
  my %attributes;
  undef %attributes;
  while (scalar (@dn_array)) {

    $actual_element = pop @dn_array;

    ## prepare the needed strings
    if ($actual_element->[0]) {
        ## protection against basedn
        $add_dn = $actual_element->[0]."=".
                  $actual_element->[1].",".$add_dn;
    } else {
        ## servers suffix
        $actual_element->[0] = $add_dn;
        $actual_element->[0] =~ s/,.*$//;
        $actual_element->[1] = $actual_element->[0];
        $actual_element->[0] =~ s/=.*$//;
        $actual_element->[1] =~ s/^[^=]*=//;
    }
    $actual_element->[0] =~ s/^\s*//;
    $actual_element->[0] =~ s/\s*$//;

    ## add the attribute to the known attribute values
    if (exists $attributes{$actual_element->[0]})
    {
        $attributes{lc $actual_element->[0]}[scalar @{$attributes{lc $actual_element->[0]}}] = $actual_element->[1];
        $attributes{mail}[scalar @{$attributes{mail}}] = $actual_element->[1]
            if ($actual_element->[0] =~ /mail/i);
    } else {
        $attributes{lc $actual_element->[0]}[0] = $actual_element->[1];
        $attributes{mail}[0] = $actual_element->[1]
            if ($actual_element->[0] =~ /mail/i);
    }

    $self->debug ("add_object: Try to add $add_dn ...\n".
                  "attribute: $actual_element->[0]\n".
                  "value: ".$actual_element->[1]);

    ## check that the entry does not exist in the LDAP-tree
    $self->debug ("add_object: LDAP Schema DN: ".$add_dn);
    my $ldap_schema = $self->{ldap}->schema (dn => $add_dn);
    ## I stop the insertion because of a searcherror too
    if ( not $ldap_schema ) {
      $self->debug ("add_object: node doesn't exist");
    } elsif (not $ldap_schema->error() ) {
      ## node/leaf exists
      $self->debug ("add_object: node exists");
      next;
    } else {
      $self->debug ("add_object: something is going wrong --> node doesn't exist?");
      $self->debug ("add_object: LDAP Schema-Code ".$ldap_schema->error());
    }
    $use_ldap_add = 1;

    my @ldap_attr = ();
    my @objectclass = ();
    push @objectclass, 'top';

    ## set certificate type
    my $cert_type = "certificate";
    $cert_type = "ca" if ($obj->getParsed()->{IS_CA});
    $cert_type = "default" if (scalar (@dn_array));

    ## special schema handling
    $self->debug ("add_object: fixing attributes");
    $attributes{cn}[0]   = $cert_cn    if (not $attributes{cn}   and $cert_cn);
    $attributes{sn}[0]   = $cert_sn    if (not $attributes{sn}   and $cert_sn);
    $attributes{mail}[0] = $cert_email if (not $attributes{mail} and $cert_email);

    ## check that the attributetype is supported by the schema
    $self->debug ("add_object: search for matching schema - ".lc ($actual_element->[0]));
    $self->debug ("add_object: search for matching schema - ".$cert_type);
    $self->debug ("add_object: search for matching schema - ".$self);
    $self->debug ("add_object: search for matching schema - ".$self->{schema});
    $self->debug ("add_object: search for matching schema - ".$self->{schema}->{$cert_type});
    $self->debug ("add_object: search for matching schema - ".$self->{schema}->{$cert_type}->{lc ($actual_element->[0])});
    $self->debug ("add_object: search for matching schema - ".$self->{schema}->{$cert_type}->{lc ($actual_element->[0])}->{attributetype});
    if (not exists $self->{schema}->{$cert_type}->{lc ($actual_element->[0])})
    {
        $self->debug ("add_object: no matching attributetype found");
        return { STATUS => 0 , 
                 DESC => $self->{gettext} ("The attributetype is unknown to OpenCA's ldap-code. Please report to openca-users\@lists.sf.net."),
                 CODE => -199 };
    }

    ## schema compliant handling

    $self->debug ("add_object: schema validation");
    foreach my $attr (@{$self->{schema}->{$cert_type}->{lc ($actual_element->[0])}->{must}})
    {
        if (not $attributes{$attr})
        {
            ## schema violation
            return { STATUS => 0 , 
                     DESC => $self->{gettext} ("The attribute __ATTRIBUTETYPE__ is not specified but required for this objectclass.",
                                               "__ATTRIBUTETYPE__", $attr),
                     CODE => -110 };
        }
        @ldap_attr = $self->push_attribute (\@ldap_attr, $attr, \%attributes);
        $self->debug ("add_object: must $attr");
    }
    foreach my $attr (@{$self->{schema}->{$cert_type}->{lc ($actual_element->[0])}->{may}})
    {
        @ldap_attr = $self->push_attribute (\@ldap_attr, $attr, \%attributes);
        $self->debug ("add_object: may $attr");
    }
    foreach my $class (@{$self->{schema}->{$cert_type}->{lc ($actual_element->[0])}->{structural}})
    {
        push @objectclass, $class;
        $self->debug ("add_object: structural $class");
    }
    foreach my $class (@{$self->{schema}->{$cert_type}->{lc ($actual_element->[0])}->{auxiliary}})
    {
        push @objectclass, $class;
        $self->debug ("add_object: structural $class");
    }

    push @ldap_attr, 'objectclass' => [ @objectclass ];

    print "Attributes for the insertion:<br>\n" if ($self->{debug});
    for (my $h=0; $h < scalar @ldap_attr; $h+=2) {
      print "$ldap_attr[$h] = $ldap_attr[$h+1]<br>\n" if ($self->{debug});
    }
    if ($obj->getParsed()->{IS_CA})
    {
        $self->debug ("add_object: Must setup a CA-cert");
    } else {
        $self->debug ("add_object: Must setup a normal cert");
    }

    $ldapadd_result = $self->{ldap}->add ( $add_dn , attr => [ @ldap_attr ] );
    $self->debug ("add_object: The resultcode of the nodeinsertion was ".
                  $ldapadd_result->code);
    last if ($ldapadd_result->code);
  }

  if ($use_ldap_add) {
    if( $ldapadd_result->is_error ) {
      return { STATUS => 0 , 
               DESC => $self->{gettext}->("LDAP-add failed: __ERRVAL__",
                                          "__ERRVAL__", $ldapadd_result->error),
               CODE => $ldapadd_result->code };
    }
  }

  return { STATUS => 1, CODE => 0, DESC => $self->{gettext} ("Success") };
}

## this function add certificates and CRLs to the directory
sub add_attribute {
  my $self = shift;
  my $keys = { @_ };
  my $obj;
  my $ret;
  my $noprint;
  my $dn;
  my $attr;
  my $txt;
  my @values;
  my @mails;

  ## check the type of the attribute
  if ( $keys->{CERTIFICATE} ) {
    $obj = $keys->{CERTIFICATE};
    $attr = "userCertificate";
  } elsif ( $keys->{AUTHORITY_CERTIFICATE} ) {
    $obj = $keys->{AUTHORITY_CERTIFICATE};
    $attr = "cACertificate";
  } elsif ( $keys->{CRL} ) {
    $obj = $keys->{CRL};
    $attr = "certificateRevocationList";
  } elsif ( $keys->{AUTHORITY_CRL} ) {
    $obj = $keys->{AUTHORITY_CRL};
    $attr = "authorityRevocationList";
  }
  $attr .= ";binary";
  return { STATUS => 0,
           CODE => -1,
           DESC => $self->{gettext} ("No object specified.")
         } if ( not $obj );

  ## reject certificates of special roles
  if ($attr =~ /userCertificate/i)
  {
      my $roles = join '\n', @{$self->{excluded_roles}};
      my $role  = $obj->getParsed ()->{HEADER}->{ROLE};
      return { STATUS => 1,
               CODE => -2,
               DESC => $self->{gettext} ("Excluded because of the role.")
             } if ($roles =~ /^${role}$/m);
  }

  ## set output mode
  $noprint = $keys->{NOPRINT};

  ## Initializing Connection to LDAP Server
  if ( not $self->connect() ) {
    return { STATUS => 0,
             CODE => -3,
             DESC => $self->{gettext} ("Connection refused by server.") };
  }

  ##// Let's bind for a predetermined User
  if (not $self->bind())
  {
    my $msg = $self->{gettext} ("LDAP-bind failed: __ERRVAL__",
                                "__ERRVAL__", $self->errval) ;
    return { STATUS => 0, CODE => $self->errno, DESC => $msg };
  }

  ## get dn
  if ( $attr =~ /RevocationList/i ) {
    $dn = $obj->getParsed()->{ISSUER};
  } else { # certificates
    $dn = $obj->getParsed()->{DN};
  }
  $dn =~ s/\/(?=[A-Za-z0-9\-]+=)/,/g;
  $dn =~ s/^ *,* *//g;
  ## FIXME: is this really robust?
  ## fix problems with big letters
  $dn =~ s/email=/email=/i;
  $dn =~ s/cn=/cn=/i;
  $dn =~ s/c=/c=/i;
  $dn =~ s/ou=/ou=/i;
  $dn =~ s/o=/o=/i;
  $dn =~ s/st=/st=/i;
  $dn =~ s/l=/l=/i;

  ## $serID = $cert->getSerial();
  $self->debug ("add_attribute: DN= ".$dn);
  $self->debug ("add_attribute: attr: ".$attr);

  ###########################
  ## build the crypto-data ##
  ###########################

  ## search the attribute
  my $search_filter = "($attr=*)";
  $self->debug ("add_attribute: LDAP Searchfilter: ".$search_filter);
  my $mesg = $self->{ldap}->search (
               base => $dn,
               scope => "base",
               filter => $search_filter);
  $self->debug ("add_attribute: LDAP Search Mesg-Code ".$mesg->code);
  $self->debug ("add_attribute: LDAP Search Mesg-Count ".$mesg->count);

  ## I stop the insertion because of a searcherror too
  if ( not $mesg or $mesg->code ) {
    ## search failed
    if (!$noprint)  {
      print $self->{gettext}("Search for the attribute failed.")."\n";
    }
    my ($code, $msg);
    if ($mesg) {
      $code = $mesg->code;
      $msg  = $mesg->error;
    } else {
      $code = -4;
      $msg  = $self->{gettext} ("LDAP-search failed but the function returned no message-object.");
    }
    return { STATUS => 0 , CODE => $code, DESC => $msg };
  }

  if ( not $mesg->count or ($attr =~ /RevocationList/i)) {
    ## attribute not present now
    @values = ($obj->getDER());
  } else {

    ## we can get only one entry because scope is set to "base"

    ## load values
    @values = $mesg->entry (0)->get_value ( $attr);
    push @values, $obj->getDER();

    ## remove doubles
    @values = sort @values;
    for (my $i=1; $i < scalar @values; $i++) {
      if ($values[$i] eq $values[$i-1]) {
        splice @values, $i, 1;
        $i--;
      }
    }

  }

  ##############################
  ## build the emailaddresses ##
  ##############################

  ## search the attribute
  $search_filter = "(mail=*)";
  $self->debug ("add_attribute: LDAP Searchfilter: ".$search_filter);
  $mesg = $self->{ldap}->search (
               base => $dn,
               scope => "base",
               filter => $search_filter);
  $self->debug ("add_attribute: LDAP Search Mesg-Code ".$mesg->code);
  $self->debug ("add_attribute: LDAP Search Mesg-Count ".$mesg->count);

  ## I stop the insertion because of a searcherror too
  if ( not $mesg or $mesg->code ) {
    ## search failed
    if (!$noprint)  {
      print $self->{gettext} ("Search for the attribute mail failed.")."\n";
    }
    my ($code, $msg);
    if ($mesg) {
      $code = $mesg->code;
      $msg  = $mesg->error;
    } else {
      $code = -4;
      $msg  = $self->{gettext} ("LDAP-search failed but the function returned no message-object.");
    }
    return { STATUS => 0 , CODE => $code, DESC => $msg };
  }

  @mails = ();
  if ($attr =~ /userCertificate/i) {
    if ( not $mesg->count ) {
      push @mails, $obj->getParsed()->{EMAILADDRESS} if ($obj->getParsed()->{EMAILADDRESS});
    } else {
      @mails = $mesg->entry (0)->get_value ("mail");
      @mails = () if ((scalar @mails == 1) and not $mails[0]);
     
      my $email = $obj->getParsed()->{EMAILADDRESS};
      foreach my $h (@mails) {
        if ($h =~ /$email/i) {
          $email = "";
          last;
        }
      }
      if ($email) {
        push @mails, $obj->getParsed()->{EMAILADDRESS};
      }
    }
  }

  ## insert into ldap

  $self->debug ("add_attribute: Starting LDAP-modify: dn is ".$dn);
  if (scalar @mails) {
    $self->debug ("add_attribute: fixing mail too");
    $mesg = $self->{ldap}->modify ($dn, changes => [
                                    replace => [$attr  => [ @values ]],
              ##                      replace => ['mail' => [ @mails  ]]
                                        ]);
  } else {
    $mesg = $self->{ldap}->modify ($dn, changes => [
                                    replace => [$attr => [ @values ]]
                                        ]);
  }

  if( $mesg->code ) { 
 
    $txt = $self->{gettext} ("Error __ERRNO__: __ERRVAL__",
                        "__ERRNO__", $mesg->code,
                        "__ERRVAL__", $mesg->error);

    if (!$noprint)  {
      print "$txt\n";
    }
    return { STATUS => 0 , CODE => $mesg->code, DESC => $mesg->error };
  }

  $txt = $self->{gettext} ("Attribute successfully inserted.");
  if (!$noprint) {
    print $self->{gettext} ("Success (__MESSAGE__)", "__MESSAGE__", $txt)."\n";
  }
  return { STATUS => 1, 
           DESC => $self->{gettext} ("Success (__MESSAGE__)", "__MESSAGE__", $txt),
           CODE => 0 };
}

#################################################################
#################################################################
##          LDAP deletion stuff for revoked certs              ##
#################################################################
#################################################################

## this function add certificates and CRLs to the directory
sub delete_attribute {
  my $self = shift;
  my $keys = { @_ };
  my $obj;
  my $ret;
  my $noprint;
  my $dn;
  my $attr;
  my $txt;
  my @values;

  ## check the type of the attribute
  if ( $keys->{CERTIFICATE} ) {
    $obj = $keys->{CERTIFICATE};
    $attr = "userCertificate";
  } elsif ( $keys->{AUTHORITY_CERTIFICATE} ) {
    $obj = $keys->{AUTHORITY_CERTIFICATE};
    $attr = "cACertificate";
  } elsif ( $keys->{CRL} ) {
    $obj = $keys->{CRL};
    $attr = "certificateRevocationList";
  } elsif ( $keys->{AUTHORITY_CRL} ) {
    $obj = $keys->{AUTHORITY_CRL};
    $attr = "authorityRevocationList";
  }
  $attr .= ";binary";
  return { STATUS => 0,
           CODE => -1,
           DESC => $self->{gettext} ("No object specified.")
         } if ( not $obj );

  ## set output mode
  $noprint = $keys->{NOPRINT};
  $noprint = 0 if ($self->{debug});

  ## Initializing Connection to LDAP Server
  if ( not $self->connect() ) {
    return { STATUS => 0,
             CODE => -3,
             DESC => $self->{gettext} ("Connection refused by server.") };
  }

  ##// Let's bind for a predetermined User
  if (not $self->bind())
  {
    my $msg = $self->{gettext} ("LDAP-bind failed: __ERRVAL__",
                                "__ERRVAL__", $self->errval) ;
    return { STATUS => 0, CODE => $self->errno, DESC => $msg };
  }

  ## get dn
  if ( $attr =~ /RevocationList/i ) {
    $dn = $obj->getParsed()->{ISSUER};
  } else { # certificates
    $dn = $obj->getParsed()->{DN};
  }
  $dn =~ s/\/(?=[A-Za-z0-9\-]+=)/,/g;
  $dn =~ s/^ *,* *//g;
  ## FIXME: is this really robust
  ## fix problems with big letters
  $dn =~ s/email=/email=/i;
  $dn =~ s/cn=/cn=/i;
  $dn =~ s/c=/c=/i;
  $dn =~ s/ou=/ou=/i;
  $dn =~ s/o=/o=/i;
  $dn =~ s/st=/st=/i;
  $dn =~ s/l=/l=/i;

  ## $serID = $cert->getSerial();
  $self->debug ("delete_attribute: DN= ".$dn);
  $self->debug ("delete_attribute: attr: ".$attr);

  ## search the attribute
  my $search_filter = "($attr=*)";
  $self->debug ("delete_attribute: LDAP Searchfilter: ".$search_filter);
  my $mesg = $self->{ldap}->search (
               base => $dn,
               scope => "base",
               filter => $search_filter);
  $self->debug ("delete_attribute: LDAP Search Mesg-Code ".$mesg->code);
  $self->debug ("delete_attribute: LDAP Search Mesg-Count ".$mesg->count);

  ## I stop the insertion because of a searcherror too
  if ( not $mesg or $mesg->code ) {
    ## search failed
    if (!$noprint)  {
      print $self->{gettext}("Search for the attribute failed.")."\n";
    }
    my ($code, $msg);
    if ($mesg) {
      $code = $mesg->code;
      $msg  = $mesg->error;
    } else {
      $code = -4;
      $msg  = $self->{gettext} ("LDAP-search failed but the function returned no message-object.");
    }
    return { STATUS => 0 , CODE => $code, DESC => $msg };
  }

  my $entry = $mesg->entry (0);
  if ( $attr =~ /RevocationList/i ) {
    ## attribute not present now
    @values = ();
    $entry->replace ( $attr => [ @values ] );
  } else {

    ## we can get only one entry because scope is set to "base"a

    ## load values
    @values = $entry->get_value ( $attr);

    ## remove doubles
    @values = sort @values;
    for (my $i=1; $i < scalar @values; $i++) {
      if ($values[$i] eq $values[$i-1]) {
        splice @values, $i, 1;
        $i--;
      }
    }

    ## remove the specified object
    @values = sort @values;
    for (my $i=0; $i < scalar @values; $i++) {
      if ($values[$i] eq $obj->getDER()) {
        splice @values, $i, 1;
        $i--;
      }
    }
    $entry->replace ( $attr => [ @values ] );
  }

  ## update ldap

  $self->debug ("delete_attribute: Starting LDAP-modify: dn is ".$dn);
  $mesg = $entry->update ($self->{ldap}); 

  if( $mesg->code ) { 
 
    $txt = $self->{gettext} ("Unknown Error ( __ERRNO__ )",
                             "__ERRNO__", $mesg->code);

    if (!$noprint)  {
      print "$txt\n";
    }
    return { STATUS => 0 , CODE => $mesg->code, DESC => $mesg->error };
  }

  $txt = $self->{gettext} ("Attribute successfully deleted.");
  if (!$noprint) {
    print $self->{gettext} ("Success (__MESSAGE__)", "__MESSAGE__", $txt)."\n";
  }
  return { STATUS => 1, 
           DESC => $self->{gettext} ("Success (__MESSAGE__)", "__MESSAGE__", $txt),
           CODE => 0 };
}

#################################################################
##          Get data from the diurectory server                ##
#################################################################

sub get_attribute
{
    my $self = shift;
    my $keys = { @_ };

    my $dn         = $keys->{DN};
    my $attribute  = $keys->{ATTRIBUTE};
    my $ldap       = $keys->{LDAP};
    $ldap = $self->{ldap} if (not $ldap);

    ## perform the search

    my $search_filter = "($attribute=*)";
    my $mesg = $ldap->search (
                   base => $dn,
                   scope => "base",
                   filter => $search_filter);
    $self->{debug} = 1;
    $self->debug ("get_attribute: LDAP Search Mesg-Code ".$mesg->code);
    $self->debug ("get_attribute: LDAP Search Mesg-Count ".$mesg->count);

    ## if there is an error then stop here

    if ( not $mesg or $mesg->code ) {
        if ( $mesg ) {
            $self->setError ($mesg->code, $mesg->error);
            return undef;
        } else {
            $self->setError (-1, $self->{gettext} ("LDAP-search failed but the function returned no message-object."));
            return undef;
        }
    }

    ## we can get only one entry because scope is set to "base"

    if ($mesg->count == 0) {
        if (wantarray) {
            return ();
        } else {
            return [()];
        }
    }

    my @values = $mesg->entry (0)->get_value ( $attribute);

    if (wantarray) {
        return @values;
    } else {
        return [ @values ];
    }
}

#################################################################
#################################################################
##          LDAP search never tested or completed              ##
#################################################################
#################################################################

#sub LDAPsearch {
#
#	my $keys = { @_ };
#	my ( $mseg, $ldap, $limit, $ldapBase, $serID, $filter, $ret );
#	
#	$filter = $keys->{FILTER};
#	$serID  = $keys->{SERIAL};
#
#	return if ( not $filter );
#
#	## Get required configuration keys
#	$ldapBase = getRequired( 'basedn' );
#
#	## Initializing Connection to LDAP Server
#        if ( not ( $ldap = LDAP_connect() )) {
#		print "<FONT COLOR=\"Red\">";
#                print i18nGettext ("LDAP [__CERT_SERIAL__]: Connection Refused by server!", "__CERT_SERIAL__", $serID)."\n";
#		print "</FONT><BR>\n";
#
#                return;
#        };
#
#        ##// Let's bind for a predetermined User
#	$ret = LDAP_bind( LDAP => $ldap );
#	if( $ret->is_error ) {
#                print i18nGettext ("Failed in Bind: __ERRNO__", "__ERRNO__", $ret->{CODE}) . "\n";
#                LDAP_disconnect( LDAP => $ldap );
#                return $ret->{CODE};
#        };
#
#	my $mesg = $ldap->search ( base => "$ldapBase",
#				filter => "$filter" );
#
#	if ( $mesg->code ) {
#		LDAP_disconnect( LDAP => $ldap );
#		return;
#	}
#
#	return { COUNT => $mesg->count, ENTRIES => $mesg->entries };
#};

#######################################################
#######################################################
##              connection handling                  ##
#######################################################
#######################################################

sub connect {

    my $self = shift;
    my $keys = { @_ };

    return 1 if ($self->{ldap});

    ## if no initialization found, get defaults
    $self->{port} = 389 if (not $self->{port});

    ## some options require LDAP v3
    $self->{protocol_version} = 3
        if ($self->{tls} !~ /no|off/i or
            $self->{sasl} !~ /no|off/i);

    ## Get the Connection to the Server
    $self->debug ("connect: ldap".$self->{protocol_version}.
                            "://".$self->{host}.
                              ":".$self->{port});
    $self->{ldap} = Net::LDAP->new ($self->{host}, 
                            port    => $self->{port},
                            async   => 0,
                            version => $self->{protocol_version} );

    return undef if( not $self->{ldap} );

    if ($self->{tls} !~ /no|off/i)
    {
        return undef
            if (not $self->{ldap}->start_tls (
                          verify => 'require',
                          capath => $self->{chain}));
    }

    $self->{bind} = undef;

    return $self->{ldap};
}

sub disconnect {

    my $self = shift;

    return {STATUS => 0 } if ( not $self->{ldap} );
    $self->{ldap}->unbind();

    $self->{ldap} = undef;

    return {STATUS => 1};
}

sub bind {

    my $self = shift;

    ## scan for parameters

    my $keys = { @_ };
    my ($dn, $passwd);
    if (exists $keys->{DN}) {
        $dn = $keys->{DN};
    } else {
        $dn = $self->{login};
    }
    if (exists $keys->{PASSWD}) {
        $passwd = $keys->{PASSWD};
    } else {
        $passwd = $self->{passwd};
    }

    ## Return if no connection is present
    return undef if (not $self->{ldap});

    return $self->{bind} if ($self->{bind});

    ## Try to bind to selected user
    if ($self->{sasl} =~ /no|off/i)
    {
        $self->{bind} = $self->{ldap}->bind( $dn, 'password' => $passwd );
    } else {
        use Authen::SASL;
        my $sasl_obj = Authen::SASL->new ('CRAM-MD5', password => $passwd);
        $self->{bind} = $self->{ldap}->bind( $dn, 'sasl' => $sasl_obj);
    }

    ## if got an error, return it
    if ( $self->{bind}->is_error ) {
        $self->disconnect();
        $self->setError ($self->{bind}->code, $self->{bind}->error);
        return undef;
    }

    return $self->{bind};
}

##############################################
##############################################
##      distinguished name handling         ##
##############################################
##############################################

sub get_dn {

    my $self = shift;

    ## first argument must be the DN
    return undef if (not $_[0]);
    $self->debug ("get_dn called");
    $self->debug ("get_dn: dn: ".$_[0]);

    ## parse dn
    my $dn = X500::DN->ParseRFC2253 ($_[0]);
    return undef if (not $dn);
    ## has problems but we do not support multivalued attributes
    return undef if ($dn->hasMultivaluedRDNs());

    $self->debug ("get_dn: successfully finished");
    return $dn;
}

sub get_suffix {

    my $self = shift;
    my $dn = $_[0];
    $self->debug ("get_suffix: get_suffix called for $dn");

    my @suffix_list = @{$self->{suffix}};
    $self->debug ("get_suffix: suffixes loaded");

    my $suffix_dn;
    foreach my $suffix (@suffix_list)
    {
        $suffix_dn = $self->get_dn ($suffix);
        return undef if (not $suffix_dn);

        my $res = $self->compare_dn ($dn, $suffix_dn);
        last if (defined $res and $res >= 0);
        undef $suffix_dn;
    }

    $self->debug ("get_suffix: successfully finished");
    return $suffix_dn;
}

sub compare_dn {

    my $self = shift;
    my $dn_1 = $_[0];
    my $dn_2 = $_[1];
    $self->debug ("compare_dn: called");

    my @rdn_list_1 = $dn_1->getRDNs;
    my @rdn_list_2 = $dn_2->getRDNs;

    my $length = scalar @rdn_list_1;
    $length = scalar @rdn_list_2 if (scalar @rdn_list_1 > scalar @rdn_list_2);

    $self->debug ("compare_dn: looping");
    for (my $i=0; $i < $length; $i++)
    {
        ## we do not support multivalued attributes
        my @type_1 = $rdn_list_1[$i]->getAttributeTypes;
        my @type_2 = $rdn_list_2[$i]->getAttributeTypes;

        my $value_1 = $rdn_list_1[$i]->getAttributeValue ($type_1[0]);
        my $value_2 = $rdn_list_2[$i]->getAttributeValue ($type_2[0]);

        ## normalization
        $type_1[0] = lc $type_1[0];
        $type_2[0] = lc $type_2[0];
        $value_1   = lc $value_1;
        $value_2   = lc $value_2;

        ## compare types
        return undef if ($type_1[0] ne $type_2[0]);
        return undef if ($value_1   ne $value_2);
    }
    $self->debug ("compare_dn: successfully finished");
    return 0  if (scalar @rdn_list_1 == scalar @rdn_list_2);
    return -1 if (scalar @rdn_list_1 <  scalar @rdn_list_2);
    return 1;
}

sub get_path {

    my $self = shift;
    my @node   = $_[0]->getRDNs;
    my @suffix = $_[1]->getRDNs;
    $self->debug ("get_path: called");

    my @path = ();
    for (my $i=scalar @suffix; $i < scalar @node; $i++)
    {
        ## we do not support multivalued attributes
        push @path, [($node[$i]->getAttributeTypes)[0],
                     $node[$i]->getAttributeValue (
                         ($node[$i]->getAttributeTypes)[0]
                                                  )
                    ];
    }
    $self->debug ("get_path: successfully finished");
    return @path;
}

##############################################
##        handling of attribute array       ##
##############################################

sub push_attribute
{
    my $self = shift;
    my @ldap_array = @ { $_[0] };
    my $attribute  = $_[1];
    my $attr_hash  = $_[2];

    if ($self->{debug})
    {
        $self->debug ("push_attribute: before attribute handling");
        foreach my $h (@ldap_array)
        {
            $self->debug ("push_attribute: ldap_array: $h");
        }
        foreach my $h (keys %{$attr_hash})
        {
            if (ref $attr_hash->{$h})
            {
                foreach my $item (@{$attr_hash->{$h}})
                {
                    $self->debug ("push_attribute: attr_hash: $h=$item");
                }
            } else {
                $self->debug ("push_attribute: attr_hash: $h=$attr_hash->{$h}");
            }
        }
    }
    if (exists $attr_hash->{lc $attribute}) {
        $self->debug ("push_attribute: attribute $attribute exists in hash");
        if (scalar @{$attr_hash->{lc $attribute}} == 1) {
            push @ldap_array, $attribute => $attr_hash->{lc $attribute}[0];
        } else {
            push @ldap_array, $attribute => [ @{$attr_hash->{lc $attribute}}];
        }
    }
    if ($self->{debug})
    {
        $self->debug ("push_attribute: after attribute handling");
        $self->debug ("push_attribute: attribute=$attribute");
        if (exists $attr_hash->{lc $attribute})
        {
            foreach my $h (@{$attr_hash->{lc $attribute}})
            {
                $self->debug ("push_attribute: value=$h");
            }
        }
        foreach my $h (@ldap_array)
        {
            $self->debug ("push_attribute: ldap: $h");
        }
        foreach my $h (keys %{$attr_hash})
        {
            if (ref $attr_hash->{$h})
            {
                foreach my $item (@{$attr_hash->{$h}})
                {
                    $self->debug ("push_attribute: attr_hash: $h=$item");
                }
            } else {
                $self->debug ("push_attribute: attr_hash: $h=$attr_hash->{$h}");
            }
        }
    }
    return @ldap_array;
}

########################
##     disconnect     ##
########################

sub DESTROY {
    my $self = shift;
    $self->disconnect();
}

1;
