## OpenCA::Crypto.pm 
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

use strict;

package OpenCA::Crypto;

our ($errno, $errval);
our $AUTOLOAD;

($OpenCA::Crypto::VERSION = '$Revision: 1.1.1.1 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

# Preloaded methods go here.

## Create an instance of the Class
sub new {
    my $that = shift;
    my $class = ref($that) || $that;

    my $self = {
                DEBUG     => 0,
               };

    bless $self, $class;

    my $keys = { @_ };
    $self->{configfile}    = $keys->{CONFIG};
    $self->{DEBUG}         = 1 if ($keys->{DEBUG});
    $self->{DEFAULT_TOKEN} = $keys->{DEFAULT_TOKEN} if ($keys->{DEFAULT_TOKEN});
    $self->{cache}         = $keys->{CACHE};
    $self->{gettext}       = $keys->{GETTEXT};

    ## set default token
    $self->{DEFAULT_TOKEN} = $self->{cache}->get_xpath (
                                 FILENAME => $self->{configfile},
                                 XPATH    => [ 'token_config/default_token' ],
                                 COUNTER  => [ 0 ])
        if ($self->{configfile});

    $self->debug ("new: configfile: $self->{configfile}");
    $self->debug ("new: DEFAULT_TOKEN: $self->{DEFAULT_TOKEN}");

    ## this default token overrides the configuration
    if ($self->{DEFAULT_TOKEN})
    {
        if ($self->{configfile})
        {
            return undef if (not $self->addToken ($self->{DEFAULT_TOKEN}));
        } else {
            return $self->setError (7110010,
                       $self->{gettext} ("There was token specified but there is no configurationfile."));
        }
    }

    $self->debug ("new: crypto layer is ready");
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

    $self->debug ("setError: errno:  $self->{errno}");
    $self->debug ("setError: errval: $self->{errval}");

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

sub setConfig {

    my $self = shift;

    $self->{configfile} = $_[0];
    return $self->getConfig;

}

sub debug {

    my $self = shift;

    return 1 if (not $self->{DEBUG});

    foreach my $msg (@_) {
        print STDERR "OpenCA::Crypto->$msg\n";
    }

    return 1;
}

######################################################################
##                     slot management                              ##
######################################################################

## implicit use token
sub getToken {

    my $self = shift;
    $self->debug ("getToken: entering function");

    my $name = $_[0];
    if (not $_[0])
    {
        if (not $self->{DEFAULT_TOKEN})
        {
            return $self->setError (7121010,
                       $self->{gettext} ("No default token specified."));
        }
        $name = $self->{DEFAULT_TOKEN};
    }
    $self->debug ("getToken: $name");

    return undef
        if (not $self->{TOKEN}->{$name} and
            not $self->addToken ($name));
    $self->debug ("getToken: token added");

    return $self->setError (7121030,
               $self->{gettext} ("The token is not present in the system"))
        if (not $self->{TOKEN}->{$name});
    $self->debug ("getToken: token is present");

    return $self->setError (7121040,
               $self->{gettext} ("The token is not usable."))
        if (not $self->useToken ($name));
    $self->debug ("getToken: token is usable");

    return $self->{TOKEN}->{$name};
}

sub addToken {

    my $self = shift;
    $self->debug ("addToken: entering function");

    my $name = $_[0];
    if (not $_[0])
    {
        if (not $self->{DEFAULT_TOKEN})
        {
            return $self->setError (7123010,
                       $self->{gettext} ("No default token specified."));
        }
        $name = $self->{DEFAULT_TOKEN};
    }
    $self->debug ("addToken: $name");

    ## get matching config
    my $token_count = $self->{cache}->get_xpath_count (
                          FILENAME => $self->{configfile},
                          XPATH    => 'token_config/token');
    for (my $i=0; $i<$token_count; $i++)
    {
        $self->debug ("addToken: checking name");
        next if ($name ne $self->{cache}->get_xpath (
                              FILENAME => $self->{configfile},
                              XPATH    => [ 'token_config/token', 'name' ],
                              COUNTER  => [ $i, 0 ]));
        $self->debug ("addToken: name ok");
        my @args = ();

        ## load CRYPTO, GETTEXT, NAME and MODE to array
        push @args, "OPENCA_CRYPTO", $self;
	push @args, "GETTEXT", $self->{gettext};
        push @args, "OPENCA_TOKEN", $name;
        $self->debug ("addToken: loading mode");
        my $help = $self->{cache}->get_xpath (
                               FILENAME => $self->{configfile},
                               XPATH    => [ 'token_config/token', 'mode' ],
                               COUNTER  => [ $i, 0 ]);
        push @args, "TOKEN_MODE", $help;

        ## load complete config in array
        $self->debug ("addToken: loading options");
        my $option_count = $self->{cache}->get_xpath_count (
                               FILENAME => $self->{configfile},
                               XPATH    => [ 'token_config/token', 'option' ],
                               COUNTER  => [ $i ]);
        for (my $k=0; $k<$option_count; $k++)
        {
            $help = $self->{cache}->get_xpath (
                               FILENAME => $self->{configfile},
                               XPATH    => [ 'token_config/token', 'option', 'name' ],
                               COUNTER  => [ $i, $k, 0 ]),
            $self->debug ("addToken: option name: $help");
            push @args, $help;
            $help = $self->{cache}->get_xpath (
                               FILENAME => $self->{configfile},
                               XPATH    => [ 'token_config/token', 'option', 'value' ],
                               COUNTER  => [ $i, $k, 0 ]);
            $self->debug ("addToken: option value: $help");
            push @args, $help;
        }
        $self->debug ("addToken: loaded options");

        ## handle multivalued parameters

        my $count = scalar @args / 2;
        my %hargs = ();
        for (my $i=0; $i<$count; $i++)
        {
            my $name  = $args[2*$i];
            my $value = $args[2*$i+1];
            ## if global debug then local debug too
            $value = $self->{DEBUG} if ($name =~ /DEBUG/i and not $value and $self->{DEBUG});
            if (exists $hargs{$name})
            {
                $hargs{$name} = [ @{$hargs{$name}}, $value ];
            } else
            {
                $hargs{$name} = [ $value ];
            }
            ## activate crypto layer debugging if a single token is in debug mode
            $self->{DEBUG} = $value if ($name =~ /DEBUG/i and $value);
        }
        @args = ();
        foreach my $key (keys %hargs)
        {
            $self->debug ("addToken: argument: name: $key");
            push @args, $key;
            if (scalar @{$hargs{$key}} > 1)
            {
                push @args, $hargs{$key};
            } else
            {
                push @args, $hargs{$key}->[0];
            }
        }
        $self->debug ("addToken: fixed multivalued options");

        ## init token
        my $type = $self->{cache}->get_xpath (
                               FILENAME => $self->{configfile},
                               XPATH    => [ 'token_config/token', 'type' ],
                               COUNTER  => [ $i, 0 ]);
        $self->debug ("addToken: try to setup $type token");
        $self->{TOKEN}->{$name} = $self->newToken ($type, @args);
        if (not $self->{TOKEN}->{$name})
        {
            $self->setError (7123080,
                $self->{gettext} ("Cannot create new OpenCA Token object. __ERRVAL__",
                                  "__ERRVAL__", $self->errval));
            return undef;
        }
        $self->debug ("addToken: token $name successfully added");
        return $self->{TOKEN}->{$name};
    }
    return $self->setError (7123090,
               $self->{gettext} ("The requested token is not configured (__NAME__).",
                                 "__NAME__", $name));
}

sub newToken {

    my $self = shift;
    my $name = shift;
    $self->debug ("newToken: entering function");
    foreach my $item (@_)
    {
        $self->debug ("newToken: argument: $item");
    }

    ## get the token class    
    my $token_class = "OpenCA::Token::$name";
    eval "require $token_class";
    if ($@)
    {
        $self->debug ("newToken: compilation of driver OpenCA::Token::$name failed");
        return $self->setError ($@, $@);
    }
    $self->debug ("newToken: class: OpenCA::Token::$name");

    ## get the token
    my $token = eval {$token_class->new (@_)};

    if ($@)
    {
        $self->debug ("newToken: cannot get new instance of driver OpenCA::Token::$name");
        return $self->setError ($@, $@);
    }
    $self->debug ("newToken: no error during new");
    return $self->setError ($token_class::errno, $token_class::errval)
        if (not $token);
    $self->debug ("newToken: new token present");

    return $token;
}

sub useToken {
    my $self = shift;

    my $name = $_[0];
    if (not $_[0])
    {
        if (not $self->{DEFAULT_TOKEN})
        {
            return $self->setError (7125010,
                       $self->{gettext} ("No default token specified"));
        }
        $name = $self->{DEFAULT_TOKEN};
    }

    ## the token must be present
    return $self->setError (7125020,
               $self->{gettext} ("The token is not present."))
        if (not $self->{TOKEN}->{$name});
    return $self->{TOKEN}->{$name}->login
        if (not $self->{TOKEN}->{$name}->online);
    return 1;
}

########################################################################
##                          access control                            ##
########################################################################

sub setAccessControl {
    my $self = shift;
    $self->{ACCESS_CONTROL} = $_[0];
    return 1;
}

sub getAccessControl {
    my $self = shift;
    return $self->{ACCESS_CONTROL};
}

sub stopSession {
    my $self = shift;
    my $error = 0;
    foreach my $token (keys %{$self->{TOKEN}})
    {
        next if (not $self->{TOKEN}->{$token}->getMode !~ /^session$/i);
        $error = 1 if (not $self->{TOKEN}->{$token}->logout);
    }
    return $self->setError (7174010,
               $self->{gettext} ("Logout of at minimum one token failed"))
        if ($error);
    return 1;
}

sub tokenLogOut{
	my $self = shift;
	my $name  = $_[0];

	my $error = 0;

	
	return $self->setError (7178030,
                   $self->{gettext} ("The token __NAME__ cannot be initialized.",
                                     "__NAME__", $name))
            if (not $self->addToken($name));

	
	 if (not $self->{TOKEN}->{$name}->logout())
	{
		return	$self->setError (7174010,
               $self->{gettext} ("Logout of $name token failed"));
	}
	return 1;
}


sub startDaemon {
    my $self = shift;
    my $error = 0;
    my $token_count = $self->{cache}->get_xpath_count (
                          FILENAME => $self->{configfile},
                          XPATH    => 'token_config/token');
    for (my $i=0; $i<$token_count; $i++)
    {
        next if ($self->{cache}->get_xpath (
                      FILENAME => $self->{configfile},
                      XPATH    => [ 'token_config/token', 'mode' ],
                      COUNTER  => [ $i, 0 ]) !~ /^daemon$/i);
        my $name = $self->{cache}->get_xpath (
                      FILENAME => $self->{configfile},
                      XPATH    => [ 'token_config/token', 'name' ],
                      COUNTER  => [ $i, 0 ]);
        return $self->setError (7176030,
                   $self->{gettext} ("The token __NAME__ cannot be initialized.",
                                     "__NAME__", $name))
            if (not $self->addToken($name));
        return $self->setError (7176040,
                   $self->{gettext} ("The token __NAME__ cannot be used.",
                                     "__NAME__", $name))
            if (not $self->useToken($name));
    }
    return $self->setError (7176080,
               $self->{gettext} ("Logout of at minimum one token failed"))
        if ($error);
    return 1;
}

sub stopDaemon {
    my $self = shift;
    my $error = 0;
    my $token_count = $self->{cache}->get_xpath_count (
                          FILENAME => $self->{configfile},
                          XPATH    => 'token_config/token');
    for (my $i=0; $i<$token_count; $i++)
    {
        next if ($self->{cache}->get_xpath (
                      FILENAME => $self->{configfile},
                      XPATH    => [ 'token_config/token', 'mode' ],
                      COUNTER  => [ $i, 0 ]) !~ /^daemon$/i);
        my $name = $self->{cache}->get_xpath (
                      FILENAME => $self->{configfile},
                      XPATH    => [ 'token_config/token', 'name' ],
                      COUNTER  => [ $i, 0 ]);
        return $self->setError (7178030,
                   $self->{gettext} ("The token __NAME__ cannot be initialized.",
                                     "__NAME__", $name))
            if (not $self->addToken($name));
        $error = 1 if (not $self->{TOKEN}->{$name}->logout());
    }
    return $self->setError (7178010,
               $self->{gettext} ("Logout of at minimum one token failed"))
        if ($error);
    return 1;
}

##################################################################
##                 automatic functionality                      ##
##################################################################

## failover to default token
sub AUTOLOAD {
    my $self = shift;

    return $self->setError (7196010,
               $self->{gettext} ("There is no default token specified."))
        if (not $self->{DEFAULT_TOKEN});

    return $self->setError (7196020,
               $self->{gettext} ("The default token is not present."))
        if (not $self->{TOKEN}->{$self->{DEFAULT_TOKEN}});

    return $self->{TOKEN}->{$self->{DEFAULT_TOKEN}}->$AUTOLOAD ( @_ );
}

## logout all tokens except sessions and daemons
sub DESTROY {
    my $self = shift;

    my $default_token = $self->{TOKEN}->{$self->{DEFAULT_TOKEN}};
    delete $self->{TOKEN}->{$self->{DEFAULT_TOKEN}};

    my $error = 0;
    foreach my $token (keys %{$self->{TOKEN}})
    {
        next if (not $self->{TOKEN}->{$token}->getMode =~ /^(session|daemon)$/i);
        $error = 1 if (not $self->{TOKEN}->{$token}->logout);
    }

    return $self->setError (7199010,
               $self->{gettext} ("Logout of at minimum one token failed"))
        if ($error);
    return 1;
}

1;
