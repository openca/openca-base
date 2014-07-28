## OpenCA::Logger::Syslog::Unix.pm 
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

package OpenCA::Logger::Syslog::Unix;

use Unix::Syslog qw(:macros :subs);

($OpenCA::Logger::Syslog::Unix::VERSION = '$Revision: 1.1.1.1 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

# Preloaded methods go here.

## Create an instance of the Class
sub new {
    my $that = shift;
    my $class = ref($that) || $that;

    my $self = {};

    bless $self, $class;

    my $keys = { @_ };

    ## load config
    $self->{prefix}   = $keys->{prefix};
    $self->{host}     = $keys->{host};
    $self->{port}     = $keys->{port};
    my $facility      = $keys->{facility};

    ## build priority
    $_ = $facility;
    SWITCH : {
        $self->{facility} = undef;
        $self->{facility} = LOG_AUTH   if (/auth/i);
        $self->{facility} = LOG_SYSLOG if (/syslog/i);
        $self->{facility} = LOG_DAEMON if (/daemon/i);
        $self->{facility} = LOG_LOCAL0 if (/local0/i);
        $self->{facility} = LOG_LOCAL1 if (/local1/i);
        $self->{facility} = LOG_LOCAL2 if (/local2/i);
        $self->{facility} = LOG_LOCAL3 if (/local3/i);
        $self->{facility} = LOG_LOCAL4 if (/local4/i);
        $self->{facility} = LOG_LOCAL5 if (/local5/i);
        $self->{facility} = LOG_LOCAL6 if (/local6/i);
        $self->{facility} = LOG_LOCAL7 if (/local7/i);
    }

    return undef
        if (not openlog $self->{prefix}, LOG_PID | LOG_PERROR | LOG_NDELAY, $self->{facility});

    return $self;
}

sub addMessage {
    my $self     = shift;
    my $msg      = $_[0];

    ## build priority
    $_ = $msg->getLevel;
    SWITCH : {
        $self->{priority} = LOG_EMERG   if (/EMERG/i);
        $self->{priority} = LOG_ALERT   if (/ALERT/i);
        $self->{priority} = LOG_CRIT    if (/CRIT/i);
        $self->{priority} = LOG_ERR     if (/ERR/i);
        $self->{priority} = LOG_WARNING if (/WARNING/i);
        $self->{priority} = LOG_NOTICE  if (/NOTICE/i);
        $self->{priority} = LOG_INFO    if (/INFO/i);
        $self->{priority} = LOG_DEBUG   if (/DEBUG/i);
    }

    return undef if (not syslog $self->{priority}, "%s", $msg->getXML);

    return 1;
}

sub DESTROY {
    my $self = shift;
    
    return undef if (not closelog);

    return 1;
}

1;

__END__
