## OpenCA::Logger::Syslog::Net.pm 
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

package OpenCA::Logger::Syslog::Net;

($OpenCA::Logger::Syslog::Net::VERSION = '$Revision: 1.1.1.1 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

use Net::Syslog;

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
    $self->{facility} = $keys->{facility};

    $self->{syslog} = new Net::Syslog(
                             Name     => $self->{prefix},
                             Host     => $self->{host},
                             Port     => $self->{port},
                             Facility => $self->{facility},
                            );
    return undef if (not $self->{syslog});

    return $self;
}

sub addMessage {
    my $self = shift;
    my $msg  = $_[0];

    ## build priority
    $_ = $msg->getLevel;
    SWITCH : {
        $self->{priority} = "emerg"   if (/EMERG/i);
        $self->{priority} = "alert"   if (/ALERT/i);
        $self->{priority} = "crit"    if (/CRIT/i);
        $self->{priority} = "err"     if (/ERR/i);
        $self->{priority} = "warning" if (/WARNING/i);
        $self->{priority} = "notice"  if (/NOTICE/i);
        $self->{priority} = "info"    if (/INFO/i);
        $self->{priority} = "debug"   if (/DEBUG/i);
    }

    return undef
        if (not $self->{syslog}->send ($msg->getXML, Priority => $self->{priority}));

    return 1;
}

1;

__END__
