## OpenCA::Logger::Syslog::Sys.pm 
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

package OpenCA::Logger::Syslog::Sys;

use Sys::Syslog qw(:DEFAULT setlogsock);

($OpenCA::Logger::Syslog::Sys::VERSION = '$Revision: 1.2 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

# Preloaded methods go here.

## Create an instance of the Class
sub new {
    my $that = shift;
    my $class = ref($that) || $that;

    my $self = {};

    bless $self, $class;

    my $keys = { @_ };

    ## load config
    $self->{prefix}      = $keys->{prefix};
    $self->{socket_type} = 'unix';
    $self->{socket_type} = $keys->{socket_type} if $keys->{socket_type};
    $self->{facility}    = $keys->{facility};

    my $header = "OpenCA MASTER ALERT: OpenCA::Logger::Syslog::Sys";

    if (not setlogsock $self->{socket_type}) {
        print STDERR "$header: Cannot set the logging socket (socket_type: ".
                     $self->{socket_type}.")\n";
        return undef;
    }

    if (not openlog $self->{prefix}, 'pid,perror,ndelay', $self->{facility})
    {
        print STDERR "$header: Cannot open the logging system\n";
        print STDERR "$header: ident: ".$self->{prefix}."\n";
        print STDERR "$header: logopt: pid,perror,ndelay\n";
        print STDERR "$header: facility: ".$self->{facility}."\n";
        return undef;
    }

    return $self;
}

sub addMessage {
    my $self     = shift;
    my $msg      = $_[0];

    if (not ref $msg) {
        print STDERR "OpenCA::Logger::Syslog::Sys: Cannot add message because no message was specified.\n";
        return 1;
    }

    ## fix level

    my $level = $msg->getLevel();
    if (not $level)
    {
        $level = "crit";
        print STDERR "OpenCA::Logger::Syslog::Sys: Using syslog priority ".
			" CRIT because no level was specified.\n";
    }

    ## build priority

    $_ = $level;
    SWITCH : {
        $self->{priority} = "";
        $self->{priority} .= "|emerg"   if (/EMERG/i);
        $self->{priority} .= "|alert"   if (/ALERT/i);
        $self->{priority} .= "|crit"    if (/CRIT/i);
        $self->{priority} .= "|err"     if (/ERR/i);
        $self->{priority} .= "|warning" if (/WARNING/i);
        $self->{priority} .= "|notice"  if (/NOTICE/i);
        $self->{priority} .= "|info"    if (/INFO/i);
        $self->{priority} .= "|debug"   if (/DEBUG/i);
    }
    $self->{priority} =~ s/^\|//;

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
