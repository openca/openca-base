## OpenCA::Log.pm 
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

package OpenCA::Log;

use OpenCA::Tools;

our ($errno, $errval);

($OpenCA::Log::VERSION = '$Revision: 1.1.1.1 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

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
    $self->{errno}  = $errno;
    $self->{errval} = $errval;

    print STDERR "PKI Master Alert: Logging error\n";
    print STDERR "PKI Master Alert: Aborting all operations\n";
    print STDERR "PKI Master Alert: Error:   $errno\n";
    print STDERR "PKI Master Alert: Message: $errval\n";
    print STDERR "PKI Master Alert: debugging messages of logging follow\n";
    $self->debug ("setError: errno $errno");
    $self->debug ("setError: errval $errval");

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

    return 1 if (not $self->{DEBUG});

    foreach my $msg (@_) {
        print STDERR "OpenCA::Log->$msg\n";
    }

    return 1;
}

sub new {
    my $that = shift;
    my $class = ref($that) || $that;

    my $self = {
                DEBUG     => 0,
               };

    bless $self, $class;

    my $keys = { @_ };

    ## get crypto backend
    $self->{TOKEN} = $keys->{CRYPTO};
    $self->debug ("token loaded");

    ## get i18n stuff
    $self->{gettext}  = $keys->{GETTEXT};
    $self->{encoding} = $keys->{ENCODING};
    $self->debug ("gettext loaded");

    ## load config
    $self->{configfile} = $keys->{CONFIG};
    $self->{cache}      = $keys->{CACHE};
    $self->debug ("config ready");

    ## determine slots
    my $slot_count = $self->{cache}->get_xpath_count (
                         FILENAME => $self->{configfile},
                         XPATH    => 'log/slots/slot');
    for (my $i=0; $i<$slot_count; $i++)
    {
        $self->debug ("loading slot ...");
        my $name  = $self->{cache}->get_xpath (
                        FILENAME => $self->{configfile},
                        XPATH    => [ 'log/slots/slot', 'name' ],
                        COUNTER  => [ $i, 0 ]);
        my $class = $self->{cache}->get_xpath (
                        FILENAME => $self->{configfile},
                        XPATH    => [ 'log/slots/slot', 'class' ],
                        COUNTER  => [ $i, 0 ]);
        my $level = $self->{cache}->get_xpath (
                        FILENAME => $self->{configfile},
                        XPATH    => [ 'log/slots/slot', 'level' ],
                        COUNTER  => [ $i, 0 ]);
        $self->{CLASS}->{$class}[scalar @{$self->{CLASS}->{$class}}] = $name;
        $self->{LEVEL}->{$level}[scalar @{$self->{LEVEL}->{$level}}] = $name;
        $self->{SLOT}->{$name}->{logger} = $self->{cache}->get_xpath (
                        FILENAME => $self->{configfile},
                        XPATH    => [ 'log/slots/slot', 'logger' ],
                        COUNTER  => [ $i, 0 ]);
        if (not defined $self->{SLOT}->{$name}->{logger})
        {
            return $self->setError (64310022,
                       $self->{gettext} ("OpenCA LOG: There is a log slot without a logger!"));
        }

        ## try to load requested syslog module
        my $syslog_class = "OpenCA::Logger::".$self->{SLOT}->{$name}->{logger};
        eval "require $syslog_class";
        return $self->setError (64310025, $@) if ($@);
        $self->debug ("    loaded class");

        ## try to load parameters
        my @list = (
                    "GETTEXT", $self->{gettext},
                    "name",    $name,
                    "class",   $class,
                    "level",   $level
                   );
        my @known_para = eval ("\@${syslog_class}::CONFIG_PARAMS");
        foreach my $h (@known_para) {
            my $value = $self->{cache}->get_xpath (
                        FILENAME => $self->{configfile},
                        XPATH    => [ 'log/slots/slot', $h ],
                        COUNTER  => [ $i, 0 ]);
            push @list, $h, $value if (defined $value);
        }
        $self->debug ("    name=".$name);
        $self->debug ("    class=".$class);
        $self->debug ("    level=".$level);


        ## try to initialize the module
        $self->{SLOT}->{$name} = eval {$syslog_class->new (@list)};
        $self->debug ("    object result: ".$@);
        $self->debug ("    object errno: ".eval {$syslog_class::errno});
        return $self->setError ($@, $@) if ($@);
        return $self->setError (64310030, $@."(".$syslog_class::errno.")".$syslog_class::errval)
            if (not $self->{SLOT}->{$name} or not ref $self->{SLOT}->{$name});
        $self->debug ("    loaded object");
    }
    $self->debug ("slots loaded");
    foreach my $class (keys %{$self->{CLASS}}) {
        @{$self->{CLASS}->{$class}} = sort @{$self->{CLASS}->{$class}};
    }
    foreach my $level (keys %{$self->{LEVEL}}) {
        @{$self->{LEVEL}->{$level}} = sort @{$self->{LEVEL}->{$level}};
    }
    $self->debug ("slots sorted");

    return $self;
}

sub setEncoding
{
    my $self = shift;
    $self->{encoding} = $_[0];
    return $self->{encoding};
}

sub addMessage {
    my $self = shift;
    my $msg  = $_[0];

    ## set encoding to handle special characters
    $msg->setEncoding ($self->{encoding})
        if (exists $self->{encoding});

    ## determine used slots

    ## build class list
    my @class_list = ();

    push @class_list, @{$self->{CLASS}->{$msg->getClass}}
        if (exists $self->{CLASS}->{$msg->getClass});
    push @class_list, @{$self->{CLASS}->{'*'}}
        if (exists $self->{CLASS}->{'*'});
    @class_list = sort @class_list;

    ## build level list
    my @level_list = ();
    push @level_list, @{$self->{LEVEL}->{$msg->getLevel}}
        if (exists $self->{LEVEL}->{$msg->getLevel});
    push @level_list, @{$self->{LEVEL}->{'*'}}
        if (exists $self->{LEVEL}->{'*'});
    @level_list = sort @level_list;

    ## merge lists
    my @slot_list = ();
    my $class_slot = pop @class_list;
    my $level_slot = pop @level_list;
    while (defined $class_slot and defined $level_slot)
    {
        if ($class_slot > $level_slot) {
            $level_slot = pop @level_list;
        } elsif ($class_slot < $level_slot) {
            $class_slot = pop @class_list;
        } else {
            push @slot_list, $class_slot;
            $level_slot = pop @level_list;
            $class_slot = pop @class_list;
        }
    }
    return $self->setError (64510020,
               $self->{gettext} ("There is no appropriate logger."))
        if (not scalar @slot_list);

    ## sign message if supported
    if ($self->{TOKEN}->keyOnline)
    {
        $msg->setSignature($self->{TOKEN}->sign(DATA => $msg->getXML));
    }

    ## store message in slots
    foreach my $slot (@slot_list) {
        ## add message
        return $self->setError (64510030,
                  $self->{gettext} ("addMessage failed for log slot __SLOT__ (__ERRNO__). __ERRVAL__",
                                    "__SLOT__", $slot,
                                    "__ERRNO__", $self->{SLOT}->{$slot}->errno(),
                                    "__ERRVAL__", $self->{SLOT}->{$slot}->errval()))
            if (not $self->{SLOT}->{$slot}->addMessage ($msg));

        ## get digest from log if supported and
        ## sign digest from log if supported
        if ($self->{SLOT}->{$slot}->getFeatures()->{"LogDigest"} and
            $self->{SLOT}->{$slot}->getFeatures()->{"LogSignature"})
        {
            my $digest    = $self->{SLOT}->{$slot}->getLogDigest();
            my $signature = $self->{TOKEN}->sign(DATA => $digest);
            $self->{SLOT}->{$slot}->addLogSignature($signature);
        }
        
        ## flush log
        $self->{SLOT}->{$slot}->flush;
    }
    return 1;
}

## should be implemented later
sub search {
    my $self = shift;
    my $keys = { @_ };
    my @list = ();
    my @slots = ();

    ## extract parameters
    my $class = $keys->{CLASS};
    my $level = $keys->{LEVEL};
    my $id    = $keys->{SESSION_ID};

    ## find slots which support searching
    foreach my $slot (keys %{$self->{SLOT}})
    {
        push @slots, $slot if ($self->{SLOT}->{$slot}->getFeatures()->{"Search"});
    }

    ## search in every slot
    foreach my $slot (@slots) {
        my @res = ();
        push @res, "CLASS",      $class if (defined $class);
        push @res, "LEVEL",      $level if (defined $level);
        push @res, "SESSION_ID", $id    if (defined $id);
        @res = $self->{SLOT}->{$slot}->search (@res);
        push @list, @res if @res;
    }

    ## order results
    @list = sort @list;

    ## remove duplicates
    my @h_list = @list;
    @list = ();
    foreach my $item (@h_list)
    {
        push @list, $item if ($list[scalar @list -1] ne $item);
    }

    ## return
    return @list;
}

sub getMessage {
    my $self = shift;
    my $id   = shift;
    my @slots = ();

    ## find slots which support getMessage
    foreach my $slot (keys %{$self->{SLOT}})
    {
        push @slots, $slot if ($self->{SLOT}->{$slot}->getFeatures()->{"GetMessage"});
    }

    ## try to get slot
    my ($errno, $errval) = (0, "");
    foreach my $slot (@slots) {
        my $herrno  = $self->{SLOT}->{$slot}->errno();
        my $herrval = $self->{SLOT}->{$slot}->errval();
        my $msg = $self->{SLOT}->{$slot}->getMessage ($id);
        if ($herrno != $self->{SLOT}->{$slot}->errno())
        {
            $errno  = $self->{SLOT}->{$slot}->errno();
            $errval .= $self->{SLOT}->{$slot}->errval();
        }
        return $msg if ($msg);
    }

    ## cannot get message
    return $self->setError ($errno, $errval);
}

sub recovery
{
    my $self = shift;
    my $output_func = shift;
    my @slots = ();
    $self->debug ("recovery: starting recovery");

    ## find slots which support recovery
    foreach my $slot (keys %{$self->{SLOT}})
    {
        push @slots, $slot if ($self->{SLOT}->{$slot}->getFeatures()->{"Recovery"});
    }
    $self->debug ("recovery: determined log slots");

    ## try to get slot
    my ($errno, $errval) = (0, "");
    foreach my $slot (@slots) {
        $self->debug ("recovery: SLOT: $slot");
        my $herrno  = $self->{SLOT}->{$slot}->errno();
        my $herrval = $self->{SLOT}->{$slot}->errval();
        $self->{SLOT}->{$slot}->recovery ($output_func);
        if ($herrno != $self->{SLOT}->{$slot}->errno())
        {
            $errno  = $self->{SLOT}->{$slot}->errno();
            $errval .= $self->{SLOT}->{$slot}->errval();
        }
    }
    $self->debug ("recovery: finished");

    return $self->setError ($errno, $errval)
        if ($errno);

    $self->debug ("recovery: finished successfully");
    return 1;
}

1;
__END__
