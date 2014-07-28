## OpenCA::Log::Message.pm 
##
## Copyright (C) 2000-2003 Michael Bell <michael.bell@web.de>
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

## this simple class has only to manage the message itself
## it is used to create correct transformations

package OpenCA::Log::Message;

use XML::Twig;
use POSIX qw(strftime);

our ($errno, $errval);

($OpenCA::Log::Message::VERSION = '$Revision: 1.1.1.1 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

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
        print STDERR "OpenCA::Log::Message->$msg\n";
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

    $self->{HASH} = $self->_parseHash ($keys->{HASHREF})
        if ($keys->{HASHREF});
    return undef
        if ($keys->{XML} and not $self->_parseXML ($keys->{XML}));

    ## prepare class and level
    foreach my $key (keys %{$keys}) {
        $self->{HASH}->{CLASS} = $keys->{$key} if ($key eq "CLASS");
        $self->{HASH}->{LEVEL} = $keys->{$key} if ($key eq "LEVEL");
        $self->{ENCODING}      = $keys->{$key} if ($key eq "ENCODING");
    }

    ## prepare timestamp
    if (not $self->{HASH}->{TIMESTAMP})
    {
        ## we use UTC timestamps because they are unique for all systems
        my $time = time;
        $self->{HASH}->{TIMESTAMP}     = strftime ("%Y-%b-%d %H:%M:%S", gmtime ($time));
        $self->{HASH}->{ISO_TIMESTAMP} = strftime ("%Y-%m-%d %H:%M:%S", gmtime ($time));
        $self->{TIMESTAMP} = $time;
    }

    ## prepare ID
    if (not $self->{HASH}->{ID})
    {
        ## timestamp + 32-digit random
        $self->{HASH}->{ID} = $self->{TIMESTAMP};
        for (my $h=0; $h<32; $h++)
        {
            $self->{HASH}->{ID} .= int (int (rand (10) + 0.5) % 10);
        }
    }

    return $self;
}

sub _parseHash {
    my $self = shift;
    my $hash = shift;

    my $result = undef;
    foreach my $key (keys %{$hash})
    {
        if (ref $key)
        {
            $result->{uc $key} = $self->_parseHash ($hash->{$key});
        } else {
            $result->{uc $key} = $hash->{$key};
        }
    }
    return $result;
}

sub _parseXML {
    my $self = shift;

    ## create XML object
    $self->{twig} = new XML::Twig;
    if (not $self->{twig})
    {
        $self->debug ("XML::Twig cannot be created.");
        $self->setError (6431010, "XML::Twig cannot be created");
        return undef;
    }

    ## parse XML
    if (not $self->{twig}->safe_parse($_[0]))
    {
        my $msg = $@;
        $self->debug ("XML::Twig cannot parse configuration");
        $self->setError (6431020, "OpenCA::Log::Message: XML::Twig cannot parse XML data.".
                           "XML::Parser returned errormessage: $msg"."\n".
                           "XML docmument is like follows: \n".$_[0]);
        return undef;
    }

    ## build hash by recursion
    $self->{HASH} = $self->_parseXMLlevel($self->{twig}->root);

    if (not $self->{HASH})
    {
        $self->setError (6431025, "OpenCA::Log::Message: Cannot build hash from XML document");
        return undef;
    }

    return 1;
}

sub _parseXMLlevel {

    my $self   = shift;
    my $entity = $_[0];
    my $result = undef;

    return $result if (not $entity);

    ## return the content if there are no children
    return $entity->field if ($entity->is_field);

    ## load all childrens of the entity
    my @list = $entity->children;

    foreach my $child (@list)
    {
        $result->{uc ($child->tag)} = $self->_parseXMLlevel ($child);
    }
    return $result;
}

sub getXML {
    my $self = shift;
    my $header = "";
    $header = '<?xml version="1.0" encoding="'.$self->{ENCODING}.'" ?>'."\n"
        if (exists $self->{ENCODING});
    return $header.
           "<log_message>".
           $self->_buildXML ($self->{HASH}, "    ")."\n".
           "</log_message>";
}

sub _buildXML {
    my $self = shift;
    my $ref  = $_[0];
    my $tab  = $_[1];
    my $space = "    ";
    my $xml   = "";

    my @list = keys %{$ref};
    @list = sort @list;

    foreach my $item (@list)
    {
        my $open_tag  = $item;
        my $close_tag = $item;

        ## fix malformed attributes
        $open_tag =~ s/\s+([^=]*)=([^"\s]+)(|\s.*)$/ $1="$2"$3/g; ## adding missing ""

        ## remove attributes from tagname
        $close_tag =~ s/\s.*$//;

        if (ref $ref->{$item})
        {
            my @alist = ($ref->{$item});
            @alist = @{$ref->{$item}}
                if (ref ($ref->{$item}) eq "ARRAY");

            foreach my $aitem (@alist)
            {
                if (ref $aitem)
                {
                    $xml .= "\n".$tab."<".lc $open_tag.">".
                            $self->_buildXML ($aitem, $tab.$space).
                            "\n".$tab."</".lc $close_tag.">";
                } else {
                    $xml .= "\n".$tab."<".lc $open_tag.">".
                            $aitem.
                            "</".lc $close_tag.">";
                }
            }
        } else {
            $xml .= "\n".$tab."<".lc $open_tag.">".
                    $ref->{$item}.
                    "</".lc $close_tag.">";
        }
    }
    return $xml;
}

sub getHash {
    my $self = shift;
    return $self->{HASH};
}

sub setEncoding
{
    my $self = shift;
    $self->{ENCODING} = $_[0];
    return $self->{ENCODING};
}

sub setSignature {
    my $self = shift;
    $self->{HASH}->{SIGNATURE} = $_[0];
    return 1;
}

sub getClass {
    my $self = shift;
    return $self->{HASH}->{CLASS};
}

sub getLevel {
    my $self = shift;
    return $self->{HASH}->{LEVEL};
}

sub getID {
    my $self = shift;
    return $self->{HASH}->{ID};
}

sub getTimestamp {
    my $self = shift;
    return $self->{HASH}->{TIMESTAMP};
}

sub getISOTimestamp {
    my $self = shift;
    return $self->{HASH}->{ISO_TIMESTAMP};
}

sub getSignature {
    my $self = shift;
    return $self->{HASH}->{SIGNATURE};
}

sub getSessionID {
    my $self = shift;
    return $self->{HASH}->{SESSION_ID};
}

sub id2time {
    ## id ::= timestamp + 32-digit random
    my $self = shift;
    my $id = $_[0];
    my $l = length ($id) - 32;

    $id = sprintf ('%.'.$l.'s', $id);
    my $time = strftime ("%Y-%m-%d %H:%M:%S", gmtime ($id));
    return $time if (not wantarray);

    my @list = split /[- :]/, $time;
    return @list;
}

1;
__END__
