## OpenCA::Logger::XML.pm 
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

package OpenCA::Logger::XML;

use DB_File;
use OpenCA::Log::Message;

our ($errno, $errval);
our @CONFIG_PARAMS = ( "dir" );

($OpenCA::Logger::XML::VERSION = '$Revision: 1.1.1.1 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

# Preloaded methods go here.

## Create an instance of the Class
sub new {
    my $that = shift;
    my $class = ref($that) || $that;

    my $self = {
                DEBUG     => 0,
                debug_fd  => $STDOUT,
                ## debug_msg => ()
               };

    bless $self, $class;

    my $keys = { @_ };

    ## load config
    foreach my $key (keys %{$keys}) {
        $self->{DIR}     = $keys->{$key} if ($key =~ /DIR/i);
        $self->{gettext} = $keys->{$key} if ($key =~ /GETTEXT/i);
    }

    return $self->setError (6512013, "You must specify a translation function.")
        if (not $self->{gettext});
    return $self->setError (6512010,
               $self->{gettext} ("You must specify the used directory."))
        if (not $self->{DIR});
    return $self->setError (6512011,
               $self->{gettext} ("The specified file must be a directory."))
        if (not -d $self->{DIR});

    return $self;
}

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

    $self->_debug ("setError: errno:  $errno");
    $self->_debug ("setError: errval: $errval");
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

sub getFeatures
{
    return {
            "LogSignature" => 0,
            "LogDigest"    => 0,
            "GetMessage"   => 1,
            "Search"       => 1,
            "Recovery"     => 1,
           };
}

sub addMessage {
    my $self = shift;
    my $msg  = $_[0];

    ## load timestamp
    my $iso = $msg->getISOTimestamp;

    ## parse iso timestamp
    my @time = ($iso =~ /(\d\d\d\d)-(\d\d)-(\d\d)\s*(\d\d):(\d\d):(\d\d)/);

    ## check log-directory
    return $self->setError (6512030,
               $self->{gettext} ("The logging directory doesn't exist."))
        if (not -d $self->{DIR});

    if (not $self->{RECOVERY})
    {
      ## build log path
      my $path = $self->{DIR}."/time";
      foreach my $item (@time)
      {
        $path .= "/".$item;
        my $umask = umask (0022);
        ## this double "not -d $path" is no bug
        ## it is a protection against fast machines and process scheduling
        return $self->setError (6512032,
                   $self->{gettext} ("Cannot create directory __DIR__.",
                                     "__DIR__", $path))
            if (not -d $path and not mkdir $path and not -d $path);
        umask ($umask);
      }

      ## filename now complete
      my $filename = $path."/".$msg->getID.".xml";

      ## write file
      return $self->setError (6512034,
               $self->{gettext} ("Cannot open file __FILENAME__ for writing.",
                                 "__FILENAME__", $filename))
        if (not open FD, ">$filename");
      return $self->setError (6512035,
               $self->{gettext} ("Cannot write to file __FILENAME__.",
                                 "__FILENAME__", $filename))
        if (not print FD $msg->getXML);
      return $self->setError (6512036,
               $self->{gettext} ("Cannot close file __FILENAME__.",
                                 "__FILENAME__", $filename))
        if (not close FD);

      ## create symbolic links
      for (my $h=0; $h < 5; $h++)
      {
        ## remove last directory or filename
        $path     =~ s/\/[^\/]*$//;

        ## create all directory if not present
        my $umask = umask (0022);
        ## this double "not -d $path" is no bug
        ## it is a protection against fast machines and process scheduling
        return $self->setError (6512038,
                   $self->{gettext} ("Cannot create directory __DIR__.",
                                     "__DIR__", $path))
            if (not -d $path."/all" and not mkdir $path."/all" and not -d $path."/all");
        umask ($umask);
        
        ## create dynamic link
        return $self->setError (6512039,
                   $self->{gettext} ("Cannot create directory __DIR__.",
                                     "__DIR__", $path))
            if (not -e $path."/all/".$msg->getID.".xml" and
                not symlink $filename, $path."/all/".$msg->getID.".xml");
      }
    }  ## end of stuff which is not for recovery

    ## add message to class db
    $self->_debug ("addMessage: class: ".$msg->getClass);
    return undef if (not $self->_updateIndex (TYPE => "class",
                                              NAME => $msg->getClass,
                                              ID   => $msg->getID,
                                              REF  => $msg->getISOTimestamp));

    ## add message to level db
    $self->_debug ("addMessage: level: ".$msg->getLevel);
    return undef if (not $self->_updateIndex (TYPE => "level",
                                              NAME => $msg->getLevel,
                                              ID   => $msg->getID,
                                              REF  => $msg->getISOTimestamp));

    ## create start session entry if necessary
    return undef if (not $self->_updateIndex (TYPE => "session",
                                              NAME => "start",
                                              ID   => $msg->getID,
                                              REF  => $msg->getISOTimestamp));

    ## update stop session entry if necessary
    return undef if (not $self->_updateIndex (TYPE => "session",
                                              NAME => "stop",
                                              MODE => "force",
                                              ID   => $msg->getID,
                                              REF  => $msg->getISOTimestamp));

    ## create time reference
    return undef if (not $self->_updateIndex (TYPE => "time",
                                              NAME => "id2time",
                                              ID   => $msg->getID,
                                              REF  => $msg->getISOTimestamp));

    return 1;
}

sub flush {
    return 1;
}

sub getMessage {
    my $self = shift;
    my $id   = shift;

    # my $handle = $self->_openDB (TYPE => "time", NAME => "id2time");
    # return undef if (not $handle);
    # 
    # my $iso = $self->_getDBItem (HANDLE => $handle, ID => $id);
    # return $self->setError (6512051, "The message is not in the database.")
    #     if (not $iso);

    my $iso = OpenCA::Log::Message->id2time ($id);
    return $self->setError (6512051,
               $self->{gettext} ("The time cannot be extracted from the message ID by OpenCA::Log::Message."))
        if (not $iso);

    ## parse iso timestamp
    my @time = ($iso =~ /(\d\d\d\d)-(\d\d)-(\d\d)\s*(\d\d):(\d\d):(\d\d)/);

    ## build log path
    my $filename = $self->{DIR}."/time";
    foreach my $item (@time)
    {
        $filename .= "/".$item;
    }
    $filename .= "/".$id.".xml";
    return $self->setError (6512052,
               $self->{gettext} ("The requested item is not present."))
        if (not -e $filename);

    return $self->_load_message_from_file ($filename);
}

sub search {
    my $self = shift;
    my $keys = { @_ };
    my @session_list = undef;

    $self->_debug ("search: entering search function");

    my $scan_list;
    @{$scan_list} = ();
    $self->_debug ("search: scan_list length: ".scalar @{$scan_list});
    $self->_debug ("search: scanning classes");
    $scan_list->[scalar @{$scan_list}] =
        $self->_search_type (TYPE => "CLASS", NAME => $keys->{CLASS})
        if (defined $keys->{CLASS} and $keys->{CLASS} ne "");
    $self->_debug ("search: scan_list length: ".scalar @{$scan_list});
    $self->_debug ("search: scanning levels");
    $scan_list->[scalar @{$scan_list}] =
        $self->_search_type (TYPE => "LEVEL", NAME => $keys->{LEVEL})
        if (defined $keys->{LEVEL} and $keys->{LEVEL} ne "");
    $self->_debug ("search: scan_list length: ".scalar @{$scan_list});
    $self->_debug ("search: scanning sessions");
    $scan_list->[scalar @{$scan_list}] =
        $self->_search_dynamic (SESSION => $keys->{SESSION_ID})
        if (defined $keys->{SESSION_ID} and $keys->{SESSION_ID} ne "");
    $self->_debug ("search: scan_list length: ".scalar @{$scan_list});

    ## load all items if no class is specified
    $self->_debug ("search: loading all messages if nothing was specified");
    if (not $keys->{LEVEL} and
        not $keys->{CLASS} and
        not $keys->{SESSION_ID})
    {
        $self->_debug ("search: loading all messages");
        my $msg = undef;
        while (($msg = $self->_get_next_message ($msg)))
        {
            push @{$scan_list->[0]}, $msg->getID;
        }
        # my $handle = $self->_openDB (TYPE => "TIME", NAME => "id2time");
        # return undef if (not $handle);
        # @{$scan_list->[0]} = sort $self->_loadDB ($handle);
        $self->_debug ("search: loaded array")
            if ($scan_list->[0]);
    }

    ## merge lists
    $self->_debug ("search: scan_list length: ".scalar @{$scan_list});
    $self->_debug ("search: reference ".$scan_list->[0]);
    $self->_debug ("search: array ".@{$scan_list->[0]});
    $self->_debug ("search: scan_list length: ".scalar @{$scan_list});
    $self->_debug ("search: setting first result list");
    my @list = @{$scan_list->[0]};
    $self->_debug ("search: merging results if necessary");
    if (scalar @{$scan_list} > 1)
    {
        for (my $i=1; $i < scalar @{$scan_list}; $i++)
        {
             $self->_debug ("search: real merging");
             @list = $self->_merge_lists (\@list, $scan_list->[$i]);
        }
    }

    ## return result
    $self->_debug ("search: returning results");
    return @list;
}

sub _updateIndex {

    my $self = shift;
    my $keys = { @_ };
    my $type = $keys->{TYPE};
    my $name = $keys->{NAME};
    my $id   = $keys->{ID};
    my $ref  = $keys->{REF};
    my $mode = $keys->{MODE};

    ## open and perhaps create index
    my $db_h = $self->_openDB (TYPE => $type, NAME => $name);
    return undef if (not $db_h);

    ## check for already present item
    if (not $mode or $mode !~ /force/i)
    {
        my $item = $self->_getDBItem (HANDLE => $db_h, ID => $id);
        return 1 if ($item);
    }

    ## insert item id + iso_timestamp
    return $self->setError (6512078,
               $self->{gettext} ("Cannot update index __NAME__ __TYPE__ (__ERRNO__). __ERRVAL__",
                                 "__NAME__", $name,
                                 "__TYPE__", $type,
                                 "__ERRNO__", $self->errno,
                                 "__ERRVAL__", $self->errval))
        if (not $self->_insertDBItem (HANDLE => $db_h, ID => $id, REF => $ref));

    return 1;
}

sub _openDB {
    my $self = shift;
    my $keys = { @_ };
    my $type = $keys->{TYPE};
    my $name = $keys->{NAME};

    my $filename = $self->{DIR}."/".lc $type."/".lc $name.".dbm";

    return $self->{HANDLE_CACHE}->{$filename}
        if (exists $self->{HANDLE_CACHE} and
            exists $self->{HANDLE_CACHE}->{$filename});

    my %h;
    my $handle = tie %h, "DB_File", $filename, O_CREAT|O_RDWR, 0644, $DB_BTREE ;

    return $self->setError (6512042,
               $self->{gettext} ("Cannot open database __FILE__.",
                                 "__FILE__", $filename))
        if (not $handle);

    ## cashing handles
    $self->{HANDLE_CACHE}->{$filename} = $handle;

    return $handle;
}

sub _getDBItem {
    my $self = shift;
    my $keys = { @_ };
    my $handle = $keys->{HANDLE};
    my $id     = $keys->{ID};

    my $item;
    return $item if (not $handle->get ($id, $item));
    return undef;  ## item not present in DB
}

sub _loadDB {
    my $self   = shift;
    my $handle = shift;
    my @list = ();

    my ($key, $value) = (0, 0);
    for (my $status = $handle->seq($key, $value, R_FIRST) ;
            $status == 0 ;
            $status = $handle->seq($key, $value, R_NEXT) )
    {
        push @list, $key;
    }

    return @list;
}

sub _insertDBItem {
    my $self = shift;
    my $keys = { @_ };
    my $handle = $keys->{HANDLE};
    my $id     = $keys->{ID};
    my $ref    = $keys->{REF};

    $handle->put (sprintf ("%s", $id), $ref, R_NOOVERWRITE);
    return $self->setError (6512044,
               $self->{gettext} ("Cannot insert __ID__ to database.",
                                 "__ID__", $id))
        if (not $self->_getDBItem (HANDLE => $handle, ID => $id));

    return 1;
}

sub _closeDB {
    my $self   = shift;
    my $handle = shift;

    undef $handle;

    return 1;
}

sub _merge_lists
{
    my $self = shift;
    my $a1   = $_[0];
    my $a2   = $_[1];
    my @list = ();

    my $item1 = pop @{$a1};
    my $item2 = pop @{$a2};
    while (defined $item1 and defined $item2)
    {
        if ($item1 > $item2)
        {
            $item2 = pop @{$a2};
        } elsif ($item1 < $item2) {
            $item1 = pop @{$a1};
        } else {
            push @list, $item1;
            $item1 = pop @{$a1};
            $item2 = pop @{$a2};
        }
    }
    $self->_debug ("_merge_lists: result list");
    foreach my $item (@list)
    {
        $self->_debug ("_merge_lists: item: $item");
    }
    return @list;
}

sub _search_type
{

    ## use only array references !!!
    ## undef only works with references not with arrays

    my $self = shift;
    my $keys = { @_ };
    my $type = $keys->{TYPE};
    my $name = $keys->{NAME};
    my @result = ();

    return undef if (not defined $keys->{TYPE} or
                     not defined $keys->{NAME} or
                     $keys->{TYPE} eq ""       or
                     $keys->{NAME} eq "");

    $self->_debug ("_search_type: type: ".$type);
    $self->_debug ("_search_type: name: ".$name);

    ## fix regex
    $name =~ s/[%*]/.*/g;
    $self->_debug ("_search_type: fixed name: ".$name);

    ## determine databases
    my $dir = $self->{DIR}."/".lc $type;
    opendir DIR, $dir;
    my @dir_list = readdir DIR;
    closedir DIR;
    my $names = undef;
    foreach my $dir (@dir_list)
    {
        next if ($dir =~ /^(\.\.|\.)$/);
        next if ($dir !~ /$name/);
        $self->_debug ("_search_type: accepted database: $dir");
        push @{$names}, $dir;
    }

    my @list;
    foreach my $item (@{$names})
    {
        next if (not $item);
        $self->_debug ("_search_type: loading file: ".$item);
        $item =~ s/.dbm$//;
        $self->_debug ("_search_type: loading database: ".$item);
        my $handle = $self->_openDB (TYPE => $type, NAME => $item);
        return undef if (not $handle);
        @list = sort $self->_loadDB ($handle);
        $self->_debug ("_search_type: database items ".scalar @list);
        if (not @result)
        {
            $self->_debug ("_search_type: result undefined");
            @result = @list;
        } else {
            $self->_debug ("_search_type: result defined");
            @result = @{$self->_merge_lists (\@result, \@list)};
        }
    }
    if (@result)
    {
        $self->_debug ("_search_type: result list ".scalar @result);
        foreach my $item (@result)
        {
            $self->_debug ("_search_type: item: $item");
        }
    } else {
        $self->_debug ("_search_type: result list is empty");
    }

    $self->_debug ("_search_type: returning");
    return \@result;
}

sub _search_dynamic
{
    my $self   = shift;
    my $keys   = { @_ };
    my $result = undef;
    $self->_debug ("_search_dynamic: starting dynamic attribute based search");
    $self->_debug ("_search_dynamic: SESSION: ".$keys->{SESSION});

    ## scan all messages
    my $msg = undef;
    while (($msg = $self->_get_next_message ($msg)))
    {
        $self->_debug ("_search_dynamic: scanning message ".$msg->getID);

        ## check parameter
        if ($keys->{SESSION})
        {
            push @{$result}, $msg->getID()
                if ($msg->getSessionID() eq $keys->{SESSION});
        } else {
            ## unknow search type --> return all
            push @{$result}, $msg->getID();
        }

        $self->_debug ("_search_dynamic: message scanned");
    }

    ## return result 
    $self->_debug ("_search_dynamic: returning result");
    return $result;
}

sub _get_next_message
{
    my $self = shift;
    $self->_debug ("_get_next_message: starting next");
    return $self->_get_first_message if (not $_[0]);

    my $msg = shift;
    my $next_id = undef;

    $self->_debug ("_get_next_message: get and split iso time");
    my $iso = $msg->getISOTimestamp;
    my @time = ($iso =~ /(\d\d\d\d)-(\d\d)-(\d\d)\s*(\d\d):(\d\d):(\d\d)/);

    ## try to get next message from current dir

    $self->_debug ("_get_next_message: try to find next in current dir");
    my $filename = $self->{DIR}."/time/".join "/", @time;
    $self->_debug ("_get_next_message: current dir ".$filename);
    $self->_debug ("_get_next_message: current id ".$msg->getID);
    $next_id = $self->_get_next_id_in_dir ($msg->getID, $filename);
    return $self->_load_message_from_file ($filename."/$next_id.xml")
        if (defined $next_id);

    ## go to the next directory

    ## go up
    $self->_debug ("_get_next_message: actual dir".join "/", @time);
    $self->_debug ("_get_next_message: go up until newer dir found");
    my $i;
    my $old_time;
    for ($i=4; $i > -2; $i--)
    {
        $self->_debug ("_get_next_message: scan level: $i");
        $self->_debug ("_get_next_message: old dir: ".$time [$i+1]);
        $old_time = $time [$i+1];

        ## build dirname
        my $filename = $self->{DIR}."/time";
        for (my $k=0; $k < $i+1; $k++)
        {
            $filename .= "/".$time[$k];
        }

        ## load dirs
        my @dirs = sort $self->_get_numeric_directories ($filename);

        ## check for bigger one
        foreach my $dir (@dirs)
        {
            $self->_debug ("_get_next_message: verify dir $dir");
            next if ($dir le $time[$i+1]);
            $self->_debug ("_get_next_message: accepted dir $dir");
            $time [$i+1] = $dir;
            last;
        }
        last if ($time [$i+1] ne $old_time);
    } 
    return undef if ($i == -2);
    $self->_debug ("_get_next_message: actual dir".join "/", @time);

    ## go down
    $self->_debug ("_get_next_message: actual level ".$i+2);
    $self->_debug ("_get_next_message: go down to oldest dir");
    for ($i=$i+2; $i < 6; $i++)
    {
        ## build dirname
        my $filename = $self->{DIR}."/time";
        for (my $k=0; $k < $i; $k++)
        {
            $filename .= "/".$time[$k];
        }

        ## load dirs and take smallest one
        my @dirs = sort $self->_get_numeric_directories ($filename);
        $time [$i] = $dirs[0];
    }

    ## get smallest message ID
    $self->_debug ("_get_next_message: get oldest file");
    my $filename = $self->{DIR}."/time/".join "/", @time;
    opendir DIR, $filename;
    my @dir_list = sort grep /^\d+\.xml$/, readdir DIR;
    closedir DIR;
    return $self->_load_message_from_file ($filename."/".$dir_list[0]);
}

sub _get_next_id_in_dir
{
    my $self = shift;
    my $id   = shift;
    my $filename = shift;

    ## loaddir
    opendir DIR, $filename;
    my @dir_list = sort grep /^\d+\.xml$/, readdir DIR;
    closedir DIR;
    
    ## remove all previous and the message itself
    foreach my $item (@dir_list)
    {
        $self->_debug ("_get_next_id_in_dir: checking $item");
        $item =~ s/\.xml$//;
        return $item if ($item > $id);
    }

    return undef;
}

sub _get_first_message
{
    my $self = shift;

    my $filename = $self->{DIR}."/time";
    for (my $i=0; $i < 6; $i++)
    {
        my @list = sort $self->_get_numeric_directories($filename);
        $filename .= "/".$list [0];
    }

    opendir DIR, $filename;
    my @dir_list = sort grep /^\d+\.xml$/, readdir DIR;
    closedir DIR;
    $self->_debug ("_get_first_message: ".$filename."/".$dir_list[0]);
    return $self->_load_message_from_file ($filename."/".$dir_list[0]);
}

sub _get_numeric_directories
{
    my $self = shift;
    return undef if (not defined $_[0]);

    my $dir = shift;
    opendir DIR, $dir;
    my @list = readdir DIR;
    closedir DIR;
    my $result = undef;
    foreach my $item (@list)
    {
        next if ($item !~ /^\d*$/);
        $self->_debug ("_get_numeric_directories: dir: ".$item);
        push @{$result}, $item;
    }

    return sort @{$result};
}

sub _load_message_from_file
{
    my $self     = shift;
    my $filename = shift;

    ## read file
    my $file = "";
    return $self->setError (6512054,
               $self->{gettext} ("Cannot open file __FILENAME__ for writing.",
                                 "__FILENAME__", $filename))
        if (not open FD, "$filename");
    while ( <FD> ) {
        $file .= $_;
    };
    return $self->setError (6512056,
               $self->{gettext} ("Cannot close file __FILENAME__.",
                                 "__FILENAME__", $filename))
        if (not close FD);

    ## build message
    my $msg = OpenCA::Log::Message->new (XML => $file);
    return $self->setError ($OpenCA::Log::Message::errno, $OpenCA::Log::Message::errval)
        if (not $msg);

    return $msg;
}

sub recovery
{
    my $self        = shift;
    my $output_func = shift;
    $self->_debug ("recovery: Starting recovery");

    ## close all cached file handles

    foreach my $filename (keys %{$self->{HANDLE_CACHE}})
    {
        $self->_closeDB ($self->{HANDLE_CACHE}->{$filename});
        delete $self->{HANDLE_CACHE}->{$filename};
    }
    $self->_debug ("recovery: closed all database handles");

    ## remove all existing index databases

    my $file_search = "find ".$self->{DIR}." -name \*.dbm -print";
    my $dbm_files = `${file_search}`;
    $self->_debug ("recovery: index files: ${dbm_files}");
    my @paths = split /[\s\n]+/, $dbm_files;
    foreach my $file (@paths)
    {
        unlink ($file);
    }
    $self->_debug ("recovery: removed all index databases");

    ## move the original directory to another place

    $self->{RECOVERY} = 1;

    ## load every message and insert it to the index database

    if ($self->_recover_dir (DIR             => $self->{DIR}."/time",
                             OUTPUT_FUNCTION => $output_func))
    {
        $self->_debug ("recovery: Finished successfully");
        return 1;
    } else {
        $self->_debug ("recovery: Recovery finally failed");
        return undef;
    }
}

sub _recover_dir
{
    my $self  = shift;
    my $keys  = { @_ };
    my $dir   = $keys->{DIR};
    my $level = 0;
    $self->_debug ("recover_dir: Recover directory $dir");

    ## print status information

    if (exists $keys->{OUTPUT_FUNCTION})
    {
        my $path = $keys->{DIR};
        $path =~ s/$self->{DIR}//;
        $path =~ s/^\///;
        $self->_debug ("recover_dir: time path is $path");
        my @levels = split /\/+/, $path;
        if (scalar @levels <= 4)
        {
            my $output = "";
            $output .= $levels[1] if (exists $levels[1]);
            $output .= "-".$levels[2] if (exists $levels[2]);
            $output .= "-".$levels[3] if (exists $levels[3]);
            print $keys->{OUTPUT_FUNCTION} ($output) if ($output);
            $self->_debug ("recover_dir: output: $output");
        }
    }
    $self->_debug ("recover_dir: output function initialized");

    ## does this be the last level of the hierarchy?

    opendir DIR, $dir;
    my @full_list = readdir DIR;
    my @list      = grep /.xml$/, @full_list;
    closedir DIR;
    $self->_debug ("recover_dir: Scanned directory");

    if (scalar @list)
    {
        ## here we find the messages

        $self->_debug ("recover_dir: recover messages ...");
        foreach my $file (sort @list)
        {
            next if ($file !~ /\.xml$/);
            $file =~ s/\.xml$//;
            $self->_debug ("recover_dir: message ID $file");
            my $msg = $self->getMessage($file);
            return undef if (not $msg);
            return undef if (not $self->addMessage($msg));
        }

    } else {
        ## ok let's dive in the hierarchy

        $self->_debug ("recover_dir: recover directories ...");

        foreach my $file (sort @full_list)
        {
            next if ($file =~ /^\.|\.\.|all$/);
            next if (not -d $dir."/".$file);
            $self->_debug ("recover_dir: directory $dir/$file");
            return undef
                if (not $self->_recover_dir (DIR             => "$dir/$file",
                                             OUTPUT_FUNCTION => $keys->{OUTPUT_FUNCTION}));
        }
    }

    $self->_debug ("recover_dir: recovery completed for $dir");

    return 1;
}

sub _debug
{
    my $self = shift;

    return if (not $self->{DEBUG});

    print STDERR "OpenCA::Logger::XML->".$_[0]."\n";
}

sub DESTROY
{
    my $self = shift;
    foreach my $filename (keys %{$self->{HANDLE_CACHE}})
    {
        $self->_closeDB ($self->{HANDLE_CACHE}->{$filename});
    }
}

1;

__END__
