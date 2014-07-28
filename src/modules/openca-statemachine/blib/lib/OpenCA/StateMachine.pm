#!/bin/perl

use strict;
use warnings;

package OpenCA::StateMachine;

($OpenCA::StateMachine::VERSION = '$Revision: 1.1.1.1 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg; 

###########################
##  setup state machine  ##
###########################

our ($errno, $errval);

sub new
{
    ## create new object

    my $that = shift;
    my $class = ref($that) || $that;

    my $self = {};
    bless $self, $class;

    my $keys = { @_ };

    ## set global variables
    $self->{GLOBAL_STATE_LIST_FILE}      = "states.list";
    $self->{GLOBAL_FUNCTION_LIST_FILE}   = "functions.list";
    $self->{GLOBAL_FUNCTION_DIRECTORY}   = "functions";
    $self->{FUNCTION_STATES_FILE_SUFFIX} = "states";
    $self->{GLOBAL_USER_DIRECTORY}       = "users";
    $self->{GLOBAL_KEY_DIRECTORY}        = "workflows";
    $self->{USER_STATE_FILE_NAME}        = "states.list";

    ## replace default settings by params
    $self->{gettext} = $keys->{GETTEXT};
    $self->{gettext} = \&i18nGettext if (not defined $self->{gettext});
    $self->{GLOBAL_STATE_LIST_FILE} = $keys->{STATE_LIST_FILE}
        if ($keys->{STATE_LIST_FILE});
    $self->{GLOBAL_FUNCTION_LIST_FILE} = $keys->{FUNCTION_LIST_FILE}
        if ($keys->{FUNCTION_LIST_FILE});
    $self->{GLOBAL_FUNCTION_DIRECTORY} = $keys->{FUNCTION_DIRECTORY}
        if ($keys->{FUNCTION_DIRECTORY});
    $self->{FUNCTION_STATES_FILE_SUFFIX} = $keys->{FUNCTION_STATES_FILE_SUFFIX}
        if ($keys->{FUNCTION_STATES_FILE_SUFFIX});
    $self->{GLOBAL_USER_LIST_FILE} = $keys->{USER_LIST_FILE}
        if ($keys->{USER_LIST_FILE});
    $self->{GLOBAL_USER_DIRECTORY} = $keys->{USER_DIRECTORY}
        if ($keys->{USER_DIRECTORY});
    $self->{USER_STATE_FILE_NAME} = $keys->{USER_STATE_FILE_NAME}
        if ($keys->{USER_STATE_FILE_NAME});

    ## build bitmask for states
    return undef
        if (not $self->build_global_state_bitmask());

    ## build hash with functionnames referenced by bitmasks
    return undef
        if (not $self->build_function_state_bitmask_hash());

    return $self;
}

sub build_global_state_bitmask
{
    my $self = shift;

    ## load file
    my $file = $self->read_file ($self->{GLOBAL_STATE_LIST_FILE});
    return undef if (not defined $file);

    ## build the caseinsensitive bitmask hash

    my @state_list = split /\n/, $file;

    delete $self->{STATE} if (exists $self->{STATE});
    my $bitstring = 0b1; ## binary one
    foreach my $item (@state_list)
    {
        $item =~ s/^\n*\s*//;
        $item =~ s/\s*\n*$//;
        $self->{STATE}->{uc ($item)} = $bitstring;
        $bitstring = $bitstring << 1;
    }

    return 1;
}

sub build_function_state_bitmask_hash
{
    my $self = shift;

    my @list = $self->get_functions();

    ## build a bitmask from a file
    delete $self->{FUNCTION_MASK} if (exists $self->{FUNCTION_MASK});
    foreach my $item (@list)
    {
        $self->{FUNCTION_MASK}->{$item} =
            $self->build_bitmask_from_file (
                $self->{GLOBAL_FUNCTION_DIRECTORY}."/".
                $item.".".$self->{FUNCTION_STATES_FILE_SUFFIX});
        return undef
            if (not defined $self->{FUNCTION_MASK}->{$item});
    }

    return 1;
}

sub get_functions
{
    my $self = shift;

    ## load functionnames
    my $file = $self->read_file ($self->{GLOBAL_FUNCTION_LIST_FILE});
    return undef if (not defined $file);
    my @function_list = split /\n/, $file;
    my @list = ();
    foreach my $item (@function_list)
    {
        $item =~ s/^\n*\s*//;
        $item =~ s/\s*\n*$//;
        push @list, $item;
    }

    return @list;
}

sub get_states
{
    my $self = shift;

    ## load statenames
    my $file = $self->read_file ($self->{GLOBAL_STATE_LIST_FILE});
    return undef if (not defined $file);
    my @state_list = split /\n/, $file;
    my @list = ();
    foreach my $item (@state_list)
    {
        $item =~ s/^\n*\s*//;
        $item =~ s/\s*\n*$//;
        push @list, $item;
    }

    return @list;
}

################################################
##  perform one cycle with the state machine  ##
################################################

sub run {
    my $self = shift;
    return $self->get_next_loop ();
}

sub get_next_loop
{
    my $self = shift;
    my @result = ();

    $self->debug ("run: starting workflow loop");

    ## open user file
    my $FD;
    return $self->set_error (130,
               $self->{gettext} ("Global file with user and process list is missing."))
        if (not open ($FD, $self->{GLOBAL_USER_LIST_FILE}));

    $self->debug ("run: user list file opened");

    my ($user, $key) = $self->get_next_user($FD);
    ## iterate through the users
    while ($user)
    {
        $self->debug ("run: checking $user workflow $key");

        ## calculate the bitmask
        my $bitmask = $self->get_user_state_bitmask ($user, $key);
        return undef if (not defined $bitmask);

        ## try to find a function
        my $function = $self->get_next_function_for_user ($bitmask);

        ## put user and function to result
        if ($function and $bitmask)
        {
            $self->debug ("run: next function is $function");
            push @result, [ $user, $key, $function ];
        } else {
            $self->debug ("run: no next function");
        }

        ## get the next user
        ($user, $key) = $self->get_next_user($FD);
    }

    $self->debug ("run: loops finished");

    ## close user file
    close $FD;

    return @result;
}

sub get_next_user
{
    my $self = shift;
    my $FD   = shift;
    my ($line, $user, $key) = ("", "", "");
    my $char;

    while (read ($FD, $char, 1))
    {
        ## ignore empty lines
        $char = "" if (length ($line) == 0 and $char =~ /\n/i);
        last if ($char =~ /\n/i);
        $line .= $char;
    }
    $self->debug ("get_next_user: line:     $line");
    return () if ($line =~ /^\s*\n*$/);

    ($user, $key) = split /\s+/, $line;

    $self->debug ("get_next_user: user:     $user");
    $self->debug ("get_next_user: workflow: $key");

    return ($user, $key);
}

sub get_user_state_bitmask
{
    my $self = shift;
    my $user = shift;
    my $key  = shift;

    my $file = $self->get_workflow_path ($user, $key)."/".
               $self->{USER_STATE_FILE_NAME};

    return $self->build_bitmask_from_file ($file);
}

sub get_next_function_for_user
{
    my $self    = shift;
    my $bitmask = shift;

    foreach my $key (keys %{$self->{FUNCTION_MASK}})
    {
        my $fmask = $self->{FUNCTION_MASK}->{$key};

        ## 1)  fmask & bitmask   --> parts of fmask are in bitmask
        ## 2)  not fmask and 1)  --> 0 if 1) and fmask are identical
        ##     negate 2)         --> 1 if fmask is in bitmask
        my $mask_1 = $fmask & $bitmask;
        next if (not $mask_1);
        return $key if (not (~$fmask & $mask_1));
    }
    return "";
}

###############################################
##  load the users which wait for an action  ##
###############################################

sub get_users_for_function
{
    my $self     = shift;
    my $function = uc (shift);
    my @result   = ();

    my @list = $self->get_next_loop();

    foreach my $item (@list)
    {
        push @result, [ $item->[0], $item->[1] ]
            if (uc ($item->[2]) eq $function);
    }

    return @result;
}

#####################################
##  change the bitmask for a user  ##
#####################################

sub get_user_states
{
    my $self  = shift;
    my $keys  = { @_ };
    my $user  = $keys->{USER};
    my $key   = ( $keys->{KEY} || $keys->{WORKFLOW} || $keys->{PROCESS} );

    my $filename = $self->get_workflow_path ($user, $key)."/".
                   $self->{USER_STATE_FILE_NAME};

    my $file = $self->read_file ($filename);
    return undef if (not defined $file);
    my @state_list = split /\n/, $file;
    my @list = ();
    foreach my $item (@state_list)
    {
        $item =~ s/^\n*\s*//;
        $item =~ s/\s*\n*$//;
        push @list, $item;
    }

    return @list;
}

sub set_user_states
{
    my $self  = shift;
    my $keys  = { @_ };
    my $user  = $keys->{USER};
    my $key   = ( $keys->{KEY} || $keys->{WORKFLOW} || $keys->{PROCESS} );
    my $set   = $keys->{SET};
    my $unset = $keys->{UNSET};

    ## load bitmask
    my $bitmask = $self->get_user_state_bitmask($user, $key);
    return undef if (not defined $bitmask);

    ## set bitmask bits
    foreach my $bit (@{$set})
    {
        return $self->set_error (141,
                   $self->{gettext} ("The used state __STATE__ is no valid state.",
                                     "__STATE__", $bit))
            if (not defined $self->{STATE}->{uc ($bit)});
        $bitmask = $bitmask | $self->{STATE}->{uc ($bit)};
    }

    ## unset bitmask bits
    foreach my $bit (@{$unset})
    {
        return $self->set_error (151,
                   $self->{gettext} ("The used state __STATE__ is no valid state.",
                                     "__STATE__", $bit))
            if (not defined $self->{STATE}->{uc ($bit)});
        $bitmask = $bitmask & ~$self->{STATE}->{uc ($bit)};
    }

    ## generate state file content
    my $file = "";
    foreach my $state (keys %{$self->{STATE}})
    {
        $file .= $state."\n" if ($bitmask & $self->{STATE}->{$state});
    }

    ## write the new state
    my $filename = $self->get_workflow_path ($user, $key)."/".
                   $self->{USER_STATE_FILE_NAME};
    return $self->write_file ($filename, $file);
}

##############################
##  several help functions  ##
##############################

sub build_bitmask_from_file
{
    my $self = shift;
    my $filename = shift;

    ## load file
    my $file = $self->read_file ($filename);
    if (not defined $file)
    {
        $self->recover_file($filename);
        $file = $self->read_file ($filename);
    }
    return undef if (not defined $file);

    ## build bitmask
    return $self->build_bit_mask ($file);
}

sub build_bit_mask
{
    my $self = shift;
    my $data = shift;

    ## build array
    my @pure_list = split /\n/, $data;

    ## fix array
    my @list = ();
    foreach my $item (@pure_list)
    {
        $item =~ s/^\n*\s*//;
        $item =~ s/\s*\n*$//;
        $item = uc ($item);
        push @list, $item;
    }

    ## build bitmask
    my $bitmask = 0b0; ## binary zero
    foreach my $item (@list)
    {
        ## ignore unknown states
        next if (not exists $self->{STATE}->{$item});
        $bitmask |= $self->{STATE}->{$item};
        return $self->set_error (120,
                   $self->{gettext} ("The state __STATE__ does not exist in the configuration.",
                                     "__STATE__", $item))
            if (not defined $self->{STATE}->{$item});
    }

    $self->debug ("build_bit_mask: $bitmask");
    return $bitmask;
}

sub read_file
{
    my $self     = shift;
    my $filename = shift;

    my $ret = "";

    return $self->set_error (100,
               $self->{gettext} ("Cannot load file __FILENAME__.",
                                 "__FILENAME__", $filename))
        if (not open (FD, $filename));

    while (<FD>) {
        $ret .= $_;
    }

    close FD;
    $self->debug ("read_file: $filename");
    $self->debug ("read_file: $ret");
    return $ret;
}

sub write_file
{
    my $self     = shift;
    my $filename = shift;
    my $content  = shift;

    ## do not change the filehandling
    ## it is securd against OS crashes if journaling file systems are used
    ## (including BSD soft updates)

    ## write new file
    return $self->set_error (140,
               $self->{gettext} ("Cannot open file __FILENAME__ for writing.",
                                 "__FILENAME__", $filename))
        if (not open (FD, ">$filename.new"));
    print FD $content;
    close(FD);

    ## mv original file to old
    `mv $filename $filename.old`;

    ## mv new file to original position
    `mv $filename.new $filename`;

    ## remove old file
    unlink "$filename.old";

    return 1;
}

sub recover_file
{
    my $self     = shift;
    my $filename = shift;
    my $file_ok  = 0;

    ## file itself present?
    $file_ok = 1 if (-e $filename);

    ## new file present
    if (not $file_ok and -e "$filename.new")
    {
        `mv $filename.new $filename`;
        $file_ok = 2;
    }

    ## old file present
    if (not $file_ok and -e "$filename.old")
    {
        `mv $filename.old $filename`;
        $file_ok = 4;
    }

    return undef if (not $file_ok);

    ## cleanup
    unlink "$filename.new";
    unlink "$filename.old";

    return $file_ok;
}

sub set_error
{
    my $self = shift;
    $errno = shift;
    $self->{errno} = $errno;
    $errval = "";
    $errval = shift if (defined $_[0]);
    $self->{errval} = $errval;
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

sub get_user_path
{
    my $self = shift;
    my $user = shift;
    my $path = join ("/", split (/ */, $user));
    return $path;
}

sub get_workflow_path
{
    my $self     = shift;
    my $user     = shift;
    my $workflow = shift;

    my $file = $self->{GLOBAL_USER_DIRECTORY}."/".
               $self->get_user_path ($user)."/".
               "workflows/".
               $workflow;
    return $file;
}

sub debug
{
    my $self = shift;
    print STDERR "OpenCA::StateMachine->".shift()."\n"
        if ($self->{DEBUG});
}

## this function is used top tolerate usage without i18n
sub i18nGettext {

    my $i = 1;
    while ($_[$i]) {
        $_[0] =~ s/$_[$i]/$_[$i+1]/g;
        $i += 2;
    }

    return $_[0];
}

1;
