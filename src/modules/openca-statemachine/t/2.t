#!/bin/perl

use strict;
use warnings;
use Test;
use OpenCA::StateMachine;

BEGIN { plan tests => 7 };
ok (1);

## initialize state machine

my $state_machine = new OpenCA::StateMachine (
        "GETTEXT"                     => \&gettext,
        "STATE_LIST_FILE"             => "t/states.txt",
        "FUNCTION_LIST_FILE"          => "t/functions.txt",
        "FUNCTION_DIRECTORY"          => "t/functions",
        "FUNCTION_STATES_FILE_SUFFIX" => "txt",
        "USER_LIST_FILE"              => "t/users.txt",
        "USER_DIRECTORY"              => "t/users",
        "USER_STATE_FILE_NAME"        => "state.txt" ## this is the place of all states of this user
                                             );

if (not $state_machine)
{
    ok (0);
    print STDERR "errno:  ".$OpenCA::StateMachine::errno."\n";
    print STDERR "errval: ".$OpenCA::StateMachine::errval."\n";
    print STDERR "State machine init failed.\n";
    exit 1;
} else {
    ok (1);
}

## load the first cycle

my @result = $state_machine->run();

foreach my $item (@result)
{
    print "User:     ".$item->[0]."\n";
    print "Workflow: ".$item->[1]."\n";
    print "Function: ".$item->[2]."\n";
    print "Theoretical: calling libExecuteCommand (".$item->[2].")\n";
    print "------------------------\n";
}

if (scalar @result == 7)
{
    ok (1);
} else {
    ok (0);
}

## list waiting jobs

my $function = "load_data";
@result = $state_machine->get_users_for_function ($function);
print "\nFunction which checks for new jobs: ".$function."\n";
foreach my $item (@result)
{
    print "User:     ".$item->[0]."\n";
    print "Workflow: ".$item->[1]."\n";
    print "------------------------\n";
}

if (scalar @result == 6)
{
    ok (1);
} else {
    ok (0);
}

## test statesettings

print "\n";
if ($state_machine->set_user_states (
       USER     => "mbell",
       WORKFLOW => "1",
       UNSET    => ["never_used_failure"]))
{
    print "state test: unset doesn't detect irregular state\n";
    ok (0);
} else {
    print "state test: unset correctly detects irregular state\n";
    ok (1);
}

if ($state_machine->set_user_states (
       USER     => "mbell",
       WORKFLOW => "2",
       SET      => ["never_used_regular_state"]))
{
    print "state test: set doesn't detect irregular state\n";
    ok (0);
} else {
    print "state test: set correctly detects irregular state\n";
    ok (1);
}

if ($state_machine->set_user_states (
       USER     => "mbell",
       WORKFLOW => "1",
       UNSET    => ["no_data", "cannot_load_data"],
       SET      => ["data"]))
{
    print "state test: normal operation succeeds\n";
    ok (1);
} else {
    print "state test: normal operation failed\n";
    ok (0);
}

sub gettext
{
    return $_[0];
}

1;
