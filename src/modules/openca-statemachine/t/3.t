#!/bin/perl

use strict;
use warnings;
use Test;
use OpenCA::StateMachine;

BEGIN { plan tests => 6 };
ok (1);

## initialize state machine

my $state_machine = new OpenCA::StateMachine (
        "GETTEXT"                    => \&gettext,
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

## test performance

print STDERR "\nPerformancetest:\n";
print STDERR "<------------------------- test length ---------------------------------------->\n\n";
my $runs  = 10000;
my $limit = 125;

## testing the performance of the normal engine

print STDERR "$runs iterations on a directory path depth of 6.5\n";
my $start = time();
my @workflows;
for (my $i=0; $i<$runs; $i++)
{
    @workflows = $state_machine->run();
    print_hash_mark ($i, $limit);
}
my $stop = time();
print STDERR "\n";
print STDERR "Workflows:       ".@workflows."\n";
print STDERR "Actions:         ".@workflows * $runs."\n";
print STDERR "Time [seconds]:  ".($stop - $start)."\n";
print STDERR "Throughput:      ".@workflows * $runs / ($stop - $start)."\n";
if (@workflows * $runs / ($stop - $start) > 1000)
{
    ok (1);
} else {
    ok (0);
}

## testing the correct search for a special function

print STDERR "\n$runs checks for the waiting jobs with a directory path depth of 6.5\n";
$start = time();
for (my $i=0; $i<$runs; $i++)
{
    @workflows = $state_machine->get_users_for_function("load_data");
    print_hash_mark ($i, $limit);
}
$stop = time();
print STDERR "\n";
print STDERR "Workflows:       ".@workflows."\n";
print STDERR "Waiting Actions: ".@workflows * $runs."\n";
print STDERR "Time [seconds]:  ".($stop - $start)."\n";
print STDERR "Throughput:      ".@workflows * $runs / ($stop - $start)."\n";
if (@workflows * $runs / ($stop - $start) > 1000)
{
    ok (1);
} else {
    ok (0);
}

## test the search for a function with no waiting jobs
## (because the function doesn't exist in the model)

print STDERR "\n$runs checks for the waiting jobs with a directory path depth of 6.5\n";
$start = time();
for (my $i=0; $i<$runs; $i++)
{
    @workflows = $state_machine->get_users_for_function("non_existing_function");
    print_hash_mark ($i, $limit);
}
$stop = time();
print STDERR "\n";
print STDERR "Workflows:       ".@workflows."\n";
print STDERR "Waiting Actions: ".@workflows * $runs."\n";
print STDERR "Time [seconds]:  ".($stop - $start)."\n";
print STDERR "Throughput:      ".@workflows * $runs / ($stop - $start)."\n";
if (@workflows == 0)
{
    ok (1);
} else {
    ok (0);
}
if ($stop - $start < 60)
{
    ok (1);
} else {
    ok (0);
}

print "\n";

sub print_hash_mark
{
    my $pos   = shift;
    my $limit = shift;

    print STDERR "#" if (($pos % $limit) == 0);
}

sub gettext
{
    return $_[0];
}

1;
