#!/bin/perl

use strict;
use warnings;
use Test;

BEGIN { plan tests => 4 };
ok (1);

if (-e "t/testdata.tar")
{
    ok(1);
} else {
    ok(0);
}

`cd t; rm -rf functions functions.txt states.txt users users.txt`;

if (-e "t/states.txt")
{
    ok(0);
} else {
    ok(1);
}

if (-e "t/testdata.tar")
{
    ok(1);
} else {
    ok(0);
}

1;
