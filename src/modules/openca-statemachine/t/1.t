#!/bin/perl

use strict;
use warnings;
use Test;

BEGIN { plan tests => 3 };
ok (1);

if (-e "t/testdata.tar")
{
    ok(1);
} else {
    ok(0);
}

`tar -C t -xf t/testdata.tar`;

if (-e "t/states.txt")
{
    ok(1);
} else {
    ok(0);
}

1;
