#!/bin/perl

my $filename = $ARGV[0];
my $file = "";
open FD, $filename or die "Cannot open file $filename\n";
while (<FD>)
{
    $file .= $_;
}
close FD;

my @lines = split /\n/, $file;
@lines = sort @lines;
$file = join "\n", @lines;

print $file."\n";
