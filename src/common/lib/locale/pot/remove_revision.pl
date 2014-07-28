#!/usr/bin/perl

my $filename = $ARGV[0];

open FD, $filename or die ("Cannot open $filename.");
my $file = "";
while (<FD>)
{
    $file .= $_;
}
close FD;

## -----START REGEX-----
## (\n\#[^\n]*)                      --> new line is comment until end of line
## \nmsgid[\s]+"\$Revision:[^\n]\n  --> msgid is a Revision from CVS
## msgstr[\s]+""\n                  --> empty msgstr
## -----END REGEX-----

## #: modules/openca-openssl/OpenSSL.pm:108
## msgid "$Revision: 1.1.1.1 $"
## msgstr ""


$file =~ s/(\n\#[^\n]*)*\nmsgid[\s]+"\$Revision:[^\n]*\nmsgstr[\s]+""\n//sg;

print $file;

1;
