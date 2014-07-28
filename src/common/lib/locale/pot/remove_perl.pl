#!/usr/bin/perl

my $filename = $ARGV[0];

open FD, $filename or die ("Cannot open $filename.");
my $file = "";
while (<FD>)
{
    $file .= $_;
}
close FD;

# Remove the ?cmd= lines (menu)
$file =~ s/(\#[^\n]*\n)*msgid\s+\"\?cmd=[^\n\"]+\"\s*\nmsgstr\s*\"\"\s*\n/\n/sg;

# Removes the [?]http:// lines
$file =~ s/(\#[^\n]*\n)*msgid\s+\"\?*http[^\n\"]+\"\s*\nmsgstr\s*\"\"\s*\n/\n/sg;

# Removes the error in parsing strings for XML handling (why is that ?)
$file =~ s/(\#[^\n]*\n)*msgid\s+""\n("[^\n]+"\n)+msgstr\s*\"\"\s*\n/\n/sg;

# Removes img= or lnk= wrong strings
$file =~ s/(\#[^\n]*\n)*msgid\s+"\s*(lnk|img)="\s*\nmsgstr\s*\"\"\s*\n/\n/sg;

## $xyz filter
## -----START REGEX-----
## (\n\#[^\n]*)                      --> new line is comment until end of line
## \nmsgid[\s]+                      --> msgid start
##   ("[^\n]*"\s*\n)*                -->   stuff without $
##   "[^\n]*\$[^\n]*"\s*\n           -->   stuff with $
##   ("[^\n]*"\s*\n)*                -->   stuff without $
## msgstr[\s]+("[^\n]*"\s*\n)*       --> msgstr with possibly several lines
## -----END REGEX-----

$file =~ s/(\n\#[^\n]*)*\nmsgid[\s]+("[^\n]*"\s*\n)*"[^\n]*\$[^\n]*"\s*\n("[^\n]*"\s*\n)*msgstr[\s]+("[^\n]*"\s*\n)*//sg;

## @xyz filter
## -----START REGEX-----
## (\n\#[^\n]*)                      --> new line is comment until end of line
## \nmsgid[\s]+                      --> msgid start
##   ("[^\n]*"\s*\n)*                -->   stuff without @
##   "[^\n]*[^\\]\@[^\n]*"\s*\n           -->   stuff with @
##   ("[^\n]*"\s*\n)*                -->   stuff without @
## msgstr[\s]+("[^\n]*"\s*\n)*       --> msgstr with possibly several lines
## -----END REGEX-----

$file =~ s/(\n\#[^\n]*)*\nmsgid[\s]+("[^\n]*"\s*\n)*"[^\n]*[^\\]\@[^\n]*"\s*\n("[^\n]*"\s*\n)*msgstr[\s]+("[^\n]*"\s*\n)*//sg;

## "__XYZ__" filter
## -----START REGEX-----
## (\n\#[^\n]*)                      --> new line is comment until end of line
## \nmsgid[\s]+(""\s*\n)?            --> msgid start with possible nonse
##   "__[A-Z]+__"\s*\n               -->   stuff with variable
## msgstr[\s]+("[^\n]*"\s*\n)*       --> msgstr with possibly several lines
## -----END REGEX-----

$file =~ s/(\n\#[^\n]*)*\nmsgid[\s]+(""\s*\n)?"__[A-Z_]+__"\s*\nmsgstr[\s]+("[^\n]*"\s*\n)*//sg;

## '"?' filter
## this is the typical starting point of an URL
## -----START REGEX-----
## (\n\#[^\n]*)                      --> new line is comment until end of line
## \nmsgid[\s]+                      --> msgid start
##   ("[^\n]*"\s*\n)*                -->   stuff without special content
##   "[^\n]*\"\?[^\n]*"\s*\n       -->   stuff with "?
##   ("[^\n]*"\s*\n)*                -->   stuff without special content
## msgstr[\s]+("[^\n]*"\s*\n)*       --> msgstr with possibly several lines
## -----END REGEX-----

$file =~ s/(\n\#[^\n]*)*\nmsgid[\s]+("[^\n]*"\s*\n)*"[^\n]*\"\?[^\n]*"\s*\n("[^\n]*"\s*\n)*msgstr[\s]+("[^\n]*"\s*\n)*//sg;

## "\r" filter
## this is the typical starting point of an URL
## -----START REGEX-----
## (\n\#[^\n]*)                      --> new line is comment until end of line
## \nmsgid[\s]+                      --> msgid start
##   ("[^\n]*"\s*\n)*                -->   stuff without special content
##   "[^\n]*\\r[^\n]*"\s*\n       -->   stuff with \\r
##   ("[^\n]*"\s*\n)*                -->   stuff without special content
## msgstr[\s]+("[^\n]*"\s*\n)*       --> msgstr with possibly several lines
## -----END REGEX-----

$file =~ s/(\n\#[^\n]*)*\nmsgid[\s]+("[^\n]*"\s*\n)*"[^\n]*\\r[^\n]*"\s*\n("[^\n]*"\s*\n)*msgstr[\s]+("[^\n]*"\s*\n)*//sg;

## "?cmd" filter
## -----START REGEX-----
## (\n\#[^\n]*)                      --> new line is comment until end of line
## \nmsgid[\s]+(""\s*\n)?            --> msgid start with possible nonse
##   "__[A-Z]+__"\s*\n               -->   stuff with variable
## msgstr[\s]+("[^\n]*"\s*\n)*       --> msgstr with possibly several lines
## -----END REGEX-----

# $file =~ s/(\n\#[^\n]*)*\nmsgid[\s]+(""\s*\n)?"\?cmd[^n]*"\s*\nmsgstr[\s]+("[^\n]*"\s*\n)*//sg;

print $file;

1;
