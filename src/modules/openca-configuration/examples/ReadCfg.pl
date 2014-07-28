#!/usr/bin/perl

## Configuratio Read Program ( Example )
## (c) 1998 by Massimiliano Pala
## All Rights Reserved
##
## DISC CLAIMER: THIS SOFTWARE IS GIVEN AS IS WITHOUT ANY WARRANTIES
## ABOUT ANY DAMAGE DERIVED BY THE USE ( CORRECT OR NOT ) OF THIS
## SOFTWARE. THE AUTHOR IS THEREFORE NOT RESPONSABLE IN ANY WAY OF
## DAMAGES RELATED IN ANY WAY TO THIS OR SUPPORTED SOFTWARE AS WELL.
##
## If you want to contact me (the author) please use the e-mail
## addresses listed below. Do not esitate in reporting bugs, enhancement
## or anything seems useful in developing this software:
##
##	madwolf@comune.modena.it
##	m.pala@mo.nettuno.it
##	digid@netscape.net

## Thank you for using this software, and remember that Open Projects
## are the future of mankind. Do not sleep, partecipate to world wide
## efforts to make life easier for all!

## Base requirements
require 5.001;

## Define Program Version
$VERSION = '1.00';

## Modules to be installed to have this program to work properly
use OpenCA::Configuration;

## Generate a new reference to Configuration ( instance )
my $config = new OpenCA::Configuration;

## ReadCfg Notice
print "\nRead Configuration Example Program - Version $VERSION\n";
print "Copyright (c) 1999 by Massimiliano Pala\n";
print "(OpenCA/Configuration module version " . $config->getVersion() .")\n\n";

## Let's load our default configuration
print "Loading Configuration File ... ";
if( $config->loadCfg("RegAuth.conf") == -1 ) {
	print "error.\n\nError in loading Configuration file!\n\n";
	exit 100;
}
print "Ok.\n";

## Main Section
## ============

print "Use CTRL-D to Exit Program.\n\n";

print "Enter the Parameter Name to Search for: ";
while ( $line = <STDIN> ) {
	chop($line);
	next unless $line;

	print "Searching for $line ... ";
	$k = $config->getParam( $line );
	if( not ( keys %$k ) ) {
		print "Not Found!\n\n";
		print "Enter the Parameter Name to Search for: ";
		next;
	} else {
		print "Found!\n\n";
	};

	foreach $key ( keys %$k ) {
                print "Key: $key ( $#{ $k->{$key} } )\n";
                if ( $#{ $k->{$key}} < 0 ) {
                        print "Value :" . $k->{$key};
                } else {
                        print "Values: ";
                        foreach $val ( 0 .. $#{ $k->{$key}} ) {
                                print " $k->{$key}[$val]";
                        };
                };
                print "\n\n";
        }
	print "Enter the Parameter Name to Search for: ";
}

print "\n\nThank you for using OpenCA software.\n\n";

exit 0;
