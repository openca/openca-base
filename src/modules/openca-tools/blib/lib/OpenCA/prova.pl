#!/usr/bin/perl

$|=1;

use OpenCA::Tools;

my $tool = new OpenCA::Tools("GETTEXT" => \&gettext);
if ( not $tool ) {
	print "Error!";
	exit 1;
}

print "\n[ File Tests ]\n";
print "Copying test.pl to pollo.pl ... ";
if( not $tool->copyFiles( SRC=>"test.pl", DEST=>"pollo.pl" ) ) {
	print "Error!\n";
	exit;
}
print "Ok.\n";

print "Moving pollo.pl to tmp/ .... ";
if( not $tool->moveFiles( SRC=>"pollo.pl", DEST=>"tmp/" ) ) {
	print "Error!\n";
	exit;
}
print "Ok.\n";

print "Copying Makefile(s) to tmp/ ... ";
if( not $tool->copyFiles( SRC=>"Make*", DEST=>"tmp" ) ) {
	print "Error!\n";
	exit;
}
print "Ok.\n";

print "Deleting tmp/* ... ";
if( not $tool->deleteFiles( DIR=>"tmp/" ) ) {
	print "Error!\n";
	exit;
}
print "Ok.\n";

print "\n[ Date Tests ]\n";
print "Creating date strings ... ";
$dt1 = $tool->getDate(); ## . " GMT";
sleep 2;
$dt2 = $tool->getDate(); ## . " GMT";
sleep 2;
$dt3 = $tool->getDate(); ## . " GMT";
if( not ( $dt1 and $dt2 and $dt3 ) ) {
	print "Error!\n";
	exit;
}
print "Ok.\n";

print "::: $dt1\n";
print "::: $dt2\n";
print "::: $dt3\n";

print "Checking date compare ... ";
if( $tool->cmpDate( DATE_1=>"$dt1", DATE_2=>"$dt2" ) >= 0 ) {
	print "Error!\n";
	exit;
}
print "Ok.\n";

print "Checking date compare (2) ... ";
if( $tool->cmpDate( DATE_1=>"$dt2", DATE_2=>"$dt1" ) <= 0 ) {
	print "Error!\n";
	exit;
}
print "Ok.\n";

print "Checking period compare ... ";
if( not $tool->isInsidePeriod( DATE=>"$dt2", START=>"$dt1", END=>"$dt3" ) ) {
	print "Error!\n";
	exit;
}
print "Ok.\n";

print "Checking period compare (2) ... ";
if( $tool->isInsidePeriod( DATE=>"$dt1", START=>"$dt2", END=>"$dt3" ) ) {
	print "Error!\n";
	exit;
}
print "Ok.\n";

print "Checking period compare (3) ... ";
if( $tool->isInsidePeriod( DATE=>"$dt3", START=>"$dt1", END=>"$dt2" ) ) {
	print "Error!\n";
	exit;
}
print "Ok.\n";

print "\n[ Misc Tests ]\n";
print "Parsing DN ... ";
$tmp = $tool->parseDN( "/Email=madwolf\@openca.org/CN=Massimiliano Pala, OU=User/OU=Developer, OU=People/ O=org/C=it/" );
if( ($tmp->{O} eq "org") and ( $#{ $tmp->{OU} } == 2 ) ) {
	print "Ok.\n";
} else {
	print "Error!\n";
	exit 1;
}

print "Parsing DN (2) ... ";
$tmp = $tool->parseDN( DN=>"/Email=madwolf\@openca.org/CN=Massimiliano Pala, OU=User/OU=Developer, OU=People/ O=org/C=it/" );
if( ($tmp->{O} eq "org") and ( $#{ $tmp->{OU} } == 2 ) ) {
	print "Ok.\n";
} else {
	print "Error!\n";
	exit 1;
}

## To print each field, simply use a routine like this...
## foreach $key ( keys %$tmp ) {
## 	if( $key eq "OU" ) {
## 		foreach $tmp2 ( @{ $tmp->{$key} } ) {
## 			print "OU=$tmp2\n";
## 		}
## 	} else {
## 		print "$key = $tmp->{$key}\n";
## 	}
## }

print "\nDone.\n\n";

sub gettext
{
    return $_[0];
}

exit 0;
