#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
use OpenCA::X509;
use OpenCA::CRL;
use OpenCA::REQ;
use OpenCA::DBI;

my $openssl = new OpenCA::OpenSSL;
my @tmpfiles = ("cert.pem","priv.key","req.pem");

print "Initializing crypto shell ... \n";
$openssl->setParams ( SHELL=>"/usr/bin/openssl",
		      CONFIG=>"/usr/local/OpenCA/stuff/openssl.cnf" );
		      # CONFIG=>"/etc/ssl/openssl.cnf" );

$openssl->setParams ( STDERR => "/dev/null" );

print "Generating a 512 bit priv Key ...\n";
if( not $openssl->genKey( BITS=>512, OUTFILE=>"priv.key" ) ) {
 	print "Error\n";
}

print "Generating a Request file ... \n";
$openssl->genReq( OUTFILE=>"req.pem", KEYFILE=>"priv.key",
 		DN=>["", "", "", "CA", "", "Massimiliano Pala", "madwolf\@openca.org", "", "" ] );

print "Generating a CA certificate ... \n";
$p = $openssl->genCert( KEYFILE=>"priv.key", REQFILE=>"req.pem", DAYS=>150,
			OUTFILE=>"cert.pem");

print "Creating a new X509 object ... \n";
my $X509 = new OpenCA::X509( INFILE  => "cert.pem",
                             GETTEXT => \&gettext, 
			     FORMAT  => "PEM",
                             SHELL   => $openssl);

print " * Serial: " . $X509->getParsed()->{SERIAL} . "\n";
print " * Version: " . $X509->getParsed()->{VERSION} . "\n";
print " * Modulus: " . $X509->getParsed()->{MODULUS} . "\n";
print " * Exponent: " . $X509->getParsed()->{EXPONENT} . "\n";

print "Creating a new CRL Object ... \n";
my $CC = new OpenCA::CRL( SHELL   => $openssl, 
                          GETTEXT => \&gettext, 
                          CACERT  => "cert.pem",
			  CAKEY   => "priv.key", 
                          PASSWD  => "");
if( not $CC ) {
	print "Error!\n";
}

# my $db = new OpenCA::DB( SHELL=>$openssl, DB_DIR=>"db" );
my $db = new OpenCA::DBI( SHELL=>$openssl,
                         GETTEXT    => \&gettext, 
                         remoteType => "Pg",
                         remoteHost => "192.168.1.3",
                         remotePort => "5432",
                         remoteName => "opencasu",
                         remoteUser => "opencasu",
                         remotePassphrase => "opencasu",
                         failsafe => "off",
                         second_chance => "no",
                         mode => "ultra-secure",
                         DEBUG => 1);

if( not $db ) {
        print "new not ok\n";
        exit 1;
}

print "My class initializes correctly!\n";

$rv = $db->initDB (MODE=> "FORCE_ALL");
if ($rv < 0) {
        print "initDB returns negative\n";
}

print "Storing Request ... \n";
my $r = new OpenCA::REQ( SHELL   => $openssl, 
                         FORMAT  => "PEM", 
                         GETTEXT => \&gettext, 
                         INFILE  => "req.pem",
 		         DN      => ["", "", "", "CA", "", 
                                     "Massimiliano Pala", 
                                     "madwolf\@openca.org", "", "" ],
                         KEYFILE => "priv.key" );
if (not $r) {
	print "new OpenCA::REQ failed\n";
       	exit 1;
}

$rv = $db->storeItem( DATATYPE=>PENDING_REQUEST, OBJECT=>$r,
                      CERT_FILE=>"cert.pem", KEY_FILE=>"priv.key", PWD=>"" );

if( (not $rv ) or ($rv < 0)) {
  	print "13 ....... not ok 13\n";
   	exit 1;
}

print "storeItem is ok!\n";

##############################
## snapshottest
#############################

print "snapshottest\n";

print "Creating a new CRL Object ... \n";
my $item = new OpenCA::CRL( SHELL=>$openssl, 
                          INFILE => "11674_cacrl.pem");

print "Storing CRL to DB ....\n";
if (not $item) {
	print "there is no CRL\n";
} else {
	if( not $db->storeItem( DATATYPE=>CRL, OBJECT=>$item, 
                                CERT_FILE=>"cert.pem", KEY_FILE=>"priv.key", PWD=>"" ) ) {
   		print "14 ....... not ok 14\n";
	}
}

print "searching for DATATYPE=>CRL ...\n";
@list = $db->searchItem( DATATYPE=>CRL );

print "try to get elements and rows\n"; 
$total    = $db->elements( DATATYPE=>CRL );
print "elements return: ".$total."\n";
## $elements = $db->rows( DATATYPE=>CRL, DATE=>$testDate );
$elements = $db->rows( DATATYPE=>CRL );
print "rows return: ".$elements."\n";
 
print "Retrieved $elements on $total elements ...\n";
print "this doesn't work ... and it's absolut frustrating to don't know why\n";
foreach $crl (@list) {
	print "this item ist not a crl-object or something else\n" if (not $crl);
        print "\n";
        print " * txtCRL:      ".$crl->{txtCRL}."\n";
        print " * dB Key:      ".$crl->{KEY}."\n";
        print " * Version:     " . $crl->getParsed()->{VERSION} . "\n";
        print " * Type:        " . $crl->{DATATYPE} . "\n";
        print " * Last Update: ".$crl->getParsed()->{LAST_UPDATE}."\n";
        print " * Next Update: ".$crl->getParsed()->{NEXT_UPDATE}."\n";
        print "\n";
}
 
print "Unlinking temp files ... \n";
 
foreach $tmp (@tmpfiles) {
        unlink( "$tmp" );
}
 
 
print "end of snapshottest\n";

##############################
## end of snapshottest
###########################

print "Storing CRL to DB ....\n";
if (not $CC) {
	print "there is no CRL\n";
} else {
	if( not $db->storeItem( DATATYPE=>CRL, OBJECT=>$CC, 
                                CERT_FILE=>"cert.pem", KEY_FILE=>"priv.key", PWD=>"" ) ) {
   		print "14 ....... not ok 14\n";
	}
}

print "rest is senseless because genCRL don't works\n" if (not $CC);

## print "Retrieving the CRL from the DB ... \n";
## @list = $db->searchItem( DATATYPE=>CRL, LAST_UPDATE=>"Feb 16 12:18" );
 
## my $testDate = "May 10 10:25:32 2000";
## my $testDate = "Sun Apr 30 23:05:38 2000 GMT";
 
## @list = $db->searchItem( DATATYPE=>CRL, DATE=>$testDate );

print "searching for DATATYPE=>CRL ...\n";
@list = $db->searchItem( DATATYPE=>CRL );

print "try to get elements and rows\n"; 
$total    = $db->elements( DATATYPE=>CRL );
print "elements return: ".$total."\n";
## $elements = $db->rows( DATATYPE=>CRL, DATE=>$testDate );
$elements = $db->rows( DATATYPE=>CRL );
print "rows return: ".$elements."\n";
 
print "Retrieved $elements on $total elements ...\n";
print "this doesn't work ... and it's absolut frustrating to don't know why\n";
foreach $crl (@list) {
	print "this item ist not a crl-object or something else\n" if (not $crl);
        print "\n";
        print " * dB Key:      ".$crl->{KEY}."\n";
        print " * Version:     " . $crl->getParsed()->{VERSION} . "\n";
        print " * Type:        " . $crl->{DATATYPE} . "\n";
        print " * Last Update: ".$crl->getParsed()->{LAST_UPDATE}."\n";
        print " * Next Update: ".$crl->getParsed()->{NEXT_UPDATE}."\n";
        print "\n";
}
 
## @list = $db->searchItem( DATATYPE=>REQUEST );
## $elements = $db->elements( DATATYPE=>REQUEST );
                                                                                              
## print "Retrieved $elements elements ...\n";
## foreach $crl (@list) {
##      print "\n";
##      print " * dB Key:      $crl->{KEY}\n";
##      print " * Type:        " . $crl->{DATATYPE} . "\n";
##      print " * Version:     " . $crl->getParsed()->{VERSION} . "\n";
##      print " * CN:          ".$crl->getParsed()->{CN}."\n";
##      print " * Modulus:     ".$crl->getParsed()->{MODULUS}."\n";
##      print " * Approved:    ".$crl->getParsed()->{APPROVED}."\n";
##      print "\n";
## }
 
print "Unlinking temp files ... \n";
 
foreach $tmp (@tmpfiles) {
        unlink( "$tmp" );
}
 
print "Ok.\n\n";
 
print "dB Status:\n\n";
 
print "STATUS   => " . $db->getItem( DATATYPE =>CRL, KEY=>STATUS ) . "\n";
print "INIT     => " . $db->getItem( DATATYPE =>CRL, KEY=>INIT ) . "\n";
print "MODIFIED => " . $db->getItem( DATATYPE =>CRL, KEY=>MODIFIED ) . "\n";
print "DELETED  => " . $db->getItem( DATATYPE =>CRL, KEY=>DELETED ) . "\n";
print "ELEMENTS => " . $db->elements( DATATYPE => CRL ) . "\n";
print "SERIAL   => " . $db->getSerial( DATATYPE => CRL ) . "\n\n";
 
sub gettext
{
    return $_[0];
}

exit 0;                                                                                      
