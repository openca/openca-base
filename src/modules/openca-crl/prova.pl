#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
use OpenCA::X509;
use OpenCA::CRL;

my $openssl = new OpenCA::OpenSSL (SHELL   => "/usr/bin/openssl",
                                   GETTEXT => \&gettext);
my @tmpfiles = ("cert.pem","priv.key","req.pem");

print "Initializing crypto shell ... \n";
$openssl->setParams ( CONFIG=>"/usr/local/OpenCA/stuff/openssl.cnf" );

## $openssl->setParams ( STDERR => "/dev/null" );

print "Generating a 512 bit priv Key ...\n";
if( not $openssl->genKey( BITS=>512, OUTFILE=>"priv.key" ) ) {
 	print "Error";
}

print "Generating a Request file ... \n";
$openssl->genReq( OUTFILE=>"req.pem", KEYFILE=>"priv.key",
 		DN=>["madwolf\@openca.org", "Massimiliano Pala", "CA", "", "" ] );

print "Generating a CA certificate ... \n";
$p = $openssl->genCert( KEYFILE=>"priv.key", REQFILE=>"req.pem", DAYS=>150,
			OUTFILE=>"cert.pem");

print "Creating a new X509 object ... \n";
my $X509 = new OpenCA::X509( INFILE  => "cert.pem",
                             GETTEXT => \&gettext,
			     FORMAT  => "PEM",
                             SHELL=>$openssl);

## print "Creating a new CRL Object ... \n";
## my $CC = new OpenCA::CRL( SHELL=>$openssl, DATA=>$crl );
## if( not $CC ) {
##  	print "Error!\n";
## }
## print "   * CRL Version: " . $CC->getParsed()->{VERSION} . "\n";
## print "   * Last Update: " . $CC->getParsed()->{LAST_UPDATE} . "\n";
## print "   * Next Update: " . $CC->getParsed()->{NEXT_UPDATE} . "\n";
## print "   * S-Algorithm: " . $CC->getParsed()->{ALGORITHM} . "\n";

print "Creating a new CRL Object (2) ... \n";
my $CC = new OpenCA::CRL (SHELL   => $openssl,
                          GETTEXT => \&gettext,
                          CACERT  => "cert.pem",
			  CAKEY   => "priv.key",
                          DAYS    => "31" );
if( not $CC ) {
	print "Error!\n";
	exit;
}

## print $CC->txtCRL;

print "   * CRL Version: " . $CC->getParsed()->{VERSION} . "\n";
print "   * Last Update: " . $CC->getParsed()->{LAST_UPDATE} . "\n";
print "   * Next Update: " . $CC->getParsed()->{NEXT_UPDATE} . "\n";
print "   * S-Algorithm: " . $CC->getParsed()->{ALGORITHM} . "\n";

foreach $cert ( @{ $CC->getParsed()->{LIST}} ) {
	print "	   - Revoked Certificate : " . $cert->{SERIAL};
	print " (on " . $cert->{DATE} . ")\n";
};


print "Sleeping 2 secs ... \n";
sleep 2;

print "Creating a new CRL Object (3) ... \n";
my $RR = new OpenCA::CRL (SHELL   => $openssl,
                          GETTEXT => \&gettext,
                          CACERT  => "cert.pem",
			  CAKEY   => "priv.key",
                          DAYS    => "31");
if( not $RR ) {
	print "Error! $? -> $!\n";
}

## print $RR->txtCRL;

print "   * CRL Version: " . $RR->getParsed()->{VERSION} . "\n";
print "   * Last Update: " . $RR->getParsed()->{LAST_UPDATE} . "\n";
print "   * Next Update: " . $RR->getParsed()->{NEXT_UPDATE} . "\n";
print "   * S-Algorithm: " . $RR->getParsed()->{ALGORITHM} . "\n";

## if( not $PP ) {
##	print "Error!\n";
##}

foreach $cert ( @{ $CC->getParsed()->{LIST}} ) {
	print "	   - Revoked Certificate : " . $cert->{SERIAL};
	print " (on " . $cert->{DATE} . ")\n";
};

foreach $tmp (@tmpfiles) {
	unlink( "$tmp" );
}

sub gettext
{
    return $_[0];
}

exit 0; 

