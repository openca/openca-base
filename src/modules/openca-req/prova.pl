#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
use OpenCA::X509;
use OpenCA::REQ;
use OpenCA::Tools;

my $openssl = new OpenCA::OpenSSL( SHELL=>"/usr/bin/openssl" );
my $tools = new OpenCA::Tools(GETTEXT => \&gettext);

my @tmpfiles = ("priv.key","req.pem");

print "Initializing crypto shell ... \n";
$openssl->setParams ( CONFIG=>"/usr/ssl/openssl.cnf" );
$openssl->setParams ( STDERR => "/dev/null" );

print "Generating a 768 bit priv Key ...\n";
if( not $openssl->genKey( BITS=>768, OUTFILE=>"priv.key" ) ) {
 	print "Error";
}

print "Generating a Request file ... \n";
$openssl->genReq( OUTFILE=>"req.pem", KEYFILE=>"priv.key",
  	SUBJECT=>"Email=madwolf\@openca.org, CN=Massimiliano Pala, c=IT" );

my $old = new OpenCA::REQ (SHELL   => $openssl,
                           GETTEXT => \&gettext,
	  	           KEYFILE => "priv.key",
		           FORMAT  => "PEM",
	  	           SUBJECT => "Email=you\@openca.org, CN=John Doe, OU=Department, O=OpenCA, C=IT" );

# print $old->getParsed()->{DN} . "\n";

## print $openssl->genReq( KEYFILE=>"priv.key", OUTFORM=>TXT,
##  	DN=>["madwolf\@openca.org", "Massimiliano Pala", "CA", "", "" ] );

# print "Parsing a REVOKE request file ... \n";
# my $REQ = new OpenCA::REQ (SHELL   => $openssl,
#                             GETTEXT => \&gettext,
#                             DATA    => $tools->getFile("revoke.req"));
# print "CERT DN => " . $REQ->getParsed()->{REVOKE_CERTIFICATE_DN} . "\n";
# print "\n\n";

print "Parsing an SPKAC request file ... \n";
my $REQ = new OpenCA::REQ (SHELL   => $openssl,
                           GETTEXT => \&gettext,
                           INFILE  => "spkac.req",
                           FORMAT  => SPKAC);
## print "Parsing a RENEW request file ... \n";
## my $REQ = new OpenCA::REQ(SHELL=>$openssl, INFILE=>"renew.req", FORMAT=>RENEW);
# my $REQ = new OpenCA::REQ(SHELL=>$openssl, INFILE=>"req.pem", FORMAT=>PEM);
# print "Error! $!\n" && exit 1 if ( not $REQ );
## print "DN => \n   " . $REQ->getParsed()->{DN} . "\n";

## $REQ = $old;
## print $REQ->getTXT();

print "  OPERATOR => " . $REQ->getParsed()->{OPERATOR} . "\n";
print " NOTBEFORE => " . $REQ->getParsed()->{NOTBEFORE} . "\n";
print "  APPROVED => " . $REQ->getParsed()->{APPROVED} . "\n";
print "        DN => " . $REQ->getParsed()->{DN} . "\n";
print "        CN => " . $REQ->getParsed()->{CN} . "\n";
print "       OUs => @{$REQ->getParsed()->{OU}}\n";
print "  KEY SIZE => " . $REQ->getParsed()->{KEYSIZE} . "\n";
print "     SPKAC => " . $REQ->getParsed()->{SPKAC} . "\n";
print "    PUBKEY => " . $REQ->getParsed()->{PUBKEY} . "\n";
print "KEY DIGEST => " . $REQ->getParsed()->{KEY_DIGEST} . "\n";

foreach $tmp (@tmpfiles) {
	unlink( "$tmp" );
}

sub gettext
{
    return $_[0];
}

exit 0; 

