#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
use OpenCA::X509;

my $openssl = new OpenCA::OpenSSL( SHELL=>"/usr/bin/openssl" );
my @tmpfiles = ("cert.pem","priv.key","req.pem");

$openssl->setParams ( CONFIG=>"/usr/local/OpenCA/stuff/openssl.cnf" );

$openssl->setParams ( STDERR => "/dev/null" );

if( not $openssl->genKey( BITS=>512, OUTFILE=>"priv.key" ) ) {
 	print "Error";
}

$openssl->genReq( OUTFILE=>"req.pem", KEYFILE=>"priv.key",
 		DN=>["madwolf\@openca.org", "Massimiliano Pala", 
		"PT", "", "" ] );

print $openssl->dataConvert( INFILE=>"req.pem", DATATYPE=>REQUEST,
 				OUTFORM=>PEM );

$p = $openssl->genCert( KEYFILE=>"priv.key", REQFILE=>"req.pem", DAYS=>150,
			OUTFILE=>"cert.pem");

$k = $openssl->dataConvert( INFILE=>"cert.pem",
 			    DATATYPE=>CERTIFICATE,
 			    OUTFORM=>DER ); 
 
$openssl->issueCert( REQFILE=>"spkac.req", INFORMAT=>SPKAC );

## print "$k\n\n";
## my $X509 = new OpenCA::X509(DATA=>"$k", FORMAT=>"DER", SHELL=>$openssl);

my $X509 = new OpenCA::X509 (INFILE  => "cert.pem",
                             GETTEXT => \&gettext,
                             SHELL   => $openssl);

print "ERROR!!!\n" if (not $X509);

print "     Serial : " . $X509->getParsed()->{SERIAL} . "\n";
print "Common Name : " . $X509->getParsed()->{CN} . "\n";
print "     E-Mail : " . $X509->getParsed()->{EMAIL} . "\n";
print "     Issuer : " . $X509->getParsed()->{ISSUER} . "\n";
print " Not Before : " . $X509->getParsed()->{NOTBEFORE} . "\n";
print "  Not After : " . $X509->getParsed()->{NOTAFTER} . "\n";
print "  Algorithm : " . $X509->getParsed()->{PK_ALGORITHM} . "\n";
print "    Modulus : " . $X509->getParsed()->{MODULUS} . "\n";
print "   Key Size : " . $X509->getParsed()->{KEYSIZE} . "\n";
print "   Exponent : " . $X509->getParsed()->{EXPONENT} . "\n";
print "         OU : " . $X509->getParsed()->{OU}[0] . "\n";

## $k = $openssl->dataConvert( INFILE=>"req.pem",
## 			    DATATYPE=>REQ,
## 			    OUTFORM=>TXT ); 
## 
## print "$k\n\n";

## $crl = $openssl->issueCrl( CACERT=>"cert.pem", CAKEY=>"priv.key",
## 			   OUTFORM=>TXT, DAYS=>"32");

## print "$crl\n";

## foreach $tmp (@tmpfiles) {
## 	unlink( "$tmp" );
## }

sub gettext
{
    return $_[0];
}

exit 0; 

