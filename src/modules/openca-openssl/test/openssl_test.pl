#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
my $openssl = new OpenCA::OpenSSL( SHELL=>"/usr/bin/openssl" );

$openssl->setParams ( SHELL=>"/usr/bin/openssl",
		      CONFIG=>"/usr/local/OpenCA/stuff/openssl.cnf",
		      VERIFY=>"/usr/bin/verify",
		      SIGN=>"/usr/bin/sign" );

## $openssl->setParams ( STDERR => "/dev/null" );

if( not $openssl->genKey( BITS=>512, OUTFILE=>"priv.key", PASSWD=>"ciccio" ) ) {
 	print "Error";
}

$openssl->genReq( OUTFILE=>"req.pem", KEYFILE=>"priv.key", PASSWD=>"ciccio",
 		DN=>["madwolf\@openca.org", "Massimiliano Pala", "", "", "" ] );

$p = $openssl->genCert( KEYFILE=>"priv.key", REQFILE=>"req.pem", DAYS=>500,
			OUTFILE=>"cert.pem", PASSWD=>"ciccio");

$k = $openssl->dataConvert( INFILE=>"cert.pem",
 			    DATATYPE=>CERTIFICATE,
 			    OUTFORM=>NET ); 
 
$k = $openssl->dataConvert( INFILE=>"req.pem",
			    DATATYPE=>REQ,
			    OUTFORM=>TXT ); 

## print "$k\n\n";

## print "\nRevoking Certificate 00 ... ";
## if( not $openssl->revoke( CACERT=>"cert.pem", CAKEY=>"priv.key",
## 		   	 INFILE=>"cert.pem") ) {
## 	print "Error!\n\n";
## 	exit 0;
## }
## print "Ok.\n";

$crl = $openssl->issueCrl( CACERT=>"cert.pem", CAKEY=>"priv.key", PASSWD=>"ciccio",
			   OUTFORM=>TXT, DAYS=>"500");

print "$crl\n";

print "CRL Digest ... \n";
print "    * MD5 : ";
print $openssl->getDigest( DATA=>$crl, ALGORITHM=>md5 ) . "\n";
print "    * SHA1 : ";
print $openssl->getDigest( DATA=>$crl, ALGORITHM=>sha256 ) . "\n";

print $openssl->verify( SIGNATURE_FILE=>"sig", CA_CERT=>"cert.pem",
			VERBOSE=>"1" );

exit 0; 

