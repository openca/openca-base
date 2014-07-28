#!/usr/bin/perl

$|=1;

use OpenCA::OpenSSL;
use OpenCA::PKCS7;

## my $baseName = "27253";
## my $caDir = "/usr/local/OpenCA/chain";
my $baseName = "TEXT";
my $caDir = "chain";

my $openssl = new OpenCA::OpenSSL( SHELL=>"/usr/local/bin/openssl" );
$openssl->setParams ( CONFIG=>"/usr/ssl/openssl.cnf",
		      VERIFY=>"/usr/local/bin/openca-verify",
		      SIGN=>"/usr/local/bin/openca-sign" );

## $openssl->setParams ( STDERR => "/dev/null" );

my $signature = new OpenCA::PKCS7( SHELL    => $openssl,
                                   GETTEXT  => \&gettext,
				   INFILE   => "${baseName}.sig",
				   DATAFILE => "$baseName",
				   ## CA_CERT=>"cacert.pem",
				   CA_DIR   => $caDir);

if ( not $signature ) {
	print "Error\n";
	exit;
}

my $parsed =  $signature->getParsed();
my $signer =  $signature->getSigner();

print "Signature Error Number : " . $signature->status . "\n";
print "Signature Error Value  : " . $signature->errval . "\n";

print "Signer:\n    C-Name: $signer->{CN}\n    Serial: $signer->{SERIAL}\n\n";

my $info = $parsed->{CHAIN};

foreach $level ( keys %$info ) {
	print "Depth: $level\n";
	print "    Serial: " . $info->{$level}->{SERIAL} . "\n";
	print "    E-Mail: " . $info->{$level}->{EMAIL} . "\n";
	print "    C-Name: " . $info->{$level}->{CN} . "\n";
	print "\n";
};

sub gettext
{
    return $_[0];
}

exit 0; 

