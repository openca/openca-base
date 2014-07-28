
use Test;
BEGIN { plan tests => 7 };
use OpenCA::OpenSSL;
ok(1); # If we made it this far, we're ok.

my $cert;
my $incert;

if ( open (CERT,'t/testcert.der') ) {
  local $/;
  $/ = undef; 
  $cert = <CERT>;
  close CERT;
  $intcert = OpenCA::OpenSSL::X509::_new_from_der($cert);
  ok(defined $intcert);
} else {
  print STDERR "Could not open cert file\n";
  ok(0);
}

ok ( $intcert->serial, 1013018724 );

ok ( $intcert->subject, 'CN=NOMBRE SANCHEZ FERNANDEZ JULIO - NIF 01895525A,OU=500051325,OU=FNMT Clase 2 CA,O=FNMT,C=ES' );

ok ( $intcert->issuer, 'OU=FNMT Clase 2 CA,O=FNMT,C=ES' );

ok ( $intcert->notBefore, 'May  8 07:38:04 2002 GMT' );

ok ( $intcert->notAfter, 'May  8 08:08:04 2004 GMT' );

