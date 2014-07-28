
use Test;
BEGIN { plan tests => 7 };
use OpenCA::OpenSSL;
ok(1); # If we made it this far, we're ok.

my $csr;
my $intcsr;

## SPKAC test
if ( open (CERT,'t/testreq.spkac') ) {
  local $/;
  $/ = undef; 
  $csr = <CERT>;
  close CERT;
  $intcsr = OpenCA::OpenSSL::SPKAC::_new($csr);
  ok(defined $intcsr);
} else {
  print STDERR "Could not open csr file\n";
  ok(0);
}

$pubkey =
"Modulus (512 bit):\n".
"    00:d5:c0:a8:ab:65:9a:dc:8c:6c:e3:bb:88:ec:53:\n".
"    d5:c0:75:48:3c:3c:79:ca:ca:35:d3:96:3a:ce:9a:\n".
"    33:6a:6d:77:e5:af:11:d0:2a:68:46:f9:24:8a:02:\n".
"    32:5d:f7:02:8e:25:62:e6:85:a4:fb:a1:5f:3d:a0:\n".
"    f4:de:e3:c5:a1\n".
"Exponent: 65537 (0x10001)\n";

## 3-7
ok ( $intcsr->pubkey,       $pubkey );
ok ( $intcsr->pubkey_algorithm,      'rsaEncryption' );
ok ( $intcsr->keysize,      '512' );
ok ( $intcsr->exponent,     '10001' );
ok ( $intcsr->modulus,      'D5C0A8AB659ADC8C6CE3BB88EC53D5C075483C3C79CACA35D3963ACE9A336A6D77E5AF11D02A6846F9248A02325DF7028E2562E685A4FBA15F3DA0F4DEE3C5A1' );
