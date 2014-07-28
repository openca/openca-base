
use Test;
BEGIN { plan tests => 19 };
use OpenCA::OpenSSL;
ok(1); # If we made it this far, we're ok.

my $csr;
my $incsr;

## DER test
if ( open (CERT,'t/testreq.der') ) {
  local $/;
  $/ = undef; 
  $csr = <CERT>;
  close CERT;
  $intcsr = OpenCA::OpenSSL::PKCS10::_new_from_der($csr);
  ok(defined $intcsr);
} else {
  print STDERR "Could not open csr file\n";
  ok(0);
}

## PEM test
if ( open (CERT,'t/testreq.pem') ) {
  local $/;
  $/ = undef; 
  $csr = <CERT>;
  close CERT;
  $intcsr = OpenCA::OpenSSL::PKCS10::_new_from_pem($csr);
  ok(defined $intcsr);
} else {
  print STDERR "Could not open csr file\n";
  ok(0);
}

$signature =
"8d:b9:4e:da:87:eb:9e:3d:7a:f2:5d:16:5f:f4:80:d2:ed:10\n".
"16:8a:57:a5:57:60:22:2d:33:df:0e:7e:51:65:de:8b:ca:00\n".
"5e:c6:85:08:c3:fd:ad:bd:1a:f0:6d:c3:78:1b:66:41:27:52\n".
"a9:f9:3d:a1:c5:ff:3a:63:78:96:f1:47:b2:a7:f8:8c:c9:3d\n".
"c5:14:e9:35:8d:44:69:71:ff:98:1f:e6:c6:ca:11:cd:ec:22\n".
"f9:71:d5:ef:c7:31:0e:fc:0a:e9:95:a0:3a:4b:ea:db:6a:c6\n".
"1a:6c:9e:bd:06:cc:bf:f9:27:af:25:3c:80:8c:b8:a5:a6:da\n".
"39:11:";

$pubkey =
"Modulus (1024 bit):\n".
"    00:b9:e7:84:68:f9:51:f4:74:93:8d:aa:58:cf:05:\n".
"    6f:82:ef:63:03:34:63:72:f5:e5:e7:cd:e8:d7:ad:\n".
"    cc:ec:1e:cd:cf:73:dd:95:69:ab:7a:0a:92:04:10:\n".
"    6b:9e:c8:6d:bd:c5:a8:1b:d6:8e:c6:8f:62:91:82:\n".
"    95:58:72:67:71:ea:d1:dd:d8:99:05:5b:90:5c:15:\n".
"    57:d6:5c:be:36:3d:5e:2b:7f:dc:e2:62:89:fc:8d:\n".
"    6b:1b:2b:66:84:f8:be:a1:0a:d7:1b:c5:d6:c7:38:\n".
"    66:5d:48:85:99:27:07:3f:d5:5b:3b:d1:2f:fb:22:\n".
"    65:be:65:db:3c:60:41:62:03\n".
"Exponent: 65537 (0x10001)\n";

## 4-7
ok ( $intcsr->version,      '0 (0x0)' );
ok ( $intcsr->subject,      'emailAddress=michael.bell@web.de,CN=bellus.rz.hu-berlin.de,OU=Rechenzentrum,O=Humboldt-Universitaet zu Berlin,C=DE' );
ok ( $intcsr->subject_hash, '1975050473' );
ok ( $intcsr->emailaddress, 'michael.bell@web.de' );

## 8-12
ok ( $intcsr->pubkey,       $pubkey );
ok ( $intcsr->pubkey_algorithm,      'rsaEncryption' );
ok ( $intcsr->keysize,      '1024' );
ok ( $intcsr->exponent,     '10001' );
ok ( $intcsr->modulus,      'B9E78468F951F474938DAA58CF056F82EF6303346372F5E5E7CDE8D7ADCCEC1ECDCF73DD9569AB7A0A9204106B9EC86DBDC5A81BD68EC68F6291829558726771EAD1DDD899055B905C1557D65CBE363D5E2B7FDCE26289FC8D6B1B2B6684F8BEA10AD71BC5D6C738665D48859927073FD55B3BD12FFB2265BE65DB3C60416203' );

## 13-15
ok ( $intcsr->fingerprint,          'SHA1:D3:DB:97:76:7A:AE:56:1E:EE:F0:52:F3:EA:D7:9E:25:3C:F7:3A:5D');
ok ( $intcsr->fingerprint ("sha1"), 'SHA1:D3:DB:97:76:7A:AE:56:1E:EE:F0:52:F3:EA:D7:9E:25:3C:F7:3A:5D');
ok ( $intcsr->fingerprint ("md5"),  'MD5:FD:65:26:AB:B4:8F:BE:0E:02:52:B1:7D:D5:D6:6B:11');

## 16-17
ok ( $intcsr->extensions,  undef );
ok ( $intcsr->attributes,  "challengePassword        :bellus\n" );

## 18-19
ok ( $intcsr->signature_algorithm, 'md5WithRSAEncryption' );
ok ( $intcsr->signature, $signature);
