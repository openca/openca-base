
use Test;
BEGIN { plan tests => 22 };
use OpenCA::OpenSSL;
ok(1); # If we made it this far, we're ok.

my $cert;
my $incert;

if ( open (CERT,'t/testcert.pem') ) {
  local $/;
  $/ = undef; 
  $cert = <CERT>;
  close CERT;
  $intcert = OpenCA::OpenSSL::X509::_new_from_pem($cert);
  ok(defined $intcert);
} else {
  print STDERR "Could not open cert file\n";
  ok(0);
}

$pubkey =
"Modulus (1024 bit):\n".
"    00:ce:6e:62:c7:dc:53:2c:ed:cd:b6:c8:99:bc:a9:\n".
"    00:27:c9:2c:e9:95:37:8d:06:81:85:67:08:b1:de:\n".
"    2b:4f:1e:64:07:82:2e:aa:04:57:d2:63:34:2a:98:\n".
"    4b:65:71:8b:4e:a1:23:a4:be:5a:ef:2e:11:ae:37:\n".
"    30:03:5e:6e:1f:cf:c5:42:90:d7:ec:ee:05:7f:05:\n".
"    e0:9e:e1:ac:9e:56:4f:b1:22:9d:42:7b:dc:72:29:\n".
"    6c:a8:b4:d5:db:76:99:06:86:3b:90:d0:f5:1a:06:\n".
"    a6:bf:80:3b:27:34:c3:fd:9c:71:1a:f6:94:06:01:\n".
"    21:7d:c3:85:8b:66:38:ea:fd\n".
"Exponent: 65537 (0x10001)\n";

$signature = 
"09:b8:3e:ed:51:46:34:e7:6f:e9:cc:a2:6b:84:4d:85:93:33\n".
"8f:bd:5c:12:58:87:8f:24:fa:de:50:e0:c3:3d:12:dd:c6:c5\n".
"da:8e:e8:6a:da:78:14:34:db:29:b4:0f:9b:35:68:1b:e9:50\n".
"52:99:94:04:55:b3:d4:9e:a1:eb:16:f3:6a:13:bc:60:45:91\n".
"dc:57:7c:a8:f2:6c:fc:ce:db:13:bf:24:1a:83:28:f7:79:22\n".
"6a:69:d2:4f:7b:c3:6f:c3:82:b6:ae:63:0f:83:d3:1c:6b:e0\n".
"b2:63:6f:bb:8e:6a:02:96:32:44:a4:de:c6:2e:1b:74:bc:32\n".
"8b:e9:";

$extensions =
"    X509v3 Private Key Usage Period: \n".
"        Not Before: May  8 07:38:04 2002 GMT, Not After: May  8 08:08:04 2004 GMT\n".
"    X509v3 Key Usage: \n".
"        Digital Signature, Key Encipherment\n".
"    Netscape Cert Type: \n".
"        SSL Client, S/MIME\n".
"    X509v3 Subject Alternative Name: \n".
"        email:julio.sanchez\@wanadoo.es, DirName:/1.3.6.1.4.1.5734.1.4=01895525a/1.3.6.1.4.1.5734.1.3=fernandez/1.3.6.1.4.1.5734.1.2=sanchez/1.3.6.1.4.1.5734.1.1=julio\n".
"    X509v3 CRL Distribution Points: \n".
"        DirName:/C=ES/O=FNMT/OU=FNMT Clase 2 CA/CN=CRL538\n".
"\n".
"    X509v3 Authority Key Identifier: \n".
"        keyid:40:9A:76:44:97:74:07:C4:AC:14:CB:1E:8D:4F:3A:45:7C:30:D7:61\n".
"\n".
"    X509v3 Subject Key Identifier: \n".
"        EB:26:97:71:F9:0A:62:B2:1C:F2:F8:9E:09:5C:2A:62:1B:72:44:64\n".
"    X509v3 Basic Constraints: \n".
"        CA:FALSE\n".
"    1.2.840.113533.7.65.0: \n".
"        0\n".
"..V5.0....\n";

## 3-6
ok ( $intcert->version, "3 (0x2)" );
ok ( $intcert->fingerprint, 'SHA1:52:F0:B9:2A:C0:50:83:E0:93:0A:C3:1B:1B:A3:96:DC:B5:94:89:FC' );
ok ( $intcert->fingerprint("sha1"), 'SHA1:52:F0:B9:2A:C0:50:83:E0:93:0A:C3:1B:1B:A3:96:DC:B5:94:89:FC' );
ok ( $intcert->fingerprint("md5"), 'MD5:14:EE:65:97:43:4D:62:D7:E1:37:0E:7A:20:FE:EC:44' );

## 7-12
ok ( $intcert->serial, 1013018724 );
ok ( $intcert->subject, 'CN=NOMBRE SANCHEZ FERNANDEZ JULIO - NIF 01895525A,OU=500051325,OU=FNMT Clase 2 CA,O=FNMT,C=ES' );
ok ( $intcert->subject_hash,    '3977690925' );
ok ( $intcert->issuer, 'OU=FNMT Clase 2 CA,O=FNMT,C=ES' );
ok ( $intcert->alias, undef );
ok ( $intcert->emailaddress, 'julio.sanchez@wanadoo.es' );

## 13-14
ok ( $intcert->notBefore, 'May  8 07:38:04 2002 GMT' );
ok ( $intcert->notAfter, 'May  8 08:08:04 2004 GMT' );

## 15-19
ok ( $intcert->pubkey_algorithm, 'rsaEncryption' );
ok ( $intcert->keysize, '1024' );
ok ( $intcert->modulus, 'CE6E62C7DC532CEDCDB6C899BCA90027C92CE995378D0681856708B1DE2B4F1E6407822EAA0457D263342A984B65718B4EA123A4BE5AEF2E11AE3730035E6E1FCFC54290D7ECEE057F05E09EE1AC9E564FB1229D427BDC72296CA8B4D5DB769906863B90D0F51A06A6BF803B2734C3FD9C711AF6940601217DC3858B6638EAFD');
ok ( $intcert->exponent, '10001' );
ok ( $intcert->pubkey, $pubkey);

## 20
ok ( $intcert->extensions, $extensions);
open FD, ">t3_20.org";
print FD $extensions;
close FD;
open FD, ">t3_20.new";
print FD $intcert->extensions;
close FD;

# 21-22
ok ( $intcert->signature_algorithm, 'sha1WithRSAEncryption' );
ok ( $intcert->signature, $signature);
