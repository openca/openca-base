
use Test;
BEGIN { plan tests => 15 };
use OpenCA::OpenSSL;
ok(1); # If we made it this far, we're ok.

my $crl;
my $incrl;

## DER test
if ( open (CERT,'t/testcrl.der') ) {
  local $/;
  $/ = undef; 
  $crl = <CERT>;
  close CERT;
  $intcrl = OpenCA::OpenSSL::CRL::_new_from_der($crl);
  ok(defined $intcrl);
} else {
  print STDERR "Could not open crl file\n";
  ok(0);
}

## PEM test
if ( open (CERT,'t/testcrl.pem') ) {
  local $/;
  $/ = undef; 
  $crl = <CERT>;
  close CERT;
  $intcrl = OpenCA::OpenSSL::CRL::_new_from_pem($crl);
  ok(defined $intcrl);
} else {
  print STDERR "Could not open crl file\n";
  ok(0);
}

$signature = 
"6e:6e:e7:51:50:1c:ba:0d:22:03:f6:48:3d:82:75:8a:a5:c2\n".
"5c:82:97:63:ae:47:7d:2a:f9:72:27:77:7a:54:26:70:6b:48\n".
"49:a3:0b:14:bd:a3:4d:5d:26:4e:69:96:ba:94:e4:3f:1c:f5\n".
"32:55:20:b5:0c:98:aa:67:83:51:8c:2c:87:7a:19:c7:bb:34\n".
"f2:e9:55:c8:65:9a:00:b5:e1:01:d5:b1:eb:9d:00:90:98:11\n".
"b5:cb:03:05:9c:7d:bf:36:06:7c:ac:7c:9b:67:7e:89:66:c8\n".
"84:0e:2f:ac:4e:40:20:ca:d3:b3:fd:25:41:ca:18:82:4d:04\n".
"88:4f:85:92:c7:eb:50:99:17:1d:5d:56:8f:c4:5e:19:a2:e6\n".
"9d:a3:86:95:8d:92:2a:43:7a:46:10:c4:62:8a:cb:f2:2f:32\n".
"61:da:89:4d:ea:21:f3:a3:1b:c6:a5:2f:83:99:dc:f1:96:4a\n".
"33:5e:05:31:e7:21:6f:29:6d:10:62:15:d8:da:34:e7:6c:8e\n".
"e9:9a:7f:73:67:2c:9c:70:28:ec:a5:0e:a5:56:60:0f:a6:b9\n".
"e7:15:fe:8f:46:0a:06:a5:fb:0c:86:bf:33:da:a5:0c:ee:07\n".
"89:4f:ba:35:7d:93:0b:7d:b8:2c:20:ae:14:6c:8d:08:f3:d3\n".
"42:1c:23:64:";

## 4-15
ok ( $intcrl->version,      '1 (0x0)' );
ok ( $intcrl->issuer,      'OU=DBI Test CA 2,O=Humboldt-Universitaet zu Berlin,C=DE' );
ok ( $intcrl->issuer_hash, '3113627360' );
ok ( $intcrl->lastUpdate,  'Dec 10 15:14:05 2002 GMT' );
ok ( $intcrl->nextUpdate,  'Jan  9 15:14:05 2003 GMT' );
ok ( $intcrl->fingerprint,          'SHA1:55:F4:B9:F1:1A:F9:D6:51:35:4F:C4:06:30:41:ED:04:5F:9F:CD:12');
ok ( $intcrl->fingerprint ("sha1"), 'SHA1:55:F4:B9:F1:1A:F9:D6:51:35:4F:C4:06:30:41:ED:04:5F:9F:CD:12');
ok ( $intcrl->fingerprint ("md5"),  'MD5:3A:25:72:83:BC:8A:D7:60:D9:9D:2C:50:75:57:24:EA');
ok ( $intcrl->revoked,     "DB\n        Oct  2 12:06:43 2002 GMT\n" );
ok ( $intcrl->extensions,  undef );
ok ( $intcrl->signature_algorithm, 'md5WithRSAEncryption' );
ok ( $intcrl->signature, $signature);

