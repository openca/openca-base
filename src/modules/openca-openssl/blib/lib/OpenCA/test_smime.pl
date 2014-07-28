#!/usr/bin/perl -w

use OpenCA::X509;
use OpenCA::OpenSSL::SMIME;
use OpenCA::OpenSSL;
use strict;

my($pki, $smime, @text, @res, @ca, $ca, $ossl, $keyf, $keyt);
my($from, $to, $data);

die "usage: $0 <CAfile> <fromcrt> <fromkey> <tocrt> <tokey> <data>\n"
	unless(@ARGV == 6);

($ca, $from, $keyf, $to, $keyt, $data) = @ARGV;

$ossl = OpenCA::OpenSSL->new();

my($crtf) = OpenCA::X509->new(
		SHELL => $ossl,
                GETTEXT => \&gettext,
		INFILE => $from
		) or die;
my($crtt) = OpenCA::X509->new(
		SHELL => $ossl,
                GETTEXT => \&gettext,
		INFILE => $to
		) or die;
$ca[0] = OpenCA::X509->new(
		SHELL => $ossl,
                GETTEXT => \&gettext,
		INFILE => $ca
		) or die;

open(KEYF, '<', $keyf) or die;
open(KEYT, '<', $keyt) or die;

$smime = OpenCA::OpenSSL::SMIME->new(
		INFILE => $data,
		SHELL => $ossl,
		CA_CERTS => \@ca,
		) or die($smime->status() || $smime->errval);

$smime->sign(
		CERTIFICATE => $crtf,
		PRIVATE_KEY => \*KEYF,
		) or die($smime->status() || $smime->errval);

print "-" x 79, "\nsigned:\n";
$smime->get_mime()->print(\*STDOUT) or die($smime->errval);

$smime->encrypt(CERTIFICATE => $crtt,
		CYPHER => 'rc2-128'
	       ) or die($smime->status() || $smime->errval);

print "-" x 79, "\nencrypted:\n";
$smime->get_mime()->print(\*STDOUT) or die($smime->errval);

$smime->decrypt(CERTIFICATE => $crtt,
		PRIVATE_KEY => \*KEYT,
		) or die($smime->status() || $smime->errval);

print "-" x 79, "\ndecrypted:\n";
$smime->get_mime()->print(\*STDOUT) or die($smime->errval);

$smime->verify(USES_EMBEDDED_CERT => 1) or die($smime->status() || $smime->errval);

print "-" x 79, "\nverified:\n";
$smime->get_mime()->print(\*STDOUT) or die($smime->errval);

my($crt2) = $smime->get_last_signer();

if($crtf->getParsed()->{FINGERPRINT} ne $crt2->getParsed()->{FINGERPRINT}) {
	die "signer altered";
} else {
	print "signer ok.\n";
}

sub gettext
{
    return $_[0];
}

1;
