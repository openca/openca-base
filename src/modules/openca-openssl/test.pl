# Before `make install' is performed this script should be runnable with
# `make test'. After `make install' it should work as `perl test.pl'

######################### We start with some black magic to print on failure.

# Change 1..1 below to 1..last_test_to_print .
# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; print "1..1\n"; }
END {print "not ok 1\n" unless $loaded;}
use OpenCA::OpenSSL;
$loaded = 1;
print "ok 1\n";

######################### End of black magic.

# Insert your test code below (better if it prints "ok 13"
# (correspondingly "not ok 13") depending on the success of chunk 13
# of the test code):
my $openpath=`which openssl`;
chomp $openpath;
print "OpenSSL path: $openpath\n";

my $openssl = new OpenCA::OpenSSL( SHELL => $openpath, GETTEXT => \&i18nGettext);

if (not $openssl)
{
    print "Cannot instantiate OpenCA::OpenSSL\n";
    print "Errno: ".$OpenCA::OpenSSL::errno."\n";
    print "Errval: ".$OpenCA::OpenSSL::errval."\n";
    exit 1;
}

my $k = {
	CONFIG => "/usr/ssl/openssl.cnf"
	};

$openssl->setParams( $k );

print "ok 13\n";

sub i18nGettext {

    my $i = 1;
    while ($_[$i]) {
        $_[0] =~ s/$_[$i]/$_[$i+1]/g;
        $i += 2;
    }

    return $_[0];
}

