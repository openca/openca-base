use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'         => 'OpenCA::X509',
    'VERSION_FROM' => 'X509.pm', # finds $VERSION
    'PREREQ_PM'    => 'OpenCA::OpenSSL',
#    'MAN3PODS'     => {'X509.pod'},
    'PREREQ_PM'    => {
                       'Digest::MD5' => '2.14',
                       'X500::DN'    => '0.27'
                      }
);
