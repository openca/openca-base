use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'OpenCA::DBI',
    'VERSION_FROM' => 'DBI.pm', # finds $VERSION
#    'MAN3PODS'     => {'DBI.pod'},
    'PREREQ_PM'    => {
                       'OpenCA::REQ'     => '0.9',
                       'OpenCA::X509'    => '0.9',
                       'OpenCA::CRL'     => '0.9',
                       'OpenCA::OpenSSL' => '0.9',
                       'OpenCA::Tools'   => '0.4',
                       'DBI'             => '1.19'
                      }
);
