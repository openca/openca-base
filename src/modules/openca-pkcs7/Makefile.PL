use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'OpenCA::PKCS7',
    'VERSION_FROM' => 'PKCS7.pm', # finds $VERSION
#    'MAN3PODS'     => {'PKCS7.pod'},
    'PREREQ_PM'     => {'X500::DN' => '0.27'}
);
