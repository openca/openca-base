use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'         => 'OpenCA::REQ',
    'VERSION_FROM' => 'REQ.pm', # finds $VERSION
#    'MAN3PODS'     => {'REQ.pod'},
    'PREREQ_PM'    => {
                       'Digest::MD5' => '2.14',
                       'X500::DN'    => '0.27'
                      }
);
