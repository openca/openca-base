use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'         => 'OpenCA::TRIStateCGI',
    'VERSION_FROM' => 'TRIStateCGI.pm', # finds $VERSION
#    'MAN3PODS'     => {'TRIStateCGI.pod'},
    'PREREQ_PM'    => { 'CGI' => '0' }
);
