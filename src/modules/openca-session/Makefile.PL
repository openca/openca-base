use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'OpenCA::Session',
    'VERSION_FROM' => 'Session.pm', # finds $VERSION
    'PMLIBDIRS'    => [ 'Session' ],
#    'MAN3PODS'     => {'Session.pod'}
);
