use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'OpenCA::Configuration',
    'VERSION_FROM' => 'Configuration.pm', # finds $VERSION
#    'MAN3PODS'     => {'Configuration.pod'}
);
