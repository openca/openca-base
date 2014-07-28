use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'OpenCA::XML::Cache',
    'VERSION_FROM' => 'Cache.pm', # finds $VERSION
#    'MAN3PODS'     => {'Cache.pod'}
);
