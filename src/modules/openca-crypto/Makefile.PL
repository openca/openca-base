use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'OpenCA::Crypto',
    'VERSION_FROM' => 'Crypto.pm', # finds $VERSION
    'PMLIBDIRS'    => [ 'Token' ],
#    'MAN3PODS'     => {'Crypto.pod'}
);
