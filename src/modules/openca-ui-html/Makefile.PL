use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'OpenCA::UI::HTML',
    'VERSION_FROM' => 'HTML.pm', # finds $VERSION
#    'MAN3PODS'     => {'HTML.pod'}
);
