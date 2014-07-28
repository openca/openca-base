use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'	=> 'OpenCA::User',
    'VERSION_FROM' => 'User.pm', # finds $VERSION
#    'MAN3PODS'     => {'User.pod'}
    'PREREQ_PM'    => {
			'OpenCA::DBI' => '1.40',
			'OpenCA::Tools' => '1.00',
    }
);
