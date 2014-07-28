## #! @PERL@

## load cmds list
opendir DIR, "../../../lib/cmds";
my @cmds = grep /^(?!CVS)/, grep /^(?!Makefile)/, grep /[^.]/, readdir DIR;
closedir DIR;
@cmds = reverse sort @cmds;

## load config list
opendir DIR, ".";
my @configs = grep /\.xml/, readdir DIR;
closedir DIR;
@configs = sort @configs;

my (@missing, @obsolete);

## scan for missing configfiles
## scan for obsolete config files
my $cmd = pop @cmds;
foreach my $config (@configs) {
    while ("$cmd.xml" lt $config) {
        push @missing, $cmd;
        $cmd = pop @cmds;
    }
    if ("$cmd.xml" gt $config) {
        push @obsolete, $config;
    } else {
        $cmd = pop @cmds;
    }
}
do {
    push @missing, $cmd if ($cmd);
    $cmd = pop @cmds if (scalar @cmds);
} while ($cmd);

print "\nmissing configurationfiles:\n\n";
foreach my $cmd (@missing) {
    print "$cmd.xml\n";
}

print "\nobsolete configurationfiles:\n\n";
foreach my $config (@obsolete) {
    print "$config\n";
}
