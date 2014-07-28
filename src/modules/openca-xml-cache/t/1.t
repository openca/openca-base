
use Test;
use OpenCA::XML::Cache;
use Data::Dumper;
use XML::Twig;

BEGIN { plan tests => 5 };
ok(1); # If we made it this far, we're ok.

my $pwd = `pwd`;
$pwd =~ s/[\n\s]*//g;

## create new object
my $obj = OpenCA::XML::Cache->new(DEBUG   => 0,
                             LOGFILE => "$pwd/t/test.log",
                             PIDFILE => "$pwd/t/test.pid");
if ($obj)
{
    ok (1);
} else {
    ok (0);
    exit;
}

## start server
my $res = $obj->startDaemon();
if ($res == 1)
{
    ok (1);
} else {
    ok (0);
    exit;
}
sleep 1;

## load one xml-file
my $filename = $pwd."/t/test.xml";
my $xpath = "config";
my $counter = 0;
my $answer = $obj->get_xpath (FILENAME => $filename, COUNTER => $counter, XPATH => $xpath);
ok ($answer, "Yeah, what a nice testfile!");

my $items = 10000;
print STDERR "\nReading $items configuration parameters\n";
print STDERR gmtime()."\n";
for (my $i=0; $i<$items; $i++)
{
    $answer = $obj->get_xpath (FILENAME => $filename, COUNTER => $counter, XPATH => $xpath);
    if ($answer ne "Yeah, what a nice testfile!")
    {
        print STDERR "wrong xml data\n";
        last;
    }
}
print STDERR gmtime()."\n";


## stop daemon
$res = $obj->stopDaemon();
if ($res == 1)
{
    ok (1);
} else {
    ok (0);
}
