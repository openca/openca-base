## OpenCA::XML::Cache
##
## Written by Michael Bell for the OpenCA project 2003
## Copyright (C) 2003-2004 The OpenCA Project
##
## GNU Public License Version 2
##
## see file LICENSE or contact
##   Free Software Foundation, Inc.
##   675 Mass Ave, Cambridge, MA 02139, USA
##

use strict;

package OpenCA::XML::Cache;

use XML::Twig;
use utf8;
use Socket;
## use Carp;

use POSIX;
use English;
## use IPC::SysV;
## use IPC::SysV qw (IPC_RMID IPC_CREAT);

## the other use directions depends from the used databases
## $Revision: 0.1.1.2 

($OpenCA::XML::Cache::VERSION = '$Revision: 1.1.1.1 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg; 

$OpenCA::XML::Cache::ERROR = {
                       SETUID_FAILED       => -101,
                       SETGID_FAILED       => -102,
                       MKFIFO_FAILED       => -103,
                       OPEN_FIFO_FAILED    => -104,
                       OPEN_PIDFILE_FAILED => -105,
                       FORK_FAILED         => -108,
                       MSGGET_FAILED       => -109,
                       MSGRCV_FAILED       => -110,
                       OPEN_SOCKET_FAILED  => -111,
                      };

## Hit it in your phone if do not know what does this key mean ;-D
$OpenCA::XML::Cache::SOCKET_FILE = "/tmp/openca_xml_cache";

my $params = {
              SOCKET_FILE   => $OpenCA::XML::Cache::SOCKET_FILE,
              IPC_USER      => undef,
              IPC_GROUP     => undef,
              IPC_UID       => undef,
              IPC_GID       => undef,
              DEBUG         => 0,
              USAGE_COUNTER => 0
	     };

## functions
##
## new
## _init
## _doLog
## _debug
##
## startDaemon
## stopDaemon
## getMessage
## getData
##
## getTwig 

#######################################
##          General functions        ##
#######################################

sub new { 
  
  # no idea what this should do
  
  my $that  = shift;
  my $class = ref($that) || $that;
  
  ## my $self  = $params;
  my $self;
  my $help;
  foreach $help (keys %{$params}) {
    $self->{$help} = $params->{$help};
  }
   
  bless $self, $class;

  # ok here I start ;-)

  $self->_init (@_);

  return $self;
}

sub _init {
  my $self = shift;
  my $keys = { @_ };

  $self->{DEBUG}   = $keys->{DEBUG}   if ($keys->{DEBUG});
  $self->{gettext} = $keys->{GETTEXT} if ($keys->{GETTEXT});

  $self->debug ("_init: init of OpenCA::XML::Cache");

  ## this class can be created for several reasons
  ## 1. signing
  ## 2. backup
  ## 3. backup-verification
  ## 4. database-recovery
  ## 5. database-recovery from backup

  ## actually only signing is supported

  ## general configuration

  $self->debug ("_init: general parts ...");

  ## checking for given pipename
  $self->{PIDFILE}       = $keys->{PIDFILE}       if ($keys->{PIDFILE});
  $self->{LOGFILE}       = $keys->{LOGFILE}       if ($keys->{LOGFILE});
  $self->{SOCKET_FILE}   = $keys->{SOCKETFILE}    if ($keys->{SOCKETFILE});
  $self->{IPC_USER}      = $keys->{IPC_USER}      if ($keys->{IPC_USER});
  $self->{IPC_GROUP}     = $keys->{IPC_GROUP}     if ($keys->{IPC_GROUP});
  $self->{FILENAME}      = $keys->{FILENAME}      if ($keys->{FILENAME});
  $self->{XPATH}         = $keys->{XPATH}         if ($keys->{XPATH});
  $self->{COUNTER}       = $keys->{COUNTER}       if ($keys->{COUNTER});

  ## configure uid
  if ($self->{IPC_USER}) {
    my @passwd = getpwnam ($self->{IPC_USER});
    if (@passwd and scalar @passwd and defined $passwd[2]) {
      $self->{IPC_UID} = $passwd[2];
    } else {
      $self->{IPC_UID} = $self->{IPC_USER};
    }
  } else {
    $self->debug ("_init: IPC_UID not given so $<");
    $self->{IPC_UID} = $<                 if (not $self->{IPC_UID});
  }

  ## configure group
  if ($self->{IPC_GROUP}) {
    my @passwd = getgrnam ($self->{IPC_GROUP});
    if (@passwd and scalar @passwd and defined $passwd[2]) {
      $self->{IPC_GID} = $passwd[2];
    } else {
      $self->{IPC_GID} = $self->{IPC_GROUP};
    }
  } else {
    $self->debug ("_init: IPC_GID not given so ".getgid."\n");
    $self->{IPC_GID} = getgid                 if (not $self->{IPC_GID}); 
  }

  $self->debug ("_init: init of OpenCA::XML::Cache completed");

  return 1;
}

sub _cleanup
{
    ## this function only avoids memory leaks by calls to get_xpath

    my $self = shift;
    my $keys = { @_ };

    foreach my $key (keys %{$keys})
    {
        delete $self->{$key} if (exists $self->{$key});
    }

    return 1;
}

sub doLog {
  my $self = shift;

  if (not open (LOGFILE, ">>".$self->{LOGFILE})) {
    print STDERR "OpenCA::XML::Cache> WARNING: cannot write logfile ".$self->{LOGFILE}."\n";
    print STDERR "OpenCA::XML::Cache> MESSAGE: ".$_[0]."\n";
  } else {
    $self->debug ("LOGMESSAGE: ".$_[0]);
    print LOGFILE "\nOpenCA::XML::Cache> ".gmtime()." UTC message:\nOpenCA::XML::Cache> ";
    print LOGFILE $_[0];
    print LOGFILE "\n" if ($_[0] !~ /\n$/);
    close LOGFILE;
  }
}

sub debug {
  my $self = shift;

  if ($self->{DEBUG}) {

    my $help = $_[0];
    $help =~ s/\n/<br>\n/g;
    print STDERR "OpenCA::XML::Cache->".$help."\n";

    if ($_[1])
    {
      print STDERR "    FILENAME      ".$self->{FILENAME}."\n";
      print STDERR "    XPATH         ".$self->{XPATH}."\n";
      print STDERR "    COUNTER       ".$self->{COUNTER}."\n";
      print STDERR "    SOCKET_FILE   ".$self->{SOCKET_FILE}."\n";
      print STDERR "    IPC_USER      ".$self->{IPC_USER}."\n";
      print STDERR "    IPC_GROUP     ".$self->{IPC_GROUP}."\n";
      print STDERR "    IPC_UID       ".$self->{IPC_UID}."\n";
      print STDERR "    IPC_GID       ".$self->{IPC_GID}."\n";
      print STDERR "    PIDFILE       ".$self->{PIDFILE}."\n";
      print STDERR "    LOGFILE       ".$self->{LOGFILE}."\n";
    }
  }
  return 1;
}

###################################
##        daemon functions       ##
###################################

sub startDaemon {

  my $self = shift;
  my $keys = { @_ };
 
  $self->_init (@_);

  $self->debug ("startDaemon");

  ## check for a running daemon

  my $pid = $self->getPID();
  if ($pid)
  {
      ## return if daemon already exists
      return 1 if (getpgrp ($pid) and getpgrp ($pid) > 0);
  }

  ## initialize socket
  my $socket = $self->{SOCKET_FILE};
  my $uaddr = sockaddr_un($socket);
  my $umask = umask (0177);
  $self->debug ("startDaemon: uaddr: $uaddr");
  $self->debug ("startDaemon: maxconn: ".SOMAXCONN);

  socket(Server,PF_UNIX,SOCK_STREAM,0) ||
      return $self->setError (600, "Call to POSIX function socket failed.");
  unlink($socket);

  $self->debug ("startDaemon: anonymous socket initialized");

  ## fork away for real operation
  if ($pid = fork ()) {
    
    ## parent finish

    umask ($umask);

    ## preparations to kill the daemon
    $self->debug ("startDaemon: try to open PIDFILE ...");
    if (not open (PIDFILE, ">".$self->{PIDFILE})) {
      my $warning = "WARNING: cannot write pidfile \"".$self->{PIDFILE}."\"\n".
                    "         sub stopDaemon doesn't work!\n";
      print STDOUT $warning;
      $self->doLog ($warning);
    } else {
      $self->debug ("startDaemon: PID: ".$pid); 
      print PIDFILE sprintf ("%d", $pid);
      close PIDFILE;
    }

    ## print to LOGFILE the startup
    $self->doLog ("startDaemon successfull at ".
           gmtime ()." UTC PID: ".sprintf ("%d", $pid)."\n");
    
    ## all ok
    return 1;
    
  } elsif (defined $pid) {

    ## check for actual user and group
    ## change to predefined user and group if necessary
    ## change group first because it is better to be root

    if ($GID != $self->{IPC_GID}) {
      ## try to set correct uid
      if (POSIX::setgid ($self->{IPC_GID}) < 0) {
        return $OpenCA::XML::Cache::ERROR->{SETGID_FAILED};
      }
    }
    if ($UID != $self->{IPC_UID}) {
      ## try to set correct uid
      if (POSIX::setuid ($self->{IPC_UID}) < 0) {
        return $OpenCA::XML::Cache::ERROR->{SETUID_FAILED};
      }
    }

    ## socket initialization with correct pid and uid
    bind  (Server, $uaddr)               ||
        return $self->setError (600, "Call to POSIX function bind failed.");
    listen(Server,SOMAXCONN)             ||
        return $self->setError (600, "Call to POSIX function listen failed.");
 
    ## undock from parent process
    setpgrp (0, 0);
    POSIX::setsid();

  IPCLOOP: while (1) {

      $self->debug ("IPCLOOP: wait for clients");
      accept (Client, Server) || next;

      ## we cannot fork again because perl create
      ## completely independent processes

      $self->debug ("IPCLOOP: accepted connection from client");

      ## load message
      my $load = "";
      my $line;
      while (defined ($line = <Client>))
      {
          $load .= $line;
          last if ($load =~ /\n\n$/s);
          $self->debug ("IPCLOOP: message until now: $load");
      }
      shutdown (Client, 0);
      $self->debug ("IPCLOOP: message received");

      ## parse message
      my ($filename, $xpath, $counter) = $self->parseMessage ($load);

      ## get the answer
      my $answer = $self->getXML ($filename, $xpath, $counter);
      utf8::encode($answer);

      $self->debug ("IPCLOOP: answer: $answer");
 
      ## send the answer
      $self->debug ("IPCLOOP: write answer to socket");
      if (defined $answer)
      {
          if (length ($answer) == 0)
          {
              send (Client, "\x00\n", 0);
          } else {
              send (Client, $answer, 0);
          }
      } else {
          $self->doLog ("Sending no answer because of an error.\n".
                        "-----BEGIN REQUEST-----\n".
                        $load.
                        "-----END REQUEST-----\n");
      }
      shutdown (Client, 1);

      ## automatic next IPCLOOP
      $self->debug ("IPCLOOP: request completed");
      
    } ## end of while (1) loop
  } else {
    $self->debug ("startDaemon: daemon cannot fork so startup failed");
    ## print to LOGFILE the startup

    $self->doLog ("startDaemon failed at ".
           gmtime ()." UTC PID: ".sprintf ("%d", $pid)."\n");
    
    return $OpenCA::XML::Cache::ERROR->{FORK_FAILED};
  }
}

sub parseMessage {
  my $self = shift;
  my $message = $_[0];
  my $help = "1";

  $self->debug ("IPCLOOP: received message: $message");

  ## 1. read the filename
  my $filename = $message;
  $filename =~ s/\n.*$//s;
  $message =~ s/^[^\n]*\n//s;
  $self->debug ("IPCLOOP: xml-file: $filename");

  ## read the xpaths and counters
  my @xpath = ();
  my @counter = ();
  my $i = 0;
  while ($message and $message !~ /^\n/)
  {
    ## read the xpath
    $xpath[$i] = $message;
    $xpath[$i] =~ s/\n.*$//s;
    $message =~ s/^[^\n]*\n//s;
    $self->debug ("IPCLOOP: xpath: $xpath[$i]");

    ## read the counter
    $counter[$i] = $message;
    $counter[$i] =~ s/\n.*$//s;
    $message =~ s/^[^\n]*\n//s;
    $self->debug ("IPCLOOP: counter: $counter[$i]");

    $i++;
  }

  return ($filename, \@xpath, \@counter);
}

sub getXML
{
    my $self = shift;
    my $filename = $_[0];
    my $xpath    = $_[1];
    my $counter  = $_[2];
    my $twig;

    ## use first level cache
    my $result = $self->getCached (
                     FILENAME => $filename,
                     XPATH    => $xpath,
                     COUNTER  => $counter);
    return $result if (defined $result);

    ## create Twig object
    if (not $self->{CACHE} or not $self->{CACHE}->{$filename})
    {
        $self->{CACHE}->{$filename} = new XML::Twig;
        if (not $self->{CACHE}->{$filename})
        {
            my $msg = "Server: Cannot create new instance of XML::Twig\n";
            print STDERR $msg;
            return $self->setError (100, $msg);
        }
        if (not $self->{CACHE}->{$filename}->safe_parsefile($filename))
        {
            my $msg = "Server: XML::Twig cannot parse file $filename\n".
                      "Error: $@\n";
            print STDERR $msg;
            delete $self->{CACHE}->{$filename};
            return $self->setError (100, $msg);
        }
    }

    ## use second level cache
    $twig = $self->{CACHE}->{$filename};

    my $ent = $twig;
    my $h_xpath = "";
    $counter = [ reverse @{$counter} ];
    foreach my $xp (@{$xpath})
    {
        $h_xpath .= "/".$xp."/".$counter->[scalar @{$counter}-1];
        my @path = $ent->get_xpath ($xp);
        if ($counter->[scalar @{$counter}-1] < 0)
        {
            ## return the number of elements
            return scalar @path;
        }
        if (not @path)
        {
            $ent = undef;
            last;
        }
        $ent = $path[pop @{$counter}];
    }
    if (not $ent)
    {
        return $self->setError (200, "Server: Entity does not exist (".
                                 "filename: $filename, ".
                                 "xpath: $h_xpath).") if (not $ent);
    }

    $self->updateCache (
        FILENAME => $filename,
        XPATH    => $xpath,
        COUNTER  => $_[2],
        VALUE    => $ent->field);

    return $ent->field;
}

sub updateCache
{
    my $self = shift;
    my $keys = { @_ };

    my $filename = $keys->{FILENAME};
    my $counter  = $keys->{COUNTER};
    my $xpath    = $keys->{XPATH};
    my $value    = $keys->{VALUE};

    ## fix counter array for cache
    $counter->[scalar @{$counter}-1] = -1
        if ($counter->[scalar @{$counter}-1] < 0);

    ## build cache string
    my $string = $self->getCacheString (XPATH => $xpath, COUNTER => $counter);

    ## store value
    $self->{XPATH_CACHE}->{$filename}->{$string} = $value;

    return 1;
}

sub getCached
{
    my $self = shift;
    my $keys = { @_ };

    my $filename = $keys->{FILENAME};
    my $counter  = $keys->{COUNTER};
    my $xpath    = $keys->{XPATH};

    ## fix counter array for cache
    $counter->[scalar @{$counter}-1] = -1
        if ($counter->[scalar @{$counter}-1] < 0);

    ## undef is not an error here !

    ## return $self->setError (300, "XPATH_CACHE does not exist.")
    return undef
        if (not exists $self->{XPATH_CACHE});
    ## return $self->setError (300, "File $filename does not exist in XPATH_CACHE.")
    return undef
        if (not exists $self->{XPATH_CACHE}->{$filename});

    ## build cache string
    my $string = $self->getCacheString (XPATH => $xpath, COUNTER => $counter);

    ## return $self->setError (300, "The xpath $string does not exist for file $filename in XPATH_CACHE.")
    ##    if (not exists $self->{XPATH_CACHE}->{$filename}->{$string});
    return $self->{XPATH_CACHE}->{$filename}->{$string};
}

sub getCacheString
{
    my $self = shift;
    my $keys = { @_ };
    my $counter  = [ reverse @{$keys->{COUNTER}} ];
    my $xpath    = $keys->{XPATH};
    my $string   = "";

    foreach my $xp (@{$xpath})
    {
        $string .= "<".$xp.">";
        $string .= pop @{$counter};
    }

    return $string;
}

sub stopDaemon {
  my $self = shift;

  ## load PID
  my $s_pid = $self->getPID($_[0]);

  ## stop daemon
  ## actually no clean daemon shutdown is implemented
  ## if fork on the daemon not failed this should not be 
  ## a problem
  kill 9, $s_pid;

  $self->doLog ("killing XML Cache Daemon with PID ".$s_pid." at ".gmtime ()."UTC\n"); 

  unlink $self->{SOCKET_FILE};

  return 1;
}

#####################################
##         client functions        ##
#####################################

sub get_xpath
{
  my $self = shift;

  ## check and fix the variables

  return $self->get_xpath_all (@_)
      if (wantarray);

  delete $self->{COUNTER}; 
  $self->_init (@_); 

  return $self->setError (400, "Client: The function get_xpath requires a filename.")
      if (not $self->{FILENAME});
  return $self->setError (400, "Client: The function get_xpath requires a xpath.")
      if (not $self->{XPATH});

  if (ref ($self->{XPATH}) eq "ARRAY")
  {
      my @help;
      if (ref ($self->{COUNTER}) eq "ARRAY")
      {
          @help = @{$self->{COUNTER}};
      } else {
          @help = ($self->{COUNTER});
      }
      $self->{COUNTER} = [ @help, "0" ]
          if (scalar @{$self->{XPATH}} > scalar @help);
  } else {
      $self->{COUNTER} = 0 if (not $self->{COUNTER});
  }

  ## prepare the message
  ##
  ## format   ::= filename . "\n" . element+ . \n
  ## element  ::= xpath . "\n" . counter . "\n" 
  ## 

  my $load .= $self->{FILENAME}."\n";
  if (ref ($self->{XPATH}) eq "ARRAY")
  {
    $self->{COUNTER} = [ reverse @{$self->{COUNTER}} ];
    foreach my $xpath (@{$self->{XPATH}})
    {
      $load .= $xpath."\n";
      $load .= pop (@{$self->{COUNTER}})."\n";
    }
  } else {
    $load .= $self->{XPATH}."\n";
    $load .= $self->{COUNTER}."\n";
  }
  $load .= "\n";
  $self->debug ("get_xpath: send message: $load");

  ## connect to socket

  $self->debug ("connect to socket $self->{SOCKET_FILE}");
  my $socket = $self->{SOCKET_FILE};
  socket(SOCK, PF_UNIX, SOCK_STREAM, 0) ||
      return $self->setError (500, "Client: The POSIX function socket failed.");
  connect(SOCK, sockaddr_un($socket))	||
      return $self->setError (500, "Client: The POSIX function connect failed.");

  ## send message

  $self->debug ("get_xpath: sending message");
  return $self->setError (500, "Client: Cannot send data to XML::Cache server.")
      if (not send (SOCK, $load, 0));
  shutdown (SOCK, 1);
  my $msg = $load;
  $load = "";
  
  ## read answer

  $self->debug ("get_xpath: reading answer");
  my $length = 0;
  my $line;
  while (my $h = read (SOCK, $line, 100))
  {
      $length += $h;
      $load .= $line;
  }
  $load = "" if ($load eq "\x00\n");
  shutdown (SOCK, 0);
  if ($length == 0)
  {
    $self->setError ("Client: The answer for the following message signals an error.\n$msg");
    $load = undef;
  }
  ## $load = undef if (not $load and $load ne "\0");
  
  $self->debug ("get_xpath: received info: $load");
  $self->debug ("all ok");
  $self->{USAGE_COUNTER}++;

  $self->_cleanup (@_);
  return $load;
}

sub get_xpath_all
{
    my $self = shift;
    my @result = ();
    my $help;
    my $counter = 0;

    my $keys = { @_ };
    if (not $keys->{COUNTER})
    {
        $keys->{COUNTER} = ();
    }
    if (ref ($keys->{COUNTER}) ne "ARRAY")
    {
        my $help = $keys->{COUNTER};
        delete $keys->{COUNTER};
        if (defined $help)
        {
            $keys->{COUNTER}->[0] = $help;
        } else {
            $keys->{COUNTER} = ();
        }
    }
    if (ref ($keys->{XPATH}) ne "ARRAY")
    {
        my $help = $keys->{XPATH};
        delete $keys->{XPATH};
        $keys->{XPATH}->[0] = $help;
    }

    push @{$keys->{COUNTER}}, $counter;
    while ($help = $self->get_xpath (
                       FILENAME => $keys->{FILENAME},
                       XPATH    => $keys->{XPATH},
                       COUNTER  => $keys->{COUNTER}))
    {
        pop @{$keys->{COUNTER}};
        $result [$counter++] = $help;
        push @{$keys->{COUNTER}}, $counter;
    }

    return @result;
}

sub get_xpath_count
{
    my $self = shift;
    my @result = ();
    my $help;
    my $counter = 0;

    my $keys = { @_ };
    if (not defined $keys->{COUNTER})
    {
        $keys->{COUNTER} = ();
    }
    if (ref ($keys->{COUNTER}) ne "ARRAY")
    {
        my $help = $keys->{COUNTER};
        delete $keys->{COUNTER};
        if (defined $help)
        {
            $keys->{COUNTER}->[0] = $help;
        } else {
            $keys->{COUNTER} = ();
        }
    }
    if (ref ($keys->{XPATH}) ne "ARRAY")
    {
        my $help = $keys->{XPATH};
        delete $keys->{XPATH};
        $keys->{XPATH}->[0] = $help;
    }

    if ($keys->{COUNTER})
    {
        $keys->{COUNTER} = [ @{$keys->{COUNTER}}, "-1" ];
    } else {
        $keys->{COUNTER} = [ -1 ];
    }
    $help = $self->get_xpath (
                       FILENAME => $keys->{FILENAME},
                       XPATH    => $keys->{XPATH},
                       COUNTER  => $keys->{COUNTER});

    return $help;
}

###############################################
##          additonal help functions         ##
###############################################

sub getPID
{
    my $self = shift;
 
    my $fifo = $_[0] if ($_[0]);
    $fifo = $self->{PIDFILE} if (not $fifo); 
 
    ## getting pid from PIDFILE
    if (not open (FD, "<".$fifo)) {
        return $openCA::XML::Cache::ERROR->{OPEN_PIDFILE_FAILED};
    }

    ## I do not know PIDs longer than 10 charcters
    my $s_pid;
    read (FD, $s_pid, 10);

    return int ($s_pid);
}

sub errno {
    my $self = shift;

    return $self->{errno};
}

sub errval {
    my $self = shift;

    return $self->{errval};
}

sub setError {
    my $self = shift;

    $self->{errno}  = $_[0];
    $self->{errval} = $_[1];

    $self->doLog ("Error ".$self->{errno}.": ".$self->{errval});

    return undef;
}

sub DESTROY
{
    my $self = shift;
}

1;
