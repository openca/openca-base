## OpenCA::UI::HTML.pm 
##
## Written by Michael Bell for the OpenCA project 2003
## Copyright (C) 2003-2004 The OpenCA Project
## All rights reserved.
##
##    This library is free software; you can redistribute it and/or
##    modify it under the terms of the GNU Lesser General Public
##    License as published by the Free Software Foundation; either
##    version 2.1 of the License, or (at your option) any later version.
##
##    This library is distributed in the hope that it will be useful,
##    but WITHOUT ANY WARRANTY; without even the implied warranty of
##    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
##    Lesser General Public License for more details.
##
##    You should have received a copy of the GNU Lesser General Public
##    License along with this library; if not, write to the Free Software
##    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
##

use strict;
use utf8;

package OpenCA::UI::HTML;

use CGI qw/-no_undef_params -private_tempfiles :standard/;;
use Locale::Messages (':locale_h');
use Locale::Messages (':libintl_h');
use Digest::SHA1 qw( sha1_hex );

use FileHandle;
our ($STDERR, $STDOUT);
$STDOUT = \*STDOUT;
$STDERR = \*STDERR;

our ($errno, $errval, $user);

($OpenCA::UI::HTML::VERSION = '$Revision: 1.40 $' )=~ s/(?:^.*: (\d+))|(?:\s+\$$)/defined $1?"0\.9":""/eg;

use constant {
	XENROLL => qq{
    <!-- Use the Microsoft ActiveX control to install the certificate -->
    <object classid="clsid:43f8f289-7a20-11d0-8f06-00c04fc295e1"
        codebase=xenroll.dll id=certHelperOld>
    </object>
    <object classid= "clsid:127698e4-e730-4e5c-a2b1-21490a70c8a1"
        codebase=xenroll.dll id=certHelperNew>
    </object>
    },
};

##################################
##       initialization         ##
##################################

## Create an instance of the Class
sub new {
    my $that = shift;
    my $class = ref($that) || $that;

    my $self = {
                DEBUG         => 0,
                CONTENT_TYPE  => 0,
                debug_fd      => $STDOUT,
                DEAD_ON_ERROR => 0,
               };

    bless $self, $class;

    my $keys = { @_ };

    ## this class expects the following parameters:
    ##     - HTDOCS_URL_PREFIX
    ##     - LANGUAGE
    ##
    ## we try to handle all types of malformed parameters

    foreach my $help (keys %{$keys}) {
        if ($help =~ /LANG/i) {
            $self->{LANG} = $keys->{$help};
	} elsif ($help =~ /CHARSET/i) {
            $self->{CHARSET} = $keys->{$help};
        } elsif ($help =~ /(HTDOCS|URL|PREFIX)/i) {
            $self->{HTDOCS} = $keys->{$help};
        } elsif ($help =~ /(TOP_LOGO)/i) {
            $self->{TOP_LOGO} = $keys->{$help};
        } elsif ($help =~ /(SUPPORT_EMAIL)/i) {
            $self->{SUPPORT_EMAIL} = $keys->{$help};
        } elsif ($help =~ /(ENABLE_LOGIN)/i) {
            $self->{ENABLE_LOGIN} = 1 if ( $keys->{$help} !~ /0|N/i );
        } elsif ($help =~ /(USER)/i) {
            $self->{USER} = $keys->{$help};
        } elsif ($help =~ /CGI/i) {
            $self->{CGI} = $keys->{$help};
        } else {
            print STDERR i18nGettext ("OpenCA::UI::HTML->new: ignoring wrong parameter __NAME__",
                                      "__NAME__", $help);
        }
    }

    if ( not defined $self->{USER} ) {
	# print STDERR "HTML::Checking for the global variable...\n";
	$self->{USER} = $user;
    }

    if ( $self->{DEBUG} ) {
    	print STDERR "HTML::USER-> (" . $self->{USER} . ") LOGIN => " .
		$self->{USER}->{LOGIN} . "\n";
    	print STDERR "HTML::TOP_LOGO-> " . $self->{TOP_LOGO} . "\n";
    	print STDERR "HTML::ENABLE_LOGIN-> " . $self->{ENABLE_LOGIN} . "\n";
    };

    ## preparing CGI for object oriented handling
    $self->{CGI} = new CGI if (not exists $self->{CGI});

    return $self;
}

sub setLanguage
{
    my $self = shift;
    $self->{LANG}    = $_[0];
    $self->{CHARSET} = $_[1];
    return 1;
}

sub reset
{
    my $self = shift;
    $self->{CONTENT_TYPE} = 0;
    return 1;
}

##################################
##       debug handling         ##
##################################

sub sendDebug {

    my $self = shift;
    if ($_[0]) {
        $self->{debug_msg}[scalar @{$self->{debug_msg}}] = $_[0];
        $self->debug () if ($self->{DEBUG});
    } else {
        $self->sendContentType();
        my $msg;
        foreach $msg (@{$self->{debug_msg}}) {
            $msg =~ s/ /&nbsp;/g;
            my $oldfh = select $self->{debug_fd};
            print $msg."<br>\n";
            select $oldfh;
        }
        $self->{debug_msg} = ();
    }
}

##################################
##       error handling         ##
##################################

sub configError {
    my $self = shift;
    my @keys = @_;
    my $err = $keys[0];
    my $errNo = ( $keys[1] or 600 );
    my $name = undef;
    my $exp = undef;

    my @stack = ();

    my ($hidden_list, $info_list, $cmd_panel) = (undef, undef, undef);

    ## fix errorstring for HTML
    $err =~ s/\n(?!<br>)/<br>\n/g;

    $name = gettext ("Configuration Error");
    $exp  = '<span style="color: red;">' . gettext ("Error Code: $errNo") .
    		'</span>';

    $cmd_panel->[0] = '<input type="button" value="Back" ' .
    			'onClick="history.back();" />';
			
    if( $keys[2] ne "" ) {
    	$cmd_panel->[0] .= '&nbsp;' . '<input type="button" value="' .
		$keys[2] . "\" onClick='window.location.href=\"" .
			$keys[3] . "\";' />";
    };

    $info_list->{BODY}->[0]->[0] = "&nbsp;";
    $info_list->{BODY}->[0]->[1] = "$err";

    if( $self->{DEBUG} ) {
    	my $i = 0;
    	while ( @stack = caller ( $i++ ) ) {
		$info_list->{BODY}->[$i]->[0] = "Caller [$i]";
		$info_list->{BODY}->[$i]->[1] = join ( "<br/>\n", @stack );
		$info_list->{BODY}->[$i]->[1] =~ s/\n<br\/>\n//g;
	}
    }

    $self->libSendReply (
		"NAME"        => $name,
		"EXPLANATION" => $exp,
		"CMD_PANEL" => $cmd_panel,
		"INFO_LIST" => $info_list,
		"MENU" => 1,
	);

    $self->{DEAD_ON_ERROR} = 1;

    die i18nGettext ("OpenCA: Config error trapped __ERRNO__: __ERRVAL__",
                     "__ERRNO__", $errNo,
                     "__ERRVAL__", $err);
}

sub generalError {
    my $self = shift;
    my @keys = @_;
    my $err = $keys[0];
    my $errNo = $keys[1];
    my $name = undef;
    my $exp = undef;

    my @stack = ();

    my ($hidden_list, $info_list, $cmd_panel) = (undef, undef, undef);

    $errNo = 700 if ( not $errNo);

    ## fix errorstring for HTML
    $err =~ s/\n(?!<br>)/<br>\n/g;


    $name = gettext ("General Error");
    $exp  = '<span style="color: red;">' . gettext ("Error Code: $errNo") .
    		'</span>';

    $cmd_panel->[0] = '<input type="button" value="Back" ' .
    			'onClick="history.back();" />';
			

    if( $keys[2] ne "" ) {
    	$cmd_panel->[0] .= '&nbsp;' . '<input type="button" value="' .
		$keys[2] . "\" onClick='window.location.href=\"" .
			$keys[3] . "\";' />";
    };

    $info_list->{BODY}->[0]->[0] = "&nbsp;";
    $info_list->{BODY}->[0]->[1] = "$err";

    if( $self->{DEBUG} ) {
    	my $i = 0;
    	while ( @stack = caller ( $i++ ) ) {
		$info_list->{BODY}->[$i]->[0] = "Caller [$i]";
		$info_list->{BODY}->[$i]->[1] = join ( "<br/>\n", @stack );
		$info_list->{BODY}->[$i]->[1] =~ s/\n<br\/>\n//g;
	}
    }

    $self->libSendReply (
		"NAME"        => $name,
		"EXPLANATION" => $exp,
		"CMD_PANEL" => $cmd_panel,
		"INFO_LIST" => $info_list,
		"MENU" => 1,
	);

    $self->{DEAD_ON_ERROR} = 1;

    die i18nGettext ("OpenCA: General error trapped __ERRNO__: __ERRVAL__",
                     "__ERRNO__", $errNo,
                     "__ERRVAL__", $err);
}

sub dead_on_error
{
    my $self = shift;
    return $self->{DEAD_ON_ERROR};
    
}

##################################
##       normal output          ##
##################################

sub sendContentType {
    my $self = shift;

    if (not $self->{CONTENT_TYPE}) {
        my $ct = "text/html";
        $ct = $_[0] if ($_[0]);
    	print $STDOUT $self->{CGI}->header( 
		-type=>"$ct",
		-charset=>$self->{CHARSET} );
        # print $STDOUT "Content-Type: $ct\n\n";
        $self->{CONTENT_TYPE} = $ct;
    }

    return $self->{CONTENT_TYPE};
}

sub libSendReply
{
    my $self = shift;
    my $keys = { @_ };
    my $page = "";
    my $onload = "";
    my $os = "";
    my $os_ver = 0;
    my $xsrf_protection_token = undef;
    my $session_id = undef;
    my $displayMenu = 1;
    my @scripts = ();
    my $extraHead = undef;
    my $onLoad = undef;
    my $scriptBase = undef;
    my $scriptGeneral = undef;
  
    if( $keys->{MENU} ne "" )
		{
	  	$displayMenu = $keys->{MENU};
    };

    $session_id = $self->{CGI}->param('CGISESSID');
    $xsrf_protection_token = sha1_hex($session_id);

    $os = $self->{CGI}->param('AGENT_OS_NAME');
    $os_ver = $self->{CGI}->param('AGENT_OS_VERSION');

    $scriptBase = qq{$self->{HTDOCS}/scripts/$self->{LANG}};
    $scriptGeneral = qq{$self->{HTDOCS}/scripts/C};

    push ( @scripts, { -type => "text/Javascript",
			-src => "$scriptGeneral/tools.js" });

    push ( @scripts, { -type => "text/Javascript",
			-src => "$scriptGeneral/general.js" });

    if ( ($os =~ /WINDOWS/i) and ($os_ver < 6) ) {
		$extraHead = XENROLL;
    }

    push ( @scripts, { -type => "text/Javascript",
			-src => "$scriptGeneral/openca-menu.js" });

    if ($keys->{SIGN_FORM}) {
	push ( @scripts, { -type=>"text/Javascript", 
			   -src=> "$scriptBase/signForm.js"});

	## On Windows we need the VBScript(s)
	if ( $os =~ /WINDOWS/i ) {
		push ( @scripts, { -type => "VBScript",
				   -src => "$scriptBase/signForm.vbs"});
	}
    }

    ## Default OnLoad
    $onLoad='try { if (document.OPENCA.elements.length > 0) ' .
	    '{ document.OPENCA.elements[0].focus();}} ' .
	    'catch (e) {};';

    ## Certificate Enroll Script
    if ( $keys->{IE_ENROLL_CERT} ) {
	push( @scripts, { -type => "text/Javascript",
			  -src  => "$scriptBase/ieEnroll.js" });
        $onLoad = qq{InstallCertIE(document.OPENCA);};
    } elsif ( $keys->{VISTA_ENROLL_CERT} ) {
	push( @scripts, { -type => "text/Javascript",
			  -src  => "$scriptBase/ieVistaEnroll.js" });
        $onLoad=qq{InstallCertIE(document.OPENCA);};
   } elsif ( $keys->{NSS_ENROLL_CERT} ) {
	push( @scripts, { -type => "text/Javascript",
			  -src  => "$scriptBase/nssEnroll.js" });
        $onLoad=qq{InstallCertNSS(document.OPENCA);};
    }

    ## Certificate Request Script
    if ( $keys->{IE_REQUEST_CERT} ) {
	push( @scripts, { -type => "text/Javascript",
			  -src  => "$scriptBase/ieCSR.js" });
	$onLoad = qq{enumCSP();};
    } elsif ( $keys->{VISTA_REQUEST_CERT} ) {
	push( @scripts, { -type => "text/Javascript",
			  -src  => "$scriptBase/ieVistaCSR.js" });
	$onLoad = qq{ieInitVista();};
    } elsif ( $keys->{NSS_REQUEST_CERT} ) {
	push( @scripts, { -type => "text/Javascript",
			  -src  => "$scriptBase/nssCSR.jsn" });
    }

    $page = $self->{CGI}->start_html (
	-title   => $keys->{NAME},
	-author  => $self->{SUPPORT_EMAIL},
	-encoding=> $self->{CHARSET},
	-lang    => $self->{LANG},
	-style   => $self->{HTDOCS} . "/default.css",
	-script  => \@scripts,
	-head    => $extraHead,
	-onLoad  => $onLoad,
	-class   => 'back',
    );


  if( $displayMenu == 1 ) {
    	$page .= $self->getPageMenu ( TOKEN => $xsrf_protection_token,
			NAME => $keys->{NAME} );
  };

  if ( $keys->{TARGET} ) {
  	$page .= $self->{CGI}->start_multipart_form( 
			-method=>"POST",
                        -name  =>"OPENCA",
                        -target=>$keys->{TARGET},
                        -action=>$self->{CGI}->param("HTTP_CGI_SCRIPT" ));
  } else {
	$page .= $self->{CGI}->start_multipart_form( 
			-method=>"POST",
                        -name  =>"OPENCA",
                        -action=>$self->{CGI}->param("HTTP_CGI_SCRIPT" ));
  }

  if ( $keys->{MODE} !~ /RAW/i ) {
  $page .=
'    <center>'."\n".
'    <table class="global">'."\n".
'      <tr>'."\n".
'        <td>'."\n".
'          <div class="page_headline">'."\n";
    $page .= $keys->{NAME} if (exists $keys->{NAME});
    $page .=
'          </div>'."\n".
'        </td>'."\n".
'      </tr>'."\n";

    if (($keys->{EXPLANATION} ne "" ) or ($keys->{SIGINFO} ne "" ) ) {
    	$page .= "<tr>\n";

	if ( $keys->{EXPLANATION} ) {
	        my $exp = $keys->{EXPLANATION};
	        $exp =~ s/\n/<br>\n/g;
		$page .= qq{<td class="explanation">$exp</td>\n};
	};

	if ( $keys->{SIGINFO}) {
	        my $exp = $keys->{SIGINFO};
	        $exp =~ s/\n/<br>\n/;
	        $page .= qq{<td class="siginfo">$exp</td>\n};
	}
    	$page .= "</tr>\n";
    }

    if ($keys->{TIMESTAMP}) {
        my $strftime = gettext ('__STRFTIME_FORMAT_STRING__');
        $strftime = "%A %e %B %T UTC"
            if ($strftime eq '__STRFTIME_FORMAT_STRING__');
        $page .=
'      <tr class="timestamp">'."\n".
'        <td class="timestamp">'."\n".
POSIX::strftime($strftime, gmtime())."\n".
'        </td>'."\n".
'      </tr>'."\n";
    }

    if (exists $keys->{ITEM_LIST}) {
        my $list = $keys->{ITEM_LIST};

	if ( $keys->{MODE} =~ /STATIC/i ) {

        	$page .= qq{      <tr>
	        	<td class="global_item_list">
		  	<center>
		  	<table class="item_list">};

        	foreach my $item (@{$list}) {
            		my $b_item = shift @{$item};

            		$page .= qq{<tr class="item_list">
				<th class="item_list"> $b_item </th></tr>};

            		foreach my $b_item (@{$item}) {
                		$page .= '<tr><td class="item_list">'.
						$b_item."</td></tr>\n";
            		}
        	}
        	$page .= qq{</table>\n</center>\n</td>\n</tr>\n};
    	} else {
        	$page .= qq{<tr><td class="global_item_list">
			<center>
			<table class="item_list">
			<tr class="item_list">};

		my $class = "item_list";

		if( $list->{CLASS} ne "" ) {
			$class = $list->{CLASS};
		}

	        foreach my $item (@{$list->{HEAD}}) {
	            $page .= '<th class="'.$class.'">'.$item."</th>\n";
	        }
	        $page .= "</tr>\n";
	        foreach my $item (@{$list->{BODY}}) {
		    my $class = "item_list";

	            $page .= qq{<tr class="item_list">\n};

		    if( $list->{CLASS} ne "" ) {
			$class = $list->{CLASS};
		    }

	            foreach my $b_item (@{$item}) {
	                $page .= '<td class="'.$class.'">'.$b_item."</td>\n";
	            }
	            $page .= "</tr>\n";
	        }

        	$page .= qq{</table>\n</center>\n</td>\n</tr>\n};
	}
    };

    if (exists $keys->{INFO_LIST}) {
        my $list = $keys->{INFO_LIST};
        $page .=
'      <tr>'."\n".
'        <td class="global_info_list">'."\n".
'         <center>'."\n".
'          <table class="info_list">'."\n";
        if (exists $list->{HEAD}) {
	    my $class = "info_list";
	    
	    if( $list->{CLASS} ne "" ) {
		    $class = $list->{CLASS};
	    };
            $page .=
'            <tr class="item_list">'."\n";
            foreach my $item (@{$list->{HEAD}}) {
                $page .= '<th class="'.$class.'">'.$item."</th>\n";
            }
            $page .=
'            </tr>'."\n";
        }
        foreach my $item (@{$list->{BODY}})
        {
	    my $class = "info_list";
	    
	    if( $list->{CLASS} ne "" ) {
		    $class = $list->{CLASS};
	    };
            $page .=
'            <tr class="info_list">'."\n";
            if (scalar @{$item} == 1)
            {
                $page .= '<th colspan="2" class="'.$class.'">'.
						$item->[0]."</th>\n";
            } else {
                foreach my $b_item (@{$item}) {
                    $page .= '<td class="'.$class.'">'.$b_item."</td>\n";
                }
            }
            $page .=
'            </tr>'."\n";
        }
        $page .=
'          </table>'."\n".
'         </center>'."\n".
'        </td>'."\n".
'      </tr>'."\n";
    }

    if (exists $keys->{CMD_LIST}) {
        my $list = $keys->{CMD_LIST};
        $page .=
'      <tr>'."\n".
'        <td class="global_cmd_list">'."\n".
'         <center>'."\n".
'          <table class="cmd_list">'."\n";
        if ($list->{HEAD})
        {
            $page .=
'            <tr class="cmd_list">'."\n";
            if (scalar @{$list->{HEAD}} == 1)
            {
                $page .= '<th class="cmd_list" colspan="2">'.$list->{HEAD}->[0]."</th>\n";
            } else {
                foreach my $item (@{$list->{HEAD}})
                {
                    $page .= '<th class="cmd_list">'.$item."</th>\n";
                }
            }
            $page .=
'            </tr>'."\n";
        }
        foreach my $item (@{$list->{BODY}})
        {
            $page .=
'            <tr class="cmd_list">'."\n";
            foreach my $b_item (@{$item})
            {
                $page .= '<td class="cmd_list">'.$b_item."</td>\n";
            }
            $page .=
'            </tr>'."\n";
        }
        $page .=
'          </table>'."\n".
'        </td>'."\n".
'      </tr>'."\n";
    }

    if (exists $keys->{CMD_PANEL}) {
        my $list = $keys->{CMD_PANEL};
        $page .=
'      <tr>'."\n".
'        <td class="global_cmd_panel">'."\n".
'         <center>'."\n".
'          <table class="cmd_panel">'."\n".
'            <tr class="cmd_panel">'."\n";
        foreach my $item (@{$list})
        {
            $page .= '<td class="cmd_panel">'.$item."</td>\n";
        }
        $page .=
'            </tr>'."\n".
'          </table>'."\n".
'         </center>'."\n".
'        </td>'."\n".
'      </tr>'."\n";
    }

    $page .= qq{</table>\n};
    } else {
	## RAW mode (Body is taken raw.. it is used for the homepage
	$page .= qq{ $keys->{BODY} };
    }

    my $xsrf_protection_token = sha1_hex($self->{CGI}->param('CGISESSID'));

    $keys->{HIDDEN_LIST}->{xsrf_protection_token} = $xsrf_protection_token;
    if (exists $keys->{HIDDEN_LIST}) {

        my $list = $keys->{HIDDEN_LIST};

        foreach my $item (keys %{$list}) {
            ## this is an error handling for erroneous browsers
            ## text contains data for signing
            if ($item eq "text") {
                $list->{$item} =~ s/\r//g;       ## cleanup CR
                $list->{$item} =~ s/\n/\r\n/g;   ## LF --> CRLF
            }
            $page .= qq{<input type="hidden" name="$item" } .
		     qq{value="} . $list->{$item} . qq{" />\n};
        }
    }

    if ( $displayMenu ) {
    	$page .= $self->getFooter() . "\n";
    }

    $page .=qq{</center>\n</form>\n</body>\n</html>\n};

    $page = $self->addXSRFProtectionTokenToLinks($page);
    $self->sendContentType();

    print $STDOUT $page;

    return 1;
}

sub addXSRFProtectionTokenToLinks {
    my $self       = shift;
    my $page       = shift;
    my $body	   = undef;

    my $session_id = $self->{CGI}->param('CGISESSID');
    my $xsrf_protection_token = sha1_hex($session_id);

    # $page =~ s/(<a[^>]+href="[^">]*\?[^">]+)/$1;xsrf_protection_token=$xsrf_protection_token/g;
    $page =~ s/(\?cmd=[^"'>]+)(['"])/$1;xsrf_protection_token=${xsrf_protection_token}$2/g;
    return $page;
}


##################################
##      logging output          ##
##################################

sub startLogPage {

    my $self  = shift;
    my $title = shift;
    my $ret;

    my $session_id = undef;
    my $xsrf_protection_token = undef;

    $session_id = $self->{CGI}->param('CGISESSID');
    $xsrf_protection_token = sha1_hex($session_id);

    $title = gettext ("Proceeding") if ( not $title );

    $ret = $self->{CGI}->start_html(-title=>$title,
                              -lang     => $self->{LANG},
                              -encoding => $self->{CHARSET},
			      -script   => {
				    -type=>'text/Javascript',
			            -src=> $self->{HTDOCS}.'/scripts/'.
					$self->{LANG}.'/openca-menu.js'},
			      -style=>{'src'=> $self->{HTDOCS} .
			      				'/default.css'},
			      -charset=> $self->{CHARSET},
			      -class => 'back',
                              -BGCOLOR  => "#FFFFFF",
                              -TEXT     => "#445599" );

    $ret .= $self->getPageMenu (
		TOKEN => $xsrf_protection_token,
		NAME  => "$title");

    $ret .= qq{ <center>
    <table class="global">
      <tr>
        <td>
          <div class="page_headline">} . gettext("Log") . 
	qq{</div>
        </td>
      </tr>};

    my $strftime = gettext ('__STRFTIME_FORMAT_STRING__');
    $strftime = "%A %e %B %T UTC"
            if ($strftime eq '__STRFTIME_FORMAT_STRING__');
    $ret .= qq{ <tr class="timestamp">
        <td class="timestamp">} .  POSIX::strftime($strftime, gmtime()) .
        qq{        </td>
		</tr>};

    my $exp = $title . "<br />" . 
	      gettext ("Please wait until operation completes");

    $exp =~ s/\n/<br \/>\n/g;
    $ret .= qq{<tr><td class="explanation">$exp</td></tr>\n};

    # $ret .=  "<CENTER>";
    # $ret .=  "<FONT SIZE=\"+3\">";
    # $ret .=  "<B>$title</B></FONT><BR>\n";
    # $ret .=  "<FONT SIZE=\"+1\">";
    # $ret .=  "(".gettext ("Please wait until operation completes").")</FONT><BR>\n";
    # $ret .=  "<HR WIDTH=80%>";
#     $ret .=  "</CENTER>\n";
    $ret .= qq{ <tr><td class="global_item_list">
                <center>
    		<div class="log">};

    utf8::decode($ret);

    return $ret;
}


sub closeLogPage {

    my $self = shift;
    my $ret = "";

    $ret = qq{<!-- Closing Log Page -->};
    $ret .= "</div></center></td></tr>\n";
    $ret .= qq{<!-- Footer -->};
    # $ret .= "</CENTER>\n";
    # $ret = "<CENTER><HR WIDTH=\"80%\"></CENTER>";

    $ret .= "</tbody></table>\n";
    $ret .= $self->getFooter() . "\n";

    $ret .= qq{</center>\n</form>\n</body>\n</html>\n};

    $ret = $self->addXSRFProtectionTokenToLinks($ret);
    # $ret .= $self->{CGI}->end_html();

    utf8::decode($ret);

    return $ret;
}

sub addLogSection {
    my $self = shift;
    my $line = shift;
    my $ret;

    $ret = "<FONT SIZE=+1><FONT FACE=\"Arial, Helvetica\">\n";
    $ret .= $line;

    utf8::decode($ret);
    return $ret;
}

sub closeLogSection {
    my $self = shift;
    my $line = shift;
    my $ret;

    $ret = "</FONT></FONT>\n";

    return $ret;
}

sub addErrorLog {
    my $self = shift;
    my $line = shift;
    my $code  = ( shift or $? );

    my $ret;

    $ret  = "<BR><BR>$line<BR><BR>\n";
    $ret .= "<TT><FONT SIZE=-1 COLOR=red>";
    $ret .= "<PRE>$code</PRE></FONT></TT>\n";

    utf8::decode($ret);
    return $ret;
}

sub addLogLine {
    my $self = shift;
    my $line = shift;
    my $ret;

    $ret  = "$line<BR>\n";

    utf8::decode($ret);
    return $ret;
}

sub addPreLogLine {
    my $self = shift;
    my $line = shift;
    my $ret;

    $ret  = "<TT><FONT SIZE=-1 COLOR=#445567>";
    $ret .= "<PRE>$line</PRE></FONT></TT>\n";

    utf8::decode($ret);
    return $ret;
}

sub getPageMenu {
  my $self = shift;
  my $keys = { @_ };

  my $ret = "";
  my $token = $keys->{TOKEN};
  my $prefix = $self->{HTDOCS};
  my $script = $self->{CGI}->param( 'HTTP_CGI_SCRIPT');

  $ret .= qq{ <table cols="2" class="toprow">
		<tbody>
		  <tr><td rowspan="2">};

  if ( $self->{TOP_LOGO} ) {
  	$ret .= qq{<div class="footerleft">
		<img src="} . $self->{TOP_LOGO} . qq{" />
	   </div>};
  }

  $ret .= qq{</td><td>};

  $keys->{NAME} = "PKI" if ( $keys->{NAME} eq "");
  $keys->{NAME} .= " Support";
  $keys->{NAME} = gettext( $keys->{NAME} );
  $keys->{NAME} =~ s/[\ ]+/%20/g;

  if ( $self->{ENABLE_LOGIN} ) {
	if ( defined $self->{USER}->{LOGIN} ) {
  		$ret .= qq{<form name="user">};
  		$ret .= qq{<div class="footerright" } .
			qq{style="font-size: 0.8em; text-align: right;"}.
			qq{ >} . gettext ("Welcome") . ", " .
				$self->{USER}->{LOGIN} .
			qq{ <br /><a href="$script?cmd=logout" } .
			qq{ style="color: grey;">} .  gettext("Log Off") .
			qq{</a>};
  		$ret .= qq{</div></form>};
	} else {
  		$ret .= qq{<form>};
  		$ret .= qq{<input type="hidden" name="cmd" value="login" />\n};
  		$ret .= qq{<div class="footerright" style="color: white;"> } .
		  gettext ("User") . 
			qq{: <input type="textfield" class="medium"/> } .
		  gettext ("Secret") .
			qq{: <input type="password" class="medium"/> } .
		  	qq{ <input type="Submit" value="} . 
				gettext ("Login") . qq{" class="small"/> } .
		  	qq{ or <input type="button" value="} . 
				gettext ("Sign Up") . qq{" class="small" 
				onClick="location.href = '?cmd=getParams;GET_PARAMS_CMD=newUser';" />
			</div>};
  		$ret .= qq{</form>};
	};
  }

  $ret .= qq{</td></tr>};
  $ret .= qq{<tr ><td valign="bottom" style="text-align: right;">};
  if ( $self->{SUPPORT_EMAIL} ne "" ) {
	$ret .= qq{	<a href="mailto:} . $self->{SUPPORT_EMAIL} .
		qq{?subject=} . $keys->{NAME} . qq{">
		<img src="$prefix/images/email_link.png" 
				style="vertical-align: top;" /> } .
			gettext("Email") .
		qq{ </a> | };
  }

  $ret .= qq{
		<a href="" onClick="print(); return false;">
		<img src="$prefix/images/print_link.png" 
				style="vertical-align: top;" /> 
			Print
		</a>
	     };

  $ret .= qq{</td></tr>};
  $ret .= qq{</tbody></table>};
	

  $ret .=
    '  <div id="menu">' . "\n" .
    '  <script>genXMLMenu( "' . $self->{HTDOCS} . "/menu/" . $self->{LANG} .
	'/menu.xml","menu", ";xsrf_protection_token=' . $token . '")' .
	'</script>'."\n" .
    '  </div>' . "\n";

  # utf8::decode($ret);
  return $ret;
}

##################################
##      internal functions      ##
##################################

sub getFooter {

    my $self = shift;

    my $ret = "<br /><br />";
    my $prefix = $self->{HTDOCS};
    my $script = $self->{CGI}->param( 'HTTP_CGI_SCRIPT');

		my @now = gmtime();
		my $year = $now[5] + 1900;

    my @footer_left = (
	### FORMAT is:
	### [ "NAME", LINK, IMAGE_FILE, LOGIN_REQUIRED ]
	### [ "Home", "cmd=getStaticPage;name=homePage", "home", 0 ],
	[ "Search", "cmd=getStaticPage;name=search_cert", "search", 0],
	[ "My Certs", "cmd=viewMyCerts", "certicon_small", 1 ],
	[ "My Profile", "cmd=viewProfile", "profileicon", 1 ],
	);
	
    my @footer_right = (
	[ "Messages", "cmd=messageCenter", "message_new", 1 ],
	[ "Notices", "cmd=noticeList", "notice_new", 1 ],
	# [ "Log Out", "cmd=logout", "logout", 1 ],
    );

    ## Close the Table
    $ret .= qq{ <table classname="nav" class="nav" cols="2">
		<tbody>
		  <tr classname="menurow" class="menurow">};

	$ret .= $self->getMenuItems ( CLASS=> "footerleft",
			VALUES => \@footer_left );

	$ret .= $self->getMenuItems ( CLASS=> "footerright",
			VALUES => [ reverse ( @footer_right )] );

    $ret .= qq{</tr></tbody></table>\n};

    $ret .= qq{<div class="bottomrow">
    		<font style="color: #5090DA;">
			Open</font><font style="color: #ff7000;">CA</font>
		Software &copy; 1998-$year by Massimiliano Pala and the 
		<a href='http://www.openca.org' style='color: #555'> 
		OpenCA Labs</a>. <br />
    		</div>};
 
    # utf8::decode($ret);
    return $ret;
}

sub getMenuItems {

	my $self = shift;
	my $keys = { @_ };
	my @values = @{ $keys->{VALUES} };

    	my $prefix = $self->{HTDOCS};
    	my $script = $self->{CGI}->param( 'HTTP_CGI_SCRIPT');
	my $ret = "";

	$ret .= "<td>";
    	foreach my $row ( @values ) {

		my $icon_name = undef;
		my $name = undef;
		my $active_link = 0;
		my $opacity = 1;

		my ( $valName, $valLink, $valImg, $valLogin ) =
			@{ $row };

		if ( ($script =~ /node|batch/) and ( $valName =~ /Search/i )) {
			next;
		}

		if ( not $valLink ) {
			$name = gettext ("Disabled");
		} else {
			$name = gettext ( "$valName" );
		}

	 	$ret .= qq{<div class="} . $keys->{CLASS}. qq{" alt="$name" 
						title="$name" >};

		$active_link = 0;
		if ( $valLink ) {
			if ( $valLogin == 1) {
				if ( $self->{USER}->{LOGIN} ) {
					$active_link = 1;
				}
			} else {
				$active_link = 1;
			}
		}

		if ( $valImg ) {
			if ( $active_link == 0) {
				$icon_name = $valImg . "_off.png";
				$opacity = 0.5;
			} else {
				$icon_name = $valImg . ".png";
				$opacity = 1;
			}
		  $ret .= qq{<span style="opacity: $opacity;">};
	 	  $ret .= qq{<img style='vertical-align: middle' height='22' 
				src="$prefix/images/} . $icon_name . 
			   qq{" valign="center" />\n};
		}
		if ( $active_link == 1 ) {
			$ret .= qq{<a href="$script?} . $valLink . 
				qq{">$name</a>\n};
		} else {
			$ret .= gettext("$valName");
		}
		$ret .= qq{</span">};
		$ret .= qq{</div>\n};
    	}

    	$ret .= qq{</td>\n};

        # utf8::decode($ret);
	return $ret;
}


sub closePage {
    my $self = shift;

    print $self->closeLogPage();
    return 1;

    print $STDOUT "\n\n";
    print $STDOUT "</PRE><CENTER><HR WIDTH=80%></CENTER>\n";
    print $STDOUT "<FONT SIZE=\"+0\">";
    ## print $STDOUT getFooter();

    print $STDOUT "\n</BODY>\n";
    print $STDOUT "</HTML>\n";

    return 1;
}

## BUG NOTICE
## FIXME: HACK until there is OpenCA::Utilities
sub i18nGettext {

    my $i18n_string = gettext ($_[0]);

    my $i = 1;
    my $option;
    my $value;
    while ($_[$i]) {
        $i18n_string =~ s/$_[$i]/$_[$i+1]/g;
        $i += 2;
    }

    utf8::decode($i18n_string);
    return $i18n_string;
}

1;
