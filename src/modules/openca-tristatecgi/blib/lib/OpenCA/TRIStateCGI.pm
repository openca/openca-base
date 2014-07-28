## OpenCA::TRIStateCGI.pm 
##
## Copyright (C) 1998-1999 Massimiliano Pala (madwolf@openca.org)
## All rights reserved.
##
## This library is free for commercial and non-commercial use as long as
## the following conditions are aheared to.  The following conditions
## apply to all code found in this distribution, be it the RC4, RSA,
## lhash, DES, etc., code; not just the SSL code.  The documentation
## included with this distribution is covered by the same copyright terms
## 
## // Copyright remains Massimiliano Pala's, and as such any Copyright notices
## in the code are not to be removed.
## If this package is used in a product, Massimiliano Pala should be given
## attribution as the author of the parts of the library used.
## This can be in the form of a textual message at program startup or
## in documentation (online or textual) provided with the package.
## 
## Redistribution and use in source and binary forms, with or without
## modification, are permitted provided that the following conditions
## are met:
## 1. Redistributions of source code must retain the copyright
##    notice, this list of conditions and the following disclaimer.
## 2. Redistributions in binary form must reproduce the above copyright
##    notice, this list of conditions and the following disclaimer in the
##    documentation and/or other materials provided with the distribution.
## 3. All advertising materials mentioning features or use of this software
##    must display the following acknowledgement:
## //   "This product includes OpenCA software written by Massimiliano Pala
## //    (madwolf@openca.org) and the OpenCA Group (www.openca.org)"
## 4. If you include any Windows specific code (or a derivative thereof) from 
##    some directory (application code) you must include an acknowledgement:
##    "This product includes OpenCA software (www.openca.org)"
## 
## THIS SOFTWARE IS PROVIDED BY OPENCA DEVELOPERS ``AS IS'' AND
## ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
## IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
## ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
## FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
## DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
## OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
## HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
## LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
## OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
## SUCH DAMAGE.
## 
## The licence and distribution terms for any publically available version or
## derivative of this code cannot be changed.  i.e. this code cannot simply be
## copied and put under another distribution licence
## [including the GNU Public Licence.]
##

## Porpouse :
## ==========
##
## Build a class to use with tri-state CGI (based on CGI library)
##
## Project Status:
## ===============
##
##      Started		: 8 December 1998
##      Last Modified	: 12 Genuary 2001

use strict;

package OpenCA::TRIStateCGI;

use utf8;

use CGI qw/-no_undef_params -private_tempfiles :standard/;

@OpenCA::TRIStateCGI::ISA = ( @OpenCA::TRIStateCGI::ISA, "CGI" );
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.

$OpenCA::TRIStateCGI::VERSION = '1.5.5';

use FileHandle;
our ($STDERR, $STDOUT);
$STDOUT = \*STDOUT;
$STDERR = \*STDERR;

our ($errno, $errval);

# Preloaded methods go here.

sub set_gettext
{
    my $self = shift;
    $self->{gettext} = $_[0];
} 

## General Functions
sub status {
	my $self = shift;
	my @keys = @_;

     	my $ret = $self->param('status');
     	if ( $ret =~ /(client\-filled\-form|client\-confirmed\-form)/ ) {
		return $ret;
	} else {
        	return "start";
	};
}

## New AutoChecking Input Object

sub newInput {

	my $self = shift;
	my @keys = @_;

	my ( $ret, $error, $m );
	my ( $type, $maxlen, $minlen, $regx, $optional, $name, $values);

        ## Rearrange CGI functions changed in perl 5.6.1 - CGI ver 2.75+
        if ( $CGI::VERSION >= 2.60 ) {
                if ( ref($_[0]) ne "HASH" ) {
                        @keys = { @keys };
                }

                ( $name, $values ) = $self->rearrange(["NAME"], @keys );

                $type = $values->{'-intype'};
        } else {
         
                ( $type, $maxlen, $minlen, $regx, $optional ) =
                        $self->rearrange(["INTYPE","MAXLEN","MINLEN","REGX", "OPTIONAL"],
                                         @keys);
        }

	## Check if there is an Error
	$error = $self->newInputCheck(@_) if ( $self->status ne "start" ); 

	## Generate the Input Type
	$ret = $self->$type(@_);
     
	## Clean Out NON HTML TAGS
	$m = "(INTYPE|MAXLEN|MINLEN|REGX|OPTIONAL)=\".*\"";
	$ret =~ s/$m//g;
     
	## Concatenate the Error to the Input Object if present
	$ret .= $error;
     
	return $ret;
}

sub newInputCheck {

	my $self = shift;
	my @keys = @_;

	my ( $ret, $m, $p, $l );
	my ( $name, $values, $type, $maxlen, $minlen, $regx, $optional );

	## Rearrange CGI functions changed in perl 5.6.1 - CGI ver 2.75+
	if ( $CGI::VERSION >= 2.60 ) {
		if ( ref($_[0]) ne "HASH" ) {
			@keys = { @keys };
		}

		( $name, $values ) = $self->rearrange(["NAME"], @keys );

        	$type 	  = $values->{'-intype'};
        	$maxlen   = $values->{'-maxlen'};
        	$minlen   = $values->{'-minlen'};
        	$regx 	  = $values->{'-regx'};
        	$name 	  = $values->{'-name'};
		$optional = $values->{'-optional'};

	} else {
		( $type, $maxlen, $minlen, $regx, $name, $optional) = 
			$self->rearrange(["INTYPE","MAXLEN","MINLEN","REGX",
					   "NAME", "OPTIONAL"], @keys);
	}
     
	$p = $self->param("$name");

	return "" if ($optional and length($p) == 0);

	if( $maxlen != "" ) {
		$l = length($p);
		if ( $l > $maxlen ) {
			$ret = $self->{gettext} ("Error (max. __MAXLEN__)",
                                                 "__MAXLEN__", $maxlen);
			return $ret;
		}
	};

	if( $minlen != "" ) {
		$l = length($p);
		if ( $l < $minlen ) {
			$ret = $self->{gettext} ("Error (min. __MINLEN__)",
                                                 "__MINLEN__", $minlen);
			return $ret;
		}
	};

	if ( length($regx) < 2 ) {
		return $ret;
	};

        $m = $regx; 
        $regx = uc($regx);                          # GO UPPERCASE !
     
	$m = "[a-zA-Z\ \xA0-\xFF]+" if ( "$regx" eq "LETTERS" );
	## $m = "[a-zA-Z\ \,\.\_\:\'\`\\\/\(\)\!\;]+" if ( "$regx" eq "TEXT" );
	$m = "[ -\@a-zA-Z]+" if ( "$regx" eq "TEXT" );
	$m = "[0-9]+" if ( "$regx" eq "NUMERIC" );
	$m = "[ -\@\\x5B\\x5Da-zA-Z]+" if ( "$regx" eq "MIXED" );
	$m = "[0-9\-\/]+" if ( "$regx" eq "DATE" );
	$m = "[0-9\-\+\\\(\) ]+" if ( "$regx" eq "TEL" );
	$m = "[0-9a-zA-Z\-\_\.\+]+\@[a-zA-Z0-9\_\.\-]+" if ( "$regx" eq "EMAIL" );
	$m = '\d+\.\d+\.\d+\.\d+' if ( "$regx" eq "IPV4_ADDRESS" );

        if ( ("$regx" eq "LATIN1_LETTERS")    ||    # cert_chars == "LATIN1"
                                                    #  or lowercase analog
             ("$regx" eq "_LETTERS")          ||    # cert_chars == ""
             ("$regx" eq '@CERT_CHARS@_LETTERS') ){ # cert_chars is absent from config.xml
          $m = "[a-zA-Z\xA0-\xFF -\@]+";
          $regx = "LATIN1_LETTERS";                 # back to standart notation
        }
	
        $m = "[ -\@a-zA-Z\xA0-\xFF]+" if ( "$regx" eq "LATIN1" );

        if ( ("$regx" eq "UTF8_LETTERS")  ||        # cert_chars == "UTF8"
                                                    #  or lowercase analog
             ("$regx" eq "UTF-8_LETTERS") ||        # cert_chars == "UTF-8"
             ("$regx" eq "UTF_8_LETTERS") ) {       # cert_chars == "UTF_8"
          $m = "[ -\@\\w\\X]+";
	  utf8::decode($p);
          $regx = "UTF8_LETTERS";                   # back to standart notation
        }
       
        if ( "$regx" eq "UTF8_MIXED") {
          $m = "[ -\@\\w\\X\\d]+";
          utf8::decode($p);
        }
       
	$p =~ s/$m//g;

	if ( length($p) == 0 ) {
		$ret = "";
	} else {
		$ret .= $self->{gettext} ("Use only letters") if ( $regx eq "LETTERS" );
		$ret .= $self->{gettext} ("Use only chars") if ( $regx eq "TEXT" );
		$ret .= $self->{gettext} ("Use only LATIN1 chars") if ($regx eq "LATIN1_LETTERS");
		$ret .= $self->{gettext} ("Use only LATIN1 chars/numbers") if ( $regx eq "LATIN1");
		$ret .= $self->{gettext} ("Use only numbers") if ( $regx eq "NUMERIC" );
		$ret .= $self->{gettext} ("Use only chars and numbers.") if ( $regx eq "MIXED" );
		$ret .= $self->{gettext} ("Use xx\/xx\/xxxx format.") if ( $regx eq "DATE" );
		$ret .= $self->{gettext} ("Use ++xx-xxx-xxxxxx format.") if ( $regx eq "TEL" );
		$ret .= $self->{gettext} ("Use aabbcc\@dddd.eee.ff") if ( $regx eq "EMAIL" );
                $ret .= $self->{gettext} ("Use only UTF8 letters") if ( $regx eq "UTF8_LETTERS" );
                $ret .= $self->{gettext} ("Use only UTF8 letters and numbers") if ( $regx eq "UTF8_MIXED" );
                $ret .= $self->{gettext} ("Use aaa.bbb.ccc.ddd format.") if ( $regx eq "IPV4_ADDRESS" );
		$ret = $self->{gettext} ("Undefined Error") if ($ret eq "");

		$ret = $self->{gettext} ("Error. __ERRVAL__",
                                         "__ERRVAL__", $ret);
	}
	return $ret;
}

sub checkForm {

	my $self = shift;
	my @keys = @_;

	my ( $ret, $in, $m );
	
	for $in ( @keys ) {
		$ret .= $self->newInputCheck( %$in );
	}

	return $ret;
};

sub printError {
	my $self = shift;
	my @keys = @_;

	my ( $html, $ret );

	my $errCode = $keys[0];
	my $errTxt  = $keys[1];

	$html = $self->start_html(-title=>$self->{gettext} ("Error Accessing the Service"),
		-BGCOLOR=>'#FFFFFF');

	$html .= '<FONT FACE=Helvetica SIZE=+4 COLOR="#E54211">';
	## $html .= $self->setFont( -size=>'+4',
	## 	-face=>"Helvetica",
	## 	-color=>'#E54211');

	$html .= "Error ( code $errCode )";
	$html .= "</FONT><BR><BR>\n";
	
	$html .= '<FONT SIZE=+1 COLOR="#113388">';
	## $html .= $self->setFont( -size=>'+1',
	## 	-color=>'#113388');

	if( "$errTxt" ne "" ) {
		## The Error Code is Present in the Array, so Let us treat it...
		$html .= $errTxt;

	} else {
		## General Error Message 
		$html .= $self->{gettext} ("General Error Protection Fault : The Error Could not be determined by the server, if the error persists, please contact the system administrator for further explanation.");
	};

	$html .= "</FONT><BR>\n\n";
	$html .= "</BODY></HTML>\n\n";
        
	return $html;
}

## this functionality is part of OpenCA::Tools
## OpenCA::Tools configure files to so getFile in OpenCA::TRIStateCGI is a bug
##
## sub getFile {
## 	my $self = shift;
## 	my @keys = @_;
## 
## 	my ( $ret, $temp );
## 
## 	open( FD, $keys[0] ) || return;
## 	while ( $temp = <FD> ) {
## 		$ret .= $temp;
## 	};
## 	return $ret;
## }

sub subVar {
	my $self = shift;
	my @keys = @_;

	my ( $text, $parname, $var, $ret, $match );

	$text    = $keys[0];
	$parname = $keys[1];
	$var     = $keys[2];

	$match = "\\$parname";
	$text =~ s/$match/$var/g;

	return $text;
}

sub startTable {
	my $self = shift;
	my $keys = { @_ };

	my $width      = $keys->{WIDTH};

	my $titleColor = $keys->{TITLE_COLOR};
	my $cellColor  = $keys->{CELL_COLOR};

	my $titleBg    = $keys->{TITLE_BGCOLOR};
	my $tableBg    = $keys->{TABLE_BGCOLOR};
	my $cellBg     = $keys->{CELL_BGCOLOR};
	my $spacing    = ( $keys->{SPACING} or "1");
	my $padding    = ( $keys->{PADDING} or "1");
	my $cellPad    = ( $keys->{CELLPADDING} or "1");

	my @cols = @{ $keys->{COLS} };

	my ( $ret, $name );

	$width      = "100%" if (not $width);
	$cellColor  = "#000000" if ( not $cellColor );

	$titleBg   = "#DDDDEE" if ( not $titleBg );
	$cellBg    = "#FFFFFF" if ( not $cellBg );

	my $titleFont = "FONT FACE=Helvetica,Arial";
	$titleFont .= " color=\"$titleColor\"" if( $titleColor );
	
	$ret =  "<TABLE BORDER=0 WIDTH=\"$width\" CELLPADDING=$padding CELLSPACING=0 ";
	$ret .= "BGCOLOR=\"$tableBg\"" if ( $tableBg );
	$ret .= "><TR><TD>\n";

	$ret .= "<TABLE BORDER=0 WIDTH=\"100%\" CELLPADDING=$cellPad BGCOLOR=$cellBg";
	$ret .= " CELLSPACING=\"$spacing\" FGCOLOR=\"$cellColor\">\n";
	$ret .= "<TR BGCOLOR=\"$titleBg\">\n";

	foreach $name (@cols) {
		$ret .= "<TD><$titleFont><B>$name</B></FONT></TD>\n";
	}

	$ret .= "</TR>\n";

	return $ret;
}

sub addTableLine {
	my $self = shift;
	my $keys = { @_ };

	my @data    = @{ $keys->{DATA} };
	my $bgColor = $keys->{BGCOLOR};
	my $color   = $keys->{COLOR};

	my ( $val, $colorEnd, $ret );
	
	if( $bgColor ) {
		$ret = "<TR BGCOLOR=$bgColor>\n";
	} else {
		$ret = "<TR>\n";
	}

	if( $color ) {
		$color = "<FONT COLOR=\"$color\">";
		$colorEnd = "</FONT>";
	}

	foreach $val ( @data ) {
		$ret .= "<TD>$color $val $colorEnd</TD>\n";
	}
	$ret .= "</TR>\n";

	return $ret;
}

sub endTable {
	my $self = shift;
	my $ret;

	$ret = "</TABLE></TD></TR></TABLE><P>\n";

	return $ret;
}

sub printCopyMsg {
	my $self = shift;
	my @keys = @_;
	my $ret;

	my $msg = $keys[0];

	$msg = "&copy 1998-2004 by OpenCA Group" if ( not $msg );
	$ret = "<CENTER><BR>$msg<BR><CENTER>";

	return $ret;
}

sub buildRefs {
	my $self = shift;
	my $keys = { @_ };

	my ( $ret, $i, $link, $pages, $current, $from, $to, $title );

	my $elements    = $keys->{ELEMENTS};
	my $maxItems    = $keys->{MAXITEMS};
	my $factor	= $keys->{FACTOR};
	my $mode	= $keys->{MODE};
	my @objList	= $keys->{LIST};

	$maxItems = 50 if ( not $maxItems );

	if ($keys->{NOW_FIRST}) {
		$from = $keys->{NOW_FIRST};
	} else {
		$from = ( $self->param('viewFrom') or 0 );
	}
	if ($keys->{NOW_LAST}) {
		$to = $keys->{NOW_LAST};
	} else {
		$to = ( $self->param('viewTo') or undef );
	}

	my $first = $keys->{FIRST};
	my $last  = $keys->{LAST};

	if ( $elements == 0 or $elements < $maxItems ) {
		$title = "<DIV ALIGN=\"RIGHT\"><FONT SIZE=\"-1\">" . 
			$self->{gettext} ("No Extra References");
	} elsif ($mode =~ /EXP/i) {

		my $total_links = 0;
		$title = "<DIV ALIGN=\"RIGHT\"><FONT SIZE=\"-1\">".
                         $self->{gettext} ("Extra References");

		## fix wrong parameters
		if ($factor > $maxItems) {
			my $h     = $factor;
			$factor   = $maxItems;
			$maxItems = $h;
		}
		$factor=2 if ($factor < 2);

		## backward references

		if ($from != $first) {

			$total_links++;

			## first element
			my @list = ();

			## calculate links
			while (1) {
				my $hfrom;
				if ($from > ($maxItems * exp (log($factor)*@list))) {
					$hfrom = $maxItems * sprintf( "%.0f", exp (log($factor)*@list));
				} else {
					$hfrom = $from - $first;
				}

				if ( ($hfrom != ($from - $first)) and
				     ($elements < ($from - $first))
				   ) {
					$hfrom = $hfrom * $from / $elements;
					$hfrom = sprintf( "%.0f", $hfrom);
				}

				$hfrom = $from - $hfrom;

				$hfrom = $first
					if ($hfrom < $first);

				$list [@list] = $hfrom;

				last if ($hfrom <= $first);
			}

			## build links
			for (my $i=$#list; $i >= 0; $i--) {
				$self->param( -name=>"viewFrom", -value=>$list[$i]);
        	               	$link = "?".$self->query_string();
	        	        $title .= "&nbsp; <a href=\"$link\">";
				$title .= "|"
					if ($i == $#list);
				for (my $k=0; $k <= $i; $k++) {
					$title .= "&lt;";
				}
				$title .= "</a> ";
			}
		}

		## forward references

		if ($to != $last) {

			$total_links++;

			## first element
			my @list = ();

			## calculate links
			while (1) {
				my $hfrom;
				if ($last > ($to - $maxItems + 1 + $maxItems * exp (log($factor)*@list))) {
					$hfrom = -$maxItems + 1 +$maxItems * sprintf( "%.0f", exp (log($factor)*@list));
				} else {
					$hfrom = $last - $to;
				}

				if ( ($hfrom != ($last - $to)) and
				     ($hfrom != 1) and
				     ($elements < ($last - $to))
				   ) {
					$hfrom = $hfrom * $last / $elements;
					$hfrom = sprintf( "%.0f", $hfrom);
				}

				$hfrom = $to + $hfrom;

				$hfrom = $last - $maxItems + 1
					if ($hfrom > $last - $maxItems);

				$list [@list] = $hfrom;

				last if ($hfrom > ($last - $maxItems));
			}

			## build links
			for (my $i=0; $i <= $#list; $i++) {
				$self->param( -name=>"viewFrom", -value=>$list[$i]);
        	               	$link = "?".$self->query_string();
	        	        $title .= "&nbsp; <a href=\"$link\">";
				for (my $k=0; $k <= $i; $k++) {
					$title .= "&gt;";
				}
				$title .= "|"
					if ($i == $#list);
				$title .= "</a> ";
			}

		}

	        if ( $total_links < 1 ) {
        	        $title = "<DIV ALIGN=\"RIGHT\"><FONT SIZE=\"-1\">" . 
                	         $self->{gettext} ("No Extra References");
        	}

	} else {

	        $pages = int $elements / $maxItems;
        	$pages++ if( $elements % $maxItems );

	        $current = int $from / $maxItems;
        	## $current++ if ( $from % $maxItems );

	        $title = "<DIV ALIGN=\"RIGHT\"><FONT SIZE=\"-1\">".
                         $self->{gettext} ("Extra References");

		for( $i = 0; $i < $pages ; $i++ ) {
	                my ( $from, $pnum );
		
			$pnum = $i + 1;
			$from = sprintf( "%lx", $i * $maxItems + 1);

			if ( $i != $current ) {
				$self->param( -name=>"viewFrom", -value=>"$from" );
	                        $link = "?".$self->query_string();
                        	$title .= "&nbsp; <a href=\"$link\">$pnum</a> ";
                	} else {
        	                $title .= "&nbsp; $pnum ";
	                }
		}
	        if ( $pages <= 1 ) {
                	$title = "<DIV ALIGN=\"RIGHT\"><FONT SIZE=\"-1\">" . 
        	                 $self->{gettext} ("No Extra References");
	        }

	}

        $title .= "</FONT></DIV>";
       	$ret = $self->startTable( COLS=>[ "$title" ],
               	               TITLE_BGCOLOR=>"#EEEEF1",
                       	       TABLE_BGCOLOR=>"#000000" );

        $ret .= $self->endTable();

        return $ret;
}

sub buildRefs2 {
	my $self = shift;
	my $keys = { @_ };
	my @objList = @{$keys->{LIST}};

	my $from = 0;
	my $nowFirst = 0;
	my $first = 0;
	my $last = 0;
	my $idx = 0;

	my $title = undef;
	my $ret = "";
	my $baseLnk = $keys->{BASELINK};

	if ( $baseLnk eq "" ) {
		$baseLnk = $self->param("HTTP_CGI_SCRIPT") .
				"?cmd=" . $self->param("cmd");
	}

	if ( $keys->{MODE} eq "HEX" ) {
		$from = hex ( $keys->{FROM} );
		$nowFirst = hex ( $self->{NOW_FIRST} );
		$first = hex( $keys->{FIRST} );
		$last = hex( $keys->{LAST} );
	} else {
		$from = $keys->{FROM};
		$nowFirst = $keys->{NOW_FIRST};
		$first = $keys->{FIRST};
		$last = $keys->{LAST};
	}

	$title = "<DIV ALIGN=\"RIGHT\"><FONT SIZE=\"-1\">".
        			$self->{gettext} ("Extra References");

	$title .= " ( $first -> $last ) ";

	my $refName = 0;
	for( $idx = $first; $idx < $last ; $idx += $keys->{MAXITEMS} ) {
		$refName++;
		if( $idx < $nowFirst ) {
			$title .= "<a href=\"$baseLnk;viewFrom=" .
				$objList[$idx]->getSerial($keys->{DATATYPE}) .
					"\">$refName</a>";
		} elsif ( $idx > ( $nowFirst + $keys->{MAXITEMS}) ) {
			$title .= "<a href=\"$baseLnk;viewFrom=" .
				#$objList[$idx]->getSerial($keys->{DATATYPE}) .
				$idx .  "\">$idx-$refName</a>";
		} else {
			$title .= " $refName ";
		}
	}
	$ret = $self->startTable( COLS=>[ "$title (" . $#objList . ") " ], 
			TITLE_BGCOLOR=>"#EEEEF1", TABLE_BGCOLOR=>"#000000");

	$ret .= $self->endTable();
}


sub setError {
    my $self = shift;

    if (scalar (@_) == 4) {
        my $keys = { @_ };
        $errval = $keys->{ERRVAL};
        $errno  = $keys->{ERRNO};
    } else {
        $errno  = $_[0];
        $errval = $_[1];
    }

    print $STDERR "PKI Master Alert: Access control is misconfigured\n";
    print $STDERR "PKI Master Alert: Aborting all operations\n";
    print $STDERR "PKI Master Alert: Error:   $errno\n";
    print $STDERR "PKI Master Alert: Message: $errval\n";
    print $STDERR "PKI Master Alert: debugging messages of access control follow\n";
    $self->{debug_fd} = $STDERR;
    $self->debug ();
    $self->{debug_fd} = $STDOUT;

    ## support for: return $self->setError (1234, "Something fails.") if (not $xyz);
    return undef;
}

sub debug {

    my $self = shift;
    if ($_[0]) {
        $self->{debug_msg}[scalar @{$self->{debug_msg}}] = $_[0];
        $self->debug () if ($self->{DEBUG});
    } else {
        my $msg;
        foreach $msg (@{$self->{debug_msg}}) {
            $msg =~ s/ /&nbsp;/g;
            my $oldfh = select $self->{debug_fd};
            print $STDOUT $msg."<br>\n";
            select $oldfh;
        }
        $self->{debug_msg} = ();
    }

}

#############################################################################
##                         check the channel                               ##
#############################################################################
# Autoload methods go after =cut, and are processed by the autosplit program.

1;
