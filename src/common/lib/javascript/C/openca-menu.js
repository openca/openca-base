/*
 * ==========================================
 * OpenCA Iface 2.0 - Dynamic Javascript Menu
 * (c) by Massimiliano Pala and OpenCA Team
 * All Rights Reserved
 * ==========================================
 * OpenCA Licensed Software
 * ==========================================
 */

var xmlDoc = null;
var request = null;
var menu = null;
var docDir = "images";
var isMSIE = ( navigator.appVersion.indexOf("MSIE") > 0) ? 1 : 0;
var brVER  = parseInt(navigator.appVersion); 

function genXMLMenu ( fname, objID, addLink ) {

	if( window.XMLHttpRequest ) {
		if( typeof(XMLHttpRequest) != 'undefined' ) {
			try {
				request = new XMLHttpRequest();
			} catch ( e ) {
				request = null;
			}
		}
	} else if ( window.ActiveXObject ) {
		try {
			request = new ActiveXObject( 'Msxml2.XMLHTTP' );
		} catch ( e ) {
			try {
				request = new ActiveXObject('Microsoft.XMLHTTP');
			} catch ( e ) {
				request = false;
			}
		}
	}

	if( request == null ) {
		alert ("Browser is not supported!");
		return;
	}

	request.open('GET', fname, true );
	request.onreadystatechange = function () { parseXMLConfig (objID, addLink) };
	request.send(null);

	return;
}

function parseXMLConfig ( objID, addLink ) {

	/* xmlDoc, request are general variables */
	var response = null;

	if ( request.readyState == 4 ) {
		if( request.status == 200 ) {
			response = request.responseText;
		} else {
			try {
				response = request.responseText;
			} catch ( e ) {
				alert ( "ERROR, can not find menu configuration");
				request = null;
			}
		};
	} else {
		return ( null );
	}

	if ( window.ActiveXObject ) {
		xmlDoc = new ActiveXObject('Microsoft.XMLDOM');
		xmlDoc.async = false;
		xmlDoc.loadXML ( response );
	} else if ((document.implementation) &&
			(document.implementation.createDocument) ) {
		try {
			xmlDoc = document.implementation.createDocument('','', null );
			xmlDoc.loadXML( response );
		} catch ( e ) {
			try {
				parser = new DOMParser();
				xmlDoc = parser.parseFromString( response, "text/xml" );
			} catch ( e ) {
				alert ( "Browser is not suppoted (line 96)");
				return null;
			}
		}
	} else {
		alert ( "Browser not supported (line 100)" );
		return null;
	}


	if( xmlDoc ) {
		createMenu( objID, xmlDoc, addLink );
	}

	return xmlDoc;

}

/* 
 * Show/Hide/Click functions for menu displaying 
 */

function showMenu( el, type ) {
	var list;
	var type;
	var target;

	list = el.childNodes;

	if( type == null ) {
		type = 'TABLE';
	}

	if ( el.className == "menutitle" ) {
		// el.style.color = "#4c6490";
		el.style.color = "#eeeeff";
		el.style.backgroundColor = 'white';
		el.style.borderStyle = 'solid';
		el.style.borderWidth = '1px';
		el.style.borderColor = '#4c6490';
		el.style.margin = '1px';
	}

	for ( i=0; i < list.length; i++ ) {
		if(( list[i].nodeName == 'DIV' ) &&
			( list[i].className == "submenuitem" ) ) {
			list[i].style.borderStyle = 'solid';
			list[i].style.borderColor = '#ccc';
			list[i].style.borderWidth = '1px';
			list[i].style.backgroundColor = '#fefeff';
		}

		if( list[i].nodeName != type ) {
			continue;
		};

		fadeInit ( list[i], 'in' );
	}
}

function clickMenu( el ) {
	var list;

	list = el.childNodes;

	for ( var i=0; i < list.length; i++ ) {
		if( list[i].nodeName == "TABLE" ) {
			if ( list[i].style.display == 'none' ) {
				fadeInit ( list[i], 'in' );
			} else {
				list[i].setAttribute ( "fade", "" );
				list[i].style.display = 'none';
				list[i].style.opacity = 0;
				list[i].style.filter = "alpha(opacity = 0)";

			}
		}
	}
}

function hideMenu( el ) {
	var list;
	var obj;
	var target;

	list = el.childNodes;

	if ( el.className == "menutitle" ) {
		el.style.color = '';
		el.style.borderStyle = '';
		el.style.backgroundColor = '';
		el.style.margin = '2px';
	}

	for ( i=0; i < list.length; i++ ) {
		if ( list[i].nodeName == 'TABLE' ) {
			fadeInit( list[i], 'out' );
			continue;
		}
	}
}

function highlightSubMenuItem ( el ) {
	if ( el.className == "submenuitem" ) {
		el.style.borderStyle = 'solid';
		el.style.borderWidth = '1px';
		el.style.backgroundColor = "#eeeeff";
		el.style.color = '4c6490';
		el.style.margin = '1px';
	}
}

function cleanSubMenuItem ( el ) {
	try {
		if ( el.className == "submenuitem" ) {
			el.style.borderStyle = '';
			el.style.backgroundColor = '';
			el.style.color = '';
			el.style.margin = '';
		}
	} catch ( e ) {
	}
}

function createSubMenu ( obj, menuNodes, cls, addLink ) {

	var table;
	var tbody;
	var cldName;

	if( (obj == null) || ( menuNodes == null ) ) {
		alert ("ERROR:: obj=" + obj + " nodes=" + menuNodes );
		return false;
	} 

	if( cls < 1 ) {
		clsName = "submenu";
	} else {
		clsName = "subsubmenu";
	}

	table = document.createElement ( "table" );
	tbody = document.createElement ( "tbody" );

	table.appendChild( tbody );
	obj.appendChild ( table );

	if( clsName ) {
		setClass( table, clsName );
	}

	table.style.display = 'none';
	table.style.opacity = 0;
	table.style.filter = "alpha(opacity = 0)";

	for ( var i = 0; i < menuNodes.length; i++) {
		var tr;
		var td;
		var div;
		var lst;
		var enabled;

		var node;
		var name;
		var lnk;
		var img;

		node = menuNodes[i];
		enabled = 1;

		if ( (node.nodeName != "item") && 
				(node.nodeName != "submenu") ) {
			continue;
		}

		tr = document.createElement( "tr" );
		td = document.createElement( "td" );

		name = node.getAttribute("name");
		lnk = node.getAttribute("lnk");
		img = node.getAttribute("img");

		if ( ( lnk == "") && ( node.childNodes.length == 0 ) ) {
			td.style.color = "#bbb";
			enabled = 0;
		}

		div = document.createElement( "div" );

		if( (name) && (name != "")) {
			if( (lnk) && (lnk != "") ) {
				var target = "";
				var lnkObj = document.createElement('a');

				target = lnk + addLink;
				lnkObj.setAttribute('href', target);
				lnkObj.innerHTML = name;
				div.appendChild( lnkObj );
			} else {
				div.innerHTML = name;
			}
		} else {
			hr = document.createElement("hr");
			div.appendChild( hr );
			enabled = 0;
		}

		if( enabled == 1 ) {
			setClass( div, "submenuitem" );
			if( node.childNodes.length > 0 ) {
				createSubMenu ( div, node.childNodes, 
					cls+1, addLink );
			}

		} else {
			if ( name && ( name != "") ) {
				setClass( div, "submenuitemoff" );
			} else {
				setClass ( div, "submenuseparator" );
			}
		}

		td.appendChild( div );

		if ( enabled == 1 ) {
			registerEventsSubMenu ( div );
		}

		tr.appendChild( td );
		tbody.appendChild( tr );
	}

	return tbody;
}

function createMenu ( objId, xmlDoc, addLink ) {
	var table;
	var tbody;
	var row;
	var config;
	var currlist;
	var menuObject;
	var width;
	var menuNum = 0;
	var td;
	var floatSide = "left";
	var counter = 0;
	var img;

	var obj = document.getElementById( objId );

	if( obj == null ) {
		alert ( "ERROR: menu not found!" );
	}

	var menulist = xmlDoc.childNodes;
	var mainNode = xmlDoc.getElementsByTagName("openca");

	if ( !mainNode || typeof(mainNode) === "undefined" ) {
		alert ( "Error::missing openca node in config!");
		return;
	}

	OpenCA.Log ("Test Log!");

	// This is a global variable
	docDir = mainNode[0].getAttribute("base");

	currlist = mainNode[0].childNodes;

	menuObject = document.createElement ( "table" );
	tbody = document.createElement ( "tbody" );

	menuObject.appendChild( tbody );
	setClass ( menuObject, "nav" );

	obj.appendChild ( menuObject );

	row = document.createElement( "tr" );
	setClass ( row, "menurow" );
	tbody.appendChild( row );

	menuNum = 0;
	for ( var i = 0 ; i < currlist.length;i++ ) {
		if ( (currlist[i].nodeName == "menu") ||
				(currlist[i].nodeName == "item" )) {
			menuNum++;
		}
	}

	if( menuNum == 0 ) {
		menuNum++;
	}

	width = 100 / menuNum;

	// td = document.createElement( "td" );
	// img = document.createElement( "img" );
	// img.setAttribute ( "src", docDir + "/images/menu_left.png" );
	// setClass ( img, "menuleft" );

	// td.appendChild( img );
	// row.appendChild( td );
	
	td = document.createElement( "td" );
	setClass ( td, "menutitle" );

	for( var i = 0 ; i < currlist.length; i++ ) {
		var tab;
		var node;
		var name;
		var img;
		var span;
		var lnk;
		var imgName;
		var target;
		var isItem = 0;
		var separate_leftRight_menu_activated = 1;

		node = currlist[i];
		if(( node.nodeName != "menu" ) && 
				( node.nodeName != "item" )) {
			continue;
		};

		name = node.getAttribute("name");
		if ( name == "" ) {
			continue;
		}

		if ( separate_leftRight_menu_activated ) {
			counter++;
			if ( node.nodeName == 'item' ) {
				row.appendChild( td );
				td = document.createElement( "td" );
				floatSide = "right";
				separate_leftRight_menu_activated = 0;
			};
		}

		if ( (floatSide == 'right') && 
				( node.nodeName != "item" )) {
			continue;
		}

		div = document.createElement( "div" );
		div.style.float = floatSide;

		target = node.getAttribute( "lnk");
		imgName = node.getAttribute ( "img" );

		if( imgName ) {
			img = document.createElement( "img" );
			img.setAttribute ( "src", docDir + "/" + imgName );
			img.style.verticalAlign = 'top';
			img.style.height = '22px';
			img.style.marginRight = '5px';
		} else {
			img = null;
		}

		span = document.createElement( "span" );

		if( name ) {
			/* name.replace(/ /g, "&nbsp;"); */
			span.innerHTML = name;
		} else {
			span.innerHTML = '<center><hr />';
		}

		if ( target ) {
			lnk = document.createElement( "a" );
			lnk.setAttribute( "href", target );
			lnk.style.color = 'white';
			if( img ) {
				lnk.appendChild ( img );
			}
			lnk.appendChild ( span );
			div.appendChild ( lnk );
		} else {
			if( img ) {
				div.appendChild ( img );
			}
			div.appendChild ( span );
		}

		if ( node.nodeName == "item" ) {
			isItem = 1;
			setClass( div, "menutitle" );
		} else {
			setClass( div, "menutitle" );
			registerEventsMenu ( div );
			div.style.margin = "2px";

			if( node.childNodes.length > 0 ) {
				createSubMenu(div, node.childNodes, 0,addLink);
			}
		}

		td.appendChild( div );
	}
	row.appendChild( td );

	// td = document.createElement( "td" );
	// img = document.createElement( "img" );
	// img.setAttribute ( "src", docDir + "/images/menu_right.png" );
	// setClass ( img, "menuright" );

	// td.appendChild ( img );
	// row.appendChild( td );

}

function registerEventsMenu ( el ) {

	try {
		el.onmouseover = function() {showMenu(this,null)};
		el.onmouseout = function() {hideMenu( this );};
		el.onclick = function() {clickMenu(this)};
	} catch ( e ) {
		el.setAttribute ("onMouseover","showMenu(this,null);");
		el.setAttribute ("onMouseout", "hideMenu( this );");
		el.setAttribute ("onClick", "clickMenu(this);");
	}

	return;
}

function registerEventsSubMenu ( el ) {

	try {
		el.onmouseover = function() {
			highlightSubMenuItem ( this );
			showMenu(this,null)};
		el.onmouseout = function() {
			cleanSubMenuItem ( this );
			hideMenu( this );};
		el.onclick = function() {clickMenu(this)};
	} catch ( e ) {
		el.setAttribute ("onMouseover",
			"highlightSubMenuItem ( this ); showMenu(this,null);");
		el.setAttribute ("onMouseout", 
			"cleanSubMenuItem ( this ); hideMenu( this );");
		el.setAttribute ("onClick", "clickMenu(this);");
	}

	return;
}


function clearEvents ( el ) {

	try {
		el.onmouseover = '';
		el.onmouseout = '';
		el.onclick = '';
	} catch ( e ) {
		el.setAttribute ("onMouseover","");
		el.setAttribute ("onMouseout", "");
		el.setAttribute ("onClick", "");
	}

	return;
}

function fadeElement ( el, interval, operation ) {
        var p = el;
        var val = 0;
        var opt = operation;
        var sleepTime = interval;
        var step = 0.05
	var ieOp = 0;

        if ( p.getAttribute("fade") != opt ) {
                return;
        }

        if ( p.style.opacity ) {
                val = p.style.opacity * 1;
        } else if ( p.style.opacity == '' ) {
                val = 1;
        }

        if ((( opt == "out") && ( val <= 0.1 )) ||
                (( opt == "in") && ( val >= 0.9 ))) {

                p.setAttribute("fade", '');

                if ( opt == 'out' ) {
                        p.style.display = 'none';
			p.style.opacity = "0";
			p.style.filter = "alpha(opacity = 0)";
                } else {
			p.style.display = 'block';
			p.style.opacity = "1";
			p.style.filter = "alpha(opacity = 100)";
		}

                return;
        }
        
	if ( isMSIE ) {
		step = 0.1;
	}

	if ( opt == "out" ) {
                p.style.opacity = val - step;
        } else {
                p.style.opacity = val + step;
        }

	ieOp = Math.round ( p.style.opacity * 100 );

	p.style.filter = "alpha(opacity = " + ieOp + ")";

        setTimeout ( function() {
                fadeElement ( p, interval, opt );
        }, interval );
}


function fadeInit ( el, op ) {
        var interval = 10;
        var sleep = 100;
        var steps = 20;
        var p = el;
        var fade;

        if ( op == '' ) {
                if ( (p.style.opacity == 1) || (p.style.opacity == "" ) ) {
                        op = 'out';
                } else if ( p.style.opacity == 0 ) {
                        op = 'in';
                } else {
                        op = el.getAttribute ( "fade" );
                        if ( op == 'in' ) {
                                op = 'out';
                        } else if ( op == 'out' ) {
                                op = 'in';
                        }
                }
        }

        if( fade = el.getAttribute ("fade" ) ) {
                if ( fade == op ) {
                        return;
                }
                sleep = 0;
        }

	el.setAttribute( "fade", op );

	if ( el.style.display == 'none' ) {
		el.style.display = 'block';
	}

	if ( op == 'out' ) {
		interval = 5;
		sleep = 50;
	}

	if ( isMSIE ) {
		interval = 10;
		sleep = 10;
	}

        setTimeout ( function() {
                fadeElement ( p, interval, op ); } , sleep );
};

function setClass ( obj, cls ) { 

	if( (obj == null) || (cls == null) ) {
		return false;
	}

	try {
		obj.setAttribute ( "class", cls );
		obj.setAttribute ( "className", cls );
	} catch ( e ) {
		alert ("ERROR: Menu generation");
	}
}

