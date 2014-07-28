// <!--

/* IE Support for MS (Version < 6.0)
 * (c) 2008 by Massimiliano Pala and OpenCA Team
 * All Rights Reserved
 */

var XCN_PROV_NONE = 0;
var XCN_PROV_RSA_FULL = 1;
var XCN_PROV_RSA_SIG = 2;
var XCN_PROV_DSS = 3;
var XCN_PROV_FORTEZZA = 4;
var XCN_PROV_MS_EXCHANGE = 5;
var XCN_PROV_SSL = 6;
var XCN_PROV_RSA_SCHANNEL = 12;
var XCN_PROV_DSS_DH = 13;
var XCN_PROV_EC_ECDSA_SIG = 14;
var XCN_PROV_EC_ECNRA_SIG = 15;
var XCN_PROV_EC_ECDSA_FULL = 16;
var XCN_PROV_EC_ECNRA_FULL = 17;
var XCN_PROV_DH_SCHANNEL = 18;
var XCN_PROV_SPYRUS_LYNKS = 20;
var XCN_PROV_RNG = 21;
var XCN_PROV_INTEL_SEC = 22;
var XCN_PROV_REPLACE_OWF = 23;
var XCN_PROV_RSA_AES = 24;

var XEnroll = null;

function getXEnroll() {

	var XE_ID_OLD = "clsid:43F8F289-7A20-11D0-8F06-00C04FC295E1";
	var XE_ID_NEW = "clsid:127698e4-e730-4e5c-a2b1-21490a70c8a1";

	var XE_OBJ_OLD;
	var XE_OBJ_NEW;

	var htmlXen;

	if ( XEnroll == null ) {

		htmlXen = document.createElement("div");
		htmlXen.style.display='none';
	
		XE_OBJ_OLD = document.createElement("object");
		XE_OBJ_OLD.setAttribute('classid',XE_ID_OLD);
		XE_OBJ_OLD.setAttribute('codebase', 'xenroll.dll' );
		XE_OBJ_OLD.setAttribute('id','XEnroll1');

		htmlXen.appendChild( XE_OBJ_OLD );

		XE_OBJ_NEW = document.createElement("object");
		XE_OBJ_NEW.setAttribute('classid',XE_ID_NEW);
		XE_OBJ_NEW.setAttribute('codebase', 'xenroll.dll' );
		XE_OBJ_NEW.setAttribute('id','XEnroll1');

		htmlXen.appendChild( XE_OBJ_NEW );

		try {
    			XE_OBJ_NEW.EnumProviders(0, 0);
    			XEnroll = XE_OBJ_NEW; 
		} catch(e) {
			try {
				XE_OBJ_OLD.EnumProviders(0,0);
    				XEnroll = XE_OBJ_OLD;
			} catch ( c ) {
				alert ("ERROR, browser not supported!");
				return null;
			}
		}
	}

	return XEnroll;
}

function enumCSP() {

	var csp;

	var maxProvType = 25;
	var defProvType =  1;

	var def = -1;
	var cont = 1;
	var i = 0;

	var provTypes;
	var strKeyType = "";

	XEnroll = getXEnroll();

	if( ! document.OPENCA ) {
		alert ( "NO DOCUMENT OPENCA IS DEFINED!");
		return;
	} else {
		csp = document.OPENCA.csp;
	}

	if ( ! csp ) {
		alert ("Missing Form Element 'csp'!");
		return;
	}

	while ( csp.length > 0 ) {
		csp.remove(0);
	};

	if ( ! document.OPENCA.keytype ) {
		alert ("ERROR: Missing form Element 'keytype'!");
		return;
	}

	strKeyType = document.OPENCA.keytype.value;

	if( strKeyType.toUpperCase() == "RSA" ) {
		provTypes = new Array ( XCN_PROV_RSA_FULL, 
			XCN_PROV_RSA_SIG , XCN_PROV_RSA_AES );
	} else if ( strKeyType.toUpperCase() == "DSA" ) {
                provTypes = new Array ( XCN_PROV_DSS, 
			XCN_PROV_DSS_DH );
	} else if( strKeyType.toUpperCase() == "ECDSA" ) {
		provTypes = new Array( XCN_PROV_EC_ECDSA_SIG,
			XCN_PROV_EC_ECDSA_FULL );
	} else {
		provTypes = new Array( 1 );
	}

	for ( type = 0; type < provTypes.length; type++ ) {

		XEnroll.providerType = provTypes[type];

		i = 0;
		cont = 1;
		while( cont == 1 ) {

			var txt;
			var opt;

			try {
				txt = XEnroll.EnumProviders( i, 0);
				i++;
			} catch ( e ) {
				/* If no more providers are available */
				cont = 0;
				break;
			}

			opt = document.createElement('option');
			opt.value = provTypes[type];
			opt.text = txt;

			if( txt == "Microsoft Enhanced Cryptographic Provider v1.0" ) {
				opt.selected = true;
				def = i;
			} else {
				if ( (def == -1 ) && 
						( txt == "Microsoft Base Cryptographic Provider v1.0" ) ) {
					opt.selected = true;
					def = i;
				}
			}

			csp.add( opt );
		}
	}

	return;
}

function genReq() {

	var XEnroll;

	var dn;
	var bits;
	var csp;
	var req;

	var KEY_FLAGS_EXPORTABLE = 0x00000001;
	var KEY_FLAGS_USER_PROTECTED = 0x00000002;
	// var profile = "1.3.6.1.4.1.311.2.1.21";
	var profile = "1.3.6.1.5.5.7.3.2";

	var keyFlags = 0x0;
	var req = "";
	var p10 = "";

	XEnroll = getXEnroll();

	csp = document.OPENCA.csp;
	XEnroll.providerType = csp.options[csp.selectedIndex].value;
	XEnroll.providerName = csp.options[csp.selectedIndex].text;
	XEnroll.KeySpec = 1;

	dn = document.OPENCA.dn.value;
	bits = document.OPENCA.bits;

	keyFlags = bits.value << 16;

	keyFlags += KEY_FLAGS_EXPORTABLE;
	keyFlags += KEY_FLAGS_USER_PROTECTED;

	XEnroll.KeySpec = 1;
	XEnroll.GenKeyFlags = keyFlags;
	XEnroll.HashAlgorithm = "SHA1";

	try {
		p10 = XEnroll.CreatePKCS10( dn, profile );
	} catch ( e ) {
		alert ( "Request Generation Failed: " + e.number );
		return false;
	}

	document.OPENCA.request.value = p10;
	document.OPENCA.submit();

	return true;
}

//-->
