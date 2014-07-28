
var ContextUser       = 1;
var ContextMachine    = 2;
var XCN_NCRYPT_ALLOW_EXPORT_FLAG          = 1;
var XCN_NCRYPT_UI_NO_PROTECTION_FLAG      = 0;
var XCN_NCRYPT_UI_PROTECT_KEY_FLAG        = 1;

function setGenKeyFlags(objPrivateKey, nGenKeyFlags)
	{
		// some constants defined in wincrypt.h:
    var CRYPT_EXPORTABLE=1;
    var CRYPT_USER_PROTECTED=2;
        
  	objPrivateKey.KeyProtection  = (0 != (CRYPT_USER_PROTECTED & nGenKeyFlags)) ? XCN_NCRYPT_UI_PROTECT_KEY_FLAG : XCN_NCRYPT_UI_NO_PROTECTION_FLAG;
    objPrivateKey.ExportPolicy   = (0 != (CRYPT_EXPORTABLE & nGenKeyFlags)) ? XCN_NCRYPT_ALLOW_EXPORT_FLAG : 0;
    objPrivateKey.Length         = nGenKeyFlags >> 16;
  }


/* 
 * IE7 and VISTa - OpenCA Support Script
 * (c) 2008 by Massimiliano Pala and OpenCA Team
 * All Rights Reserved
 *
 * OpenCA LICENSED software
 */

var webObj;
var keyObj;
var reqObj;
var enrObj;
var extObj;
var dnObj;

var csspInfoStr       = "X509Enrollment.CCspInformations";
var cx509webEnrollStr = "X509Enrollment.CX509EnrollmentWebClassFactory";
var cx509EnrollStr    = "X509Enrollment.CX509Enrollment";
var cx509PKeyStr      = "X509Enrollment.CX509PrivateKey";
var cx509ExtStr       = "X509Enrollment.CX509ExtensionKeyUsage";
var cx509P10Str       = "X509Enrollment.CX509CertificateRequestPkcs10";
var cx500DNStr        = "X509Enrollment.CX500DistinguishedName";

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

function help() {
	var msg = "";

	msg += "In order to be able to request a certificate from this CA";
	msg += " on VISTA, you must enable ActiveX.\n\n";
	msg += "To do so, please do the following:\n";
	msg += "[1.] Go to Tools->Internet Options\n";
	msg += "[2.] Select Security Tab\n";
	msg += "     (a.) Click on Trusted Websites\n";
	msg += "     (b.) Click on the 'Sites'Add button\n";
	msg += "     (b.) Click on the 'Add' button\n";
	msg += "     (c.) (eventually) Uncheck the 'Require Server ...' checkbox\n";
	msg += "[3.] Click on 'Ok'\n\n";
	msg += "Now you need to enable ActiveX elements, in particular:\n";
	msg += "[4.] Click on Custom Level\n";
	msg += "[5.] Scroll down in the list and reach `ActiveX controls and plugins'\n";
	msg += "[6.] Enable the `Initialize and script ActiveX controls not marked as safe..'\n\n";
	msg += "When you are set, please proceed to request the certificate.";

	alert (msg);
}

function ieSetPKeyParams () {

	var provObj;
	var keyType;
	var bits;

	keyObj = webObj.CreateObject(cx509PKeyStr);

	provObj = document.OPENCA.csp;

	keyObj.KeySpec = "1";

	keyType = document.OPENCA.keytype;
	bits = document.OPENCA.bits;

	keyObj.ProviderType = provObj.options[provObj.selectedIndex].value
	keyObj.Length = +bits.value;
	keyObj.MachineContext = false;
	keyObj.KeyProtection = 1; // It was 2 - but reported to not work properly
	keyObj.ExportPolicy = 1;

	return true;
}

function ieCreateList( obj ) {

	var msg = "";
	var def = 0;
	var i = 0;
	var j = 0;
	var currIdx = 0;
	var provObj;
	var keyType;
	var csp;

	obj.AddAvailableCsps();
	provObj = document.OPENCA.csp;
	keyType = document.OPENCA.keytype;

	for ( i=0; i < obj.Count; i++ ) {

		csp = obj.ItemByIndex(i);
		msg = csp.Name;

		if( keyType.value == "rsa" ) {
			switch( csp.Type ) {
				case XCN_PROV_RSA_FULL:
				case XCN_PROV_RSA_SIG:
				case XCN_PROV_RSA_AES:
					break;
				default:
					continue;
			}
		};

		if ( keyType.value == "dsa" ) {
			switch ( csp.Type ) {
				case XCN_PROV_DSS:
				case XCN_PROV_DSS_DH:
					break;
				default:
					continue;
			}
		};

		if( keyType.value == "ecdsa" ) {
			switch ( csp.Type ) {
				case XCN_PROV_EC_ECDSA_SIG:
				case XCN_PROV_EC_ECDSA_FULL:
					break;
				default:
					continue;
			}
		}
			
		if ( csp.Type == XCN_PROV_RSA_AES ) {
			def = currIdx;
		};

		opt = document.createElement("OPTION");

		opt.text = csp.Name;
		opt.value = csp.Type;

		provObj.add(opt);
		currIdx++;
	};

	provObj.selectedIndex = def;


	return true;

}

function vistaCSR() {

	var dn;
	var des;

	dn = document.OPENCA.dn.value;
	res = document.OPENCA.request;

	// try {

		// var keyUsage = 0x80 & 0x10;
		var keyUsage = 0x80 | 0x10;

		ieSetPKeyParams();

		enrObj = webObj.CreateObject(cx509EnrollStr);
		reqObj = webObj.CreateObject(cx509P10Str);
		dnObj = webObj.CreateObject(cx500DNStr);

		dnObj.Encode(dn, 2);

		reqObj.InitializeFromPrivateKey(1, keyObj, "");
		reqObj.Subject = dnObj;

		// extObj = new ActiveXObject(cx509ExtStr); 
		extObj = webObj.CreateObject(cx509ExtStr); 
		extObj.InitializeEncode(keyUsage);

		reqObj.X509Extensions.Add(extObj);

		enrObj.InitializeFromRequest(reqObj);

	try {
		res.value = enrObj.CreateRequest(1);
	} catch (e) {
		alert( "In order to create the request you need to Medium-Low" +
			" the level of security of IE by setting it in " +
			"Tools -> Internet Options -> Security -> Trusted Sites " +
			"Tab." );

		return false;
	}

	with ( document.OPENCA ) {
		submit();
	};

	return true;

}

function ieInitVista() {

	try {
		webObj = new ActiveXObject(cx509webEnrollStr);
	}
	catch(e) {
		help();
		return false;
	}

	csspInfoObj = webObj.CreateObject(csspInfoStr);
	ieCreateList( csspInfoObj );

	return true;

}

