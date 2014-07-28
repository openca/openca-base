<!--
/* nssCSR Script
 * (c) 2008 by Massimiliano Pala and OpenCA Team
 * All Rights Reserved
 *
 * OpenCA Licensed Code
 */

var authenticator = "";
var keyTransportCert = null;
var reqObj = null;

function nssCSR() {
	var size = 0;
	var myKeyType = "rsa";

	with ( document.OPENCA ) {
		// generate keys for nss
		size = parseInt(bits.value);

		if ( keytype.value == "rsa" ) {
			myKeyType = "rsa-dual-use";
		} else if ( keytype.value == "dsa" ) {
			if( size > 1024 ) {
				alert(
				   "DSA with Keys larger than 1024 is not\n" +
				   "fully supported on the browser.\n\n" +
				   "Please hit back and pick a smaller key\n" + 
				   "or choose a different Algorithm\n");
				return false;
			};
			myKeyType = "dsa-sign-nonrepudiation";
		} else {
			alert( "ERROR: Key Type not supported!" );
			return false;
		};

		if (typeof(crypto.version) != "undefined") {
			reqObj = crypto.generateCRMFRequest(
				dn.value,
				passwd1.value, 
				authenticator,
				null,
				"sendReq();",
				size, null, myKeyType);
		} else {
			alert("crypto.version is undefined!");
			return false;
		}
		return false;
	}
}

function sendReq() {

	var beginArmour = "-----BEGIN CERTIFICATE REQUEST-----";
	var endArmour = "-----END CERTIFICATE REQUEST-----";

	with (document.OPENCA) {
		// We do not actually need to add those, they are
		// added by the web interface directly.
		request.value = reqObj.request;
		submit();
	}
}

// -->
