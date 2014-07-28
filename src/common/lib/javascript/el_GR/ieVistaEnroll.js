<!--//

/* Install Certificate on IE (Vista)
 * (c) 2008 by Massimiliano Pala and OpenCA Team
 * All Rights Reserved
 *
 */

var cx509webEnrollStr = "X509Enrollment.CX509EnrollmentWebClassFactory";
var cx509EnrollStr    = "X509Enrollment.CX509Enrollment";

function InstallCertIE ( form ) {

	var enrObj;
	var webObj;
	var p7cert;

	var contextUser = 1;

	try {
		webObj = new ActiveXObject(cx509webEnrollStr);
		enrObj = webObj.CreateObject(cx509EnrollStr);

		enrObj.Initialize(contextUser);

		p7cert = form.cert.value;

		enrObj.InstallResponse( 0, p7cert, 1, "" );

		var result;

		result = document.getElementsByName('result');
		result[0].innerHTML = 
			"<h2>Congratulations!</h2><br/>" +
			"The certificate has been installed successfully. " +
			"You can check your certificate by using the " +
			"following procedure:<br /><br />" +
			"<ol>" +
			"<li>Select <b>Internet Options</b> from the browser's " +
			"<b><span style=\"font-style: italic;\">Tools</span></b> Menu<br/><br /></li>" +
			"<li>Select the <b><span style=\"font-style: italic;\">Content Tab</span></b> (upper part of the window)<br/><br /></li>" +
			"<li>Click on the <b><span style=\"font-style: italic;\">Certificates</span></b> button</li>" +
			"</ol>" +
			"For further information, please refer to the CA " +
			"support contacts.\n";

	} catch ( e ) {
		/* Error ! */
		var result;

		result = document.getElementsByName('result');

		result[0].innerHTML =
			"<h2>Error!</h2><br/> " +
			"An error occurred while installing the certificate " +
			"in the browser. This can be due to several reasons. " +
			"before attempting to download the certificate again, " +
			"please check that:<br /><br />" + 
			"<ol>" +
			"<li>The <b>CA certificate</b> is installed in the TRUSTED ROOT certificate store. If not, " +
			"Please use <span style=\"font-style: italic;\">'CA Info' -> 'Get CA Certificate'</span> &nbsp; to install it.<br/><br/></li>" +
			"<li> This is <b>the same browser</b> you used when you requested the certificate<br/><br/></li>" +
			"<li>The certificate <b>is not already installed</b>. " +
			"To access the list of installed certificates you " +
			"can use the following procedure:" +
			"<ul>" +
			"<li>Select Internet Options from the browser's " +
			"<span style=\"font-style: italic;\">Tools</span> Menu</li>" +
			"<li>Select the Content Tab (upper part of the window)</li>" +
			"<li>Click on the <span style=\"font-style: italic;\">Certificates</span> button</li>" +
			"</ul>" +
			"</li>" +
			"</ol><br />" +
			"If the error persists, please contact the CA help desk.<br/><br/>";

		return;
	}
}

//-->
