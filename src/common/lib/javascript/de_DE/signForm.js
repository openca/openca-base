<!--

function signForm(theForm, theWindow){
        if (navigator.appName == "Netscape"){
                signFormN(theForm, theWindow);
        } else {
                signFormIE(theForm,theWindow);
        }
        theForm.submit();
}

function signFormN(theForm, theWindow) {
  var signedText;

  var sObject;
  var result;

  // alert("die folgenden Informationen werden signiert: \n\n"+theForm.text.value);

  try {
    // alert ('Prüfe ob das Plugin SecCLAB installiert ist.');
    sObject = new CLABSignString();
    // alert ('Plugin SecCLAB wurde erkannt und wird nun genutzt.');
    if (sObject == undefined) alert('Das Pluging SecCLAB konnte nicht initialisiert werden.');
    var status = {value:0};
    var len = {value:0};
    try {
      result = sObject.signString(window,theForm.text.value,theForm.text.value.length,status,len);
      if (status.value != sObject.STATUS_OK) {
        alert("Abbruch durch Nutzer oder es ist kein gültiges und verifizierbares Zertifikat vorhanden.");
        return false;
      }
    } catch(ex) {
        alert("Abbruch durch Nutzer oder es ist kein gültiges und verifizierbares Zertifikat vorhanden.");
        return false;
    }
    signedText = base64_2_pem (String2Base64(result)); //String2Hex(result);
  } catch(ex) {
    // alert ('Es wird das bereits im Browser vorhandene Javascript Objekt crpyto benutzt.');
    signedText = theWindow.crypto.signText(theForm.text.value, "ask");
  }

  if ( signedText.length < 100 ) {
    alert( "Eine digitale Signatur ist notwendig, um erfolgreich fortzufahren. Diese ist nicht vorhanden!" );
    return false;
  }

  theForm.signature.value = signedText;
}

function base64_2_pem (base64)
{
  var pem = "";
  for (var i=0;i < base64.length;i++)
  {
    pem = pem + base64.charAt(i);
    if (63 == (i % 64))
    {
        pem = pem + "\n";
    }
  }
  return pem;
}

function Hex(v)
{
  var hexstring="0123456789ABCDEF";
  return hexstring[v];
}

function String2Hex(str){
  var s = "";
  var hnible;
  var lnible;
  for (var i=0;i < str.length;i++){
    hnible = Hex(str.charCodeAt(i) >> 4);
    lnible = Hex(str.charCodeAt(i) & 0x0f);
    s = s + hnible + lnible;
  }
  return s;
}

function base64ToAscii(c)
{
	var theChar = 0;
	
	if (0 <= c && c <= 25)
	{
		theChar = String.fromCharCode(c + 65);
	}
	else if (26 <= c && c <= 51)
	{
		theChar = String.fromCharCode(c - 26 + 97);
	}
	else if (52 <= c && c <= 61)
	{
		theChar = String.fromCharCode(c - 52 + 48);
	}
	else if (c == 62)
	{
		theChar = '+';
	}
	else if( c == 63 )
	{
		theChar = '/';
	}
	else
	{
		theChar = String.fromCharCode(0xFF);
	}

	return theChar;
}


function String2Base64(str) {
	var result = "";
	var i = 0;
	var sextet = 0;
	var leftovers = 0;
	var octet = 0;

	for (i=0; i < str.length; i++) {
		octet = str.charCodeAt(i);
		switch( i % 3 )
		{
			case 0:
			{
				sextet = ( octet & 0xFC ) >> 2 ;
				leftovers = octet & 0x03 ;

				// sextet contains first character in quadruple
				break;
			}

			case 1:
			{
				sextet = ( leftovers << 4 ) | ( ( octet & 0xF0 ) >> 4 );
				leftovers = octet & 0x0F ;

				// sextet contains 2nd character in quadruple
				break;
			}

			case 2:
			{
				sextet = ( leftovers << 2 ) | ( ( octet & 0xC0 ) >> 6 ) ;
				leftovers = ( octet & 0x3F ) ;

				// sextet contains third character in quadruple
				// leftovers contains fourth character in quadruple
				break;
			}
		}

		result = result + base64ToAscii(sextet);

		// don't forget about the fourth character if it is there
		if( (i % 3) == 2 )
		{
			result = result + base64ToAscii(leftovers);
		} 

	}

	// figure out what to do with leftovers and padding
	switch( str.length % 3 )
	{
		case 0:
		{
			// an even multiple of 3, nothing left to do
			break ;
		}
		case 1:
		{
			// one 6-bit chars plus 2 leftover bits
			leftovers =  leftovers << 4 ;
			result = result + base64ToAscii(leftovers);
			result = result + "==";
			break ;
		}
		case 2:
		{
			// two 6-bit chars plus 4 leftover bits
			leftovers = leftovers << 2 ;
			result = result + base64ToAscii(leftovers);
			result = result + "=";
			break ;
		}
	}

	return result;
}

// -->
