
if( typeof(OpenCA) === "undefined" )
{
	OpenCA = {};
}

OpenCA.setAllCheckbox = function ( name, checked, formName )
{
	var aNum;
	var aForm;
	var aElement;
	var log;
	var i;

	if ( typeof(checked) === "undefined" )
	{
		checked = false;
	};

	// Go Through all the Page Forms
	for ( aNum in document.forms )
	{
		aForm = document.forms[aNum];

		// Check form Name
		if ( formName != null )
		{
			if ( aForm.name !== formName )
			{
				continue;
			};
		};

		// Go through all the form elements
		for(i=0; i<aForm.length; i++ )
		{
			if ( aForm.elements != null )
			{
				aElement = aForm.elements[i];
				if((aElement.type === "checkbox") && 
					(aElement.name === name))
				{
					aElement.checked = checked;
				};
			};
		};
	};	

	return true;
}

OpenCA.Log = function LOG( message ) {

	if ( typeof console == 'undefined' ) {
		return false;
	}

	console.log ( message );
}

