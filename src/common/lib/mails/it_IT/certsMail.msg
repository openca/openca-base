Dear @USER@,

You are able to download the requested certificate from our server
at the URI:

	@httpd_protocol@://@httpd_host@@httpd_port@

please use the serial number reported in the subject of this email.
You can either follow the proposed link to import the certificate
directly from the server (no action required from you):

@httpd_protocol@://@httpd_host@@httpd_port@@pub_cgi_url_prefix@/pki?cmd=getcert&key=@SERIAL@&type=CERTIFICATE

Please, import the CA certificate (or the PKI chain) from our server
to check the correctness of your certificate:

	@httpd_protocol@://@httpd_host@@httpd_port@@pub_htdocs_url_prefix@

Please remember to keep at least one safe backup of your private
key: if you'll lose it you'll not be able to read the crypted
messages you received so far.

Last, but not least, please add the LDAP server of our organization
to your browser's list. You can find it at the following address:

	ldap://@ldap_host@:@ldap_port@/@ca_organization@,@ca_country@

To use it from Netscape, just open the address book, add a new
Directory using the following parameters:

	Description: @ca_organization@ LDAP Server with Certificates
	LDAP Server: @ldap_host@
	LDAP Port  : @ldap_port@
	Dir Root   : o=@ca_organization@, c=@ca_country@

Now you are able to search directly users' certificates by the
search facility built in Netscape with just one mouse click.



				Sincerily Yours, 
				@ca_organization@ Security Staff.


