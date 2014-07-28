Dear Customer,

your certificate with the  serial number @__SERIAL__@ and the DN @__DN__@ was
generated.  You can download it now from our server at the URI:

	@httpd_protocol@://@httpd_host@@httpd_port@

Please use the serial number. You can either follow the proposed link to import
the certificate directly from the server (no action required from you):

@httpd_protocol@://@httpd_host@@httpd_port@@pub_cgi_url_prefix@/pki?cmd=getcert&key=@__SERIAL__@&type=CERTIFICATE

Please, import the CA certificate (or the PKI chain) from our server
to check the correctness of your certificate:

	@httpd_protocol@://@httpd_host@@httpd_port@@pub_htdocs_url_prefix@

Please remember to keep at least one safe backup of your private
key: if you'll lose it you'll not be able to read the crypted
messages you received so far.

Sincerily Yours, 
@ca_organization@ Security Staff.
