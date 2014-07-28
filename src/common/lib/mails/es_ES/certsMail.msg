

Apreciado @USER@,

Ud. puede descargar el certificado solicitado desde nuestro servidor en la
direccion:

	@httpd_protocol@://@httpd_host@@httpd_port@

por favor use el numero serial incluido en el asunto de este correo.
Ud. puede tambien seguir el vinculo para importar el certificado
directamente desde el servidor (ninguna accion adicional se requiere): 

@httpd_protocol@://@httpd_host@@httpd_port@@pub_cgi_url_prefix@/pki?cmd=getcert&key=@SERIAL@&type=CERTIFICATE

Por vavor, importe el certificaod de la (o de la cadena de PKI) de nuestro
servidor para revisar la validez de su certificado:

	@httpd_protocol@://@httpd_host@@httpd_port@@pub_htdocs_url_prefix@

Por favor recuerde mantener al menos un respaldo seguro de su llave
privada: Si Ud. la pierde, no va a poder leer los mensajes cifrados
que recibe.

Adicionalmnete, adicione el servidor LDAP de nuestra organizacion
a lista de su navegador. Ud. puede encontralo en la siguiente direccion:

	ldap://@ldap_host@:@ldap_port@/@ca_organization@,@ca_country@

Para usarlo desde Firefox, solamente abra la libreta de direciones y agregue
un nuevo Directorio usando los siguientes parametros:

	Description: @ca_organization@ LDAP Server with Certificates
	LDAP Server: @ldap_host@
	LDAP Port  : @ldap_port@
	Dir Root   : o=@ca_organization@, c=@ca_country@

Ahora Ud. puede buscar directamente los certificados de usuarios usando
la habilidad nativa de Netscape con un click.



				Cordial Saludo, 
				@ca_organization@ Security Staff.


