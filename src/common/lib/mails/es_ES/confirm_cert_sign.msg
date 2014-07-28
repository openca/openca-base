
Apreciado Cliente,

Su certificado con el numero serial @__SERIAL__@ y el DN @__DN__@ fue
generado. Ud. puede descargarlo desde nuestro servidor en la direccion: 

	@httpd_protocol@://@httpd_host@@httpd_port@

Por favor use el numero serial. Ud. puede tambien seguir el vinculo para
importar el certificado directamente del servidor (no accion adicional requerida):

@httpd_protocol@://@httpd_host@@httpd_port@@pub_cgi_url_prefix@/pki?cmd=getcert&key=@__SERIAL__@&type=CERTIFICATE

Por favor, importe el certificado de la CA (o de la cadena PKI) de nuestro
servidor para probar la validez de su certificado:

	@httpd_protocol@://@httpd_host@@httpd_port@@pub_htdocs_url_prefix@

Por favor recuerde mantener al menos un respaldo seguro de su llave privada:
si Ud. llega a perderla no va ser posible leer los mensajes cifrados
que ha recibido.


Cordial Saludo, 
@ca_organization@ Security Staff.
