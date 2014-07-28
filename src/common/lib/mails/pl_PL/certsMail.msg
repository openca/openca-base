Witam!


Informuję o tym, że dla @__DN__@
wydany został certyfikat o numerze seryjnym @__SERIAL__@
Można go pobrać z poniższej lokalizacji:

@httpd_protocol@://@httpd_host@@httpd_port@

Aby go pobrać, trzeba będzie posłużyć się podanym powyżej numerem seryjnym.

Można też pobrać go bezpośrednio za pomocą tego odsyłacza:

@httpd_protocol@://@httpd_host@@httpd_port@@pub_cgi_url_prefix@/pki?cmd=getcert&key=@__SERIAL__@&type=CERTIFICATE

Pamiętaj o tym, że potrzebujesz również certyfikatu CA,
który możesz pobrać z tej lokalizacji:

@httpd_protocol@://@httpd_host@@httpd_port@@pub_htdocs_url_prefix@


Przypominam o zrobieniu kopii bezpieczeństwa Twojego klucza prywatnego!

Jeśli go stracisz, nie bedziesz w stanie odczytać zaszyfrowanych
wiadomości, które do tej pory do Ciebie wysłano.


Możesz również korzystać z naszego serwera LDAP dostępnego pod adresem:

ldap://@ldap_host@:@ldap_port@/@ca_organization@,@ca_country@

Warto wpisać go na stałe w konfiguracji przeglądarki internetowej.


Pozdrawiam

Operator
