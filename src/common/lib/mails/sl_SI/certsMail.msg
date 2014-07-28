Spoštovani @USER@,

Zahtevani certifikat si lahko z našega strežnika naložite na naslovu:

	@httpd_protocol@://@httpd_host@@httpd_port@

Prosimo, uporabite serijsko številko, ki je navedena v zadevi (Subject) tega sporočila.

Lahko se pa povežete na sledečo povezavo in uvozite certifikat neposredno z našega strežnika (nobeno dejanje ni potrebno iz vaše strani):

@httpd_protocol@://@httpd_host@@httpd_port@@pub_cgi_url_prefix@/pki?cmd=getcert&key=@SERIAL@&type=CERTIFICATE


Uvozite tudi vrhovni CA certifikat (ali PKI verigo) z našega strežnika, da boste lahko preverila veljavnost vašega certifikata:

	@httpd_protocol@://@httpd_host@@httpd_port@@pub_htdocs_url_prefix@


Prosimo, da poskrbite za vsaj eno varno kopijo vašega zasebnega ključa: v slučaju da bo izgubljen, ne boste mogli dostopati do šifriranih sporočil, ki ste jih ali pa jih še boste prejeli.

Priporočamo vam tudi, da dodate naš LDAP strežnik v seznam vaešga brkljalnika. Dostopen je na sledečem naslovu:

	ldap://@ldap_host@:@ldap_port@/@ca_organization@,@ca_country@


Za uporabo iz brkljalnika Netscape, odprite adresar (address book), dodajte nov LDAP direktorij s sledečimi parametri:

	Description: @ca_organization@ LDAP Server with Certificates
	LDAP Server: @ldap_host@
	LDAP Port  : @ldap_port@
	Dir Root   : o=@ca_organization@, c=@ca_country@

Tako lahko iščete certifikate drugih uporabnikov, neposredno iz brkljalnika s samo enim pritiskom na miško.

				Lep pozdrav, 
				@ca_organization@ varnostna ekipa.



