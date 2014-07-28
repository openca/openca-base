Spoštovani,


Vaš certifikat s serijsko številko @__SERIAL__@ in DN @__DN__@ je bil generiran. Z našega strežnika ga lahko posnamete na sledečem naslovu:

	@httpd_protocol@://@httpd_host@@httpd_port@

Prosimo, uporabite serijsko številko, ki je navedena v zadevi (Subject) tega sporočila.

Lahko se pa povežete na sledečo povezavo in uvozite certifikat neposredno z našega strežnika (nobeno dejanje ni potrebno iz vaše strani):

@httpd_protocol@://@httpd_host@@httpd_port@@pub_cgi_url_prefix@/pki?cmd=getcert&key=@__SERIAL__@&type=CERTIFICATE

Uvozite tudi vrhovni CA certifikat (ali PKI verigo) z našega strežnika, da boste lahko preverila veljavnost vašega certifikata:

	@httpd_protocol@://@httpd_host@@httpd_port@@pub_htdocs_url_prefix@


Prosimo, da poskrbite za vsaj eno varno kopijo vašega zasebnega ključa: v slučaju da bo izgubljen, ne boste mogli dostopati do šifriranih sporoči ste jih ali pa jih še boste prejeli.


Lep pozdrav, 
@ca_organization@ varnostna ekipa.
