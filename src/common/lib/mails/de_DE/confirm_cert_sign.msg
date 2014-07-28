Sehr geehrte Nutzerin, sehr geehrter Nutzer,

Ihr Zertifikat mit der Seriennummer @__SERIAL__@ und dem Namen @__DN__@
ist erstellt worden. Sie können es nun von unserem Server herunterladen:

	@httpd_protocol@://@httpd_host@@httpd_port@

Bitte benutzen Sie dafür die Seriennummer. Sie können auch den folgenden Link
benutzen, um das Zertifikat direkt von unserem Server zu importieren:

@httpd_protocol@://@httpd_host@@httpd_port@@pub_cgi_url_prefix@/pki?cmd=getcert&key=@__SERIAL__@&type=CERTIFICATE

Bitte importieren Sie das CA-Zertifikat bzw. die Zertifizierungskette auch, um
die Korrektheit Ihres Zertifikates überprüfen zu können:

	@httpd_protocol@://@httpd_host@@httpd_port@@pub_htdocs_url_prefix@

Bitte beachten Sie, dass Sie mindestens eine Sicherheitskopie Ihres privaten
Schlüssels besitzen, wenn Sie Ihren Schlüssel in Software speichern. Wenn der
private Schlüssel verloren geht, sind sie nicht mehr in der Lage verschlüsselte
Daten zu entschlüsseln.


Mit freundlichen Grüßen

Ihr @ca_organization@ PKI-Team
