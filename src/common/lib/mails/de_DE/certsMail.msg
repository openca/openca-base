Sehr geehrte(r) @USER@,

Sie können Ihr beantragtes Zertifikat nun von unserem Server herunterladen.
Unser Server hat die folgende Adresse:

	@httpd_protocol@://@httpd_host@@httpd_port@

Bitte benutzen Sie die Seriennummer, welche Sie im Betreff dieser E-Mail
finden können. Sie können auch den im Folgenden angegebenen Link benutzen,
um das Zertifikat direkt vom Server zu installieren:

@httpd_protocol@://@httpd_host@@httpd_port@@pub_cgi_url_prefix@/pki?cmd=getcert&key=@SERIAL@&type=CERTIFICATE

Bitte importieren Sie das CA-Zertifikat bzw. die gesamte Zertifikatskette
von unserem Server, um die Korrektheit des Zertifikates zu überprüfen:

	@httpd_protocol@://@httpd_host@@httpd_port@@pub_htdocs_url_prefix@

Bitte beachten Sie, dass Sie mindestens eine Sicherheitskopie Ihres privaten
Schlüssels besitzen, wenn Sie Ihren Schlüssel in Software speichern. Wenn der
private Schlüssel verloren geht, sind sie nicht mehr in der Lage verschlüsselte
Daten zu entschlüsseln.

Zum Schluss noch ein Hinweis bezüglich unseres LDAP-Servers. Bitte fügen Sie
unseren LDAP-Server zu der Liste ihrer bekannten Verzeichnisdienste in Ihrem
Addressbuch hinzu. Sie können den LDAP-Server unter folgender Adresse erreichen:

	ldap://@ldap_host@:@ldap_port@/@ca_organization@,@ca_country@

Zur Benutzung mit Mozilla und ähnlichen Browsern öffnen Sie bitte einfach Ihr
Adressbuch und fügen Sie einen neuen Verzeichnisdienst mit den folgenden
Parametern hinzu:

	Beschreibung:      @ca_organization@ LDAP-Server mit Zertifikaten
	LDAP-Server:       @ldap_host@
	LDAP-Port:         @ldap_port@
	Verzeichniswurzel: o=@ca_organization@, c=@ca_country@

Nun sind Sie in der Lage Nutzerzertifikate direkt mit der Suchmaske Ihres
Browsers mit nur einem Mausklick zu suchen.


Mit freundlichen Grüßen

Ihr @ca_organization@ PKI-Team
