Αγαπητέ χρήστη @USER@,

μπορείτε να  κατεβάσετε το πιστοποιητικό σας  από το  URI:

	@httpd_protocol@://@httpd_host@@httpd_port@

Παρακαλούμε χρησιμοποιήστε τον Α/Α που αναγράφεται στο θέμα (subject) του μηνύματος αυτού.
Μπορείτε επίσης να εισάγετε το πιστοποιητικό στον browser σας αυτόματα αν επισκεφτείτε:

@httpd_protocol@://@httpd_host@@httpd_port@@pub_cgi_url_prefix@/pki?cmd=getcert&key=@SERIAL@&type=CERTIFICATE

Παρακαλούμε εισάγετε το πιστοποιητικό της Α.Π. για να ελέγξετε την εγκυρότητα του πιστοποιητικού σας:

	@httpd_protocol@://@httpd_host@@httpd_port@@pub_htdocs_url_prefix@

Παρακαλούμε να κρατήσετε ένα ασφαλές αντίγραφο του προσωπικού σας κλειδιού. Σε περίπτωση απώλειας του δεν μπορεί να ανακτηθεί.

Τέλος σας ενημερώνουμε ότι μπορείτε να προσθέσετε τον εξυπηρετητή καταλόγου LDAP server στον browser σας. Η διεύθυνση του είναι

	ldap://@ldap_host@:@ldap_port@/@ca_organization@,@ca_country@

Αν χρησιμοποιείτε Netscape, ανοίγετε το address book, και προσθέτετε νέο εξυπηρετητή καταλόγου (new Directory)
με παραμέτρους:

	Περιγραφή: @ca_organization@ εξυπηρετητής LDAP 
	LDAP Server: @ldap_host@
	LDAP Port  : @ldap_port@
	Dir Root   : o=@ca_organization@, c=@ca_country@



Ευχαριστούμε πολύ, 
Υπηρεσία Αρχής Πιστοποίησης @ca_organization@ .


