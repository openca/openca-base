Content-Type: multipart/alternative; boundary="----=OpenCA_Verify_Email_@$$@"

------=OpenCA_Verify_Email_@$$@
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 7bit

@ca_organization@

Follow this link to confirm your email address (@EMAIL@):

http://@httpd_host@@pub_cgi_url_prefix@@server@?cmd=verifyEmail;ser=@SERIAL@;tag=@CODE@

We ask you to confirm your email address before processing your request
in order to assure no one else but you can request a certificate for this
email address. You can have several email addresses, but one will need to
be confirmed at all times to use the system.

Thank you for using @ca_organization@!

--The @ca_organization@ Team


------=OpenCA_Verify_Email_@$$@
Content-Type: text/html; charset=UTF-8

<html>
<body>
<table border="0" width="550" cellpadding="0" cellspacing="0" 
   style="max-width:550px; border-top:4px solid #669; 
   font: 12px arial, sans-serif; margin: 0 auto;">
  <tr>
  <td>  
  <h1 style="color: #000; font: bold 23px arial; margin:5px 0;" >@ca_organization@</h1>
  <p>
Someone, probably you, requested a new Digital Identity at our Certification
Authority. If you want to continue, please follow this link to confirm your
email address:
</p>
<p style="padding: 15px;">
<a href="http://@httpd_host@@pub_cgi_url_prefix@@server@?cmd=verifyEmail;ser=@SERIAL@;tag=@CODE@">
@EMAIL@
</a>
</p>
<p>
We ask you to confirm your email address before processing your request
in order to assure no one else but you can request a certificate for this
email address. You can have several email addresses, but one will need to
be confirmed at all times to use the system.
</p>
<p>
Thank you for using @ca_organization@!
</p>
<p>
--The @ca_organization@ Team
</p>
</td>
</tr>
<tr>
<td>
<p style="margin-top: 10px auto; font: 10px arial, sans-serif; color: #999;">&#169; @YEAR@, @ca_organization@</p>
</tr>
</td>
</table>
</body>
</html>

------=OpenCA_Verify_Email_@$$@

