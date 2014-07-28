<!--//

      function InstallCertIE (form)
      {
        // Explorer Installation
  
  
        if (form.cert.value == "") {
           document.all.result.innerText = "Es ist kein Zertifikat vorhanden, welches instaliert werden k\u00f6nnte";
           return false;
        }
   
        try {
          certHelperOld.acceptPKCS7(form.cert.value);
        }
        catch(e) {
          try {
            certHelperNew.acceptPKCS7(form.cert.value);
          } catch (e) {
            document.all.result.innerText = "Es ist ein Fehler bei der Installation aufgetreten. (Die Installation scheitert auch, wenn das Zertifikat bereits vorhanden ist.)";
            return false;
          }
        }
        document.all.result.innerText = "Das Zertifikat wurde erfolgreich installiert.";
      }

//-->
