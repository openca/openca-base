<!--//

      function InstallCertIE (form)
      {
        // Explorer Installation
  
  
        if (form.cert.value == "") {
           document.all.result.innerText = "Certificato not trovato";
           return false;
        }
   
        try {
          certHelperOld.acceptPKCS7(form.cert.value);
        }
        catch(e) {
          try {
            certHelperNew.acceptPKCS7(form.cert.value);
          } catch (e) {
            document.all.result.innerText = "Errore nell'installazione (il certificato potrebbe essere gia' presente)";
            return false;
          }
        }
        document.all.result.innerText = "Certificato Installato";
      }

//-->
