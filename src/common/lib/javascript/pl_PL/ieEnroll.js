<!--//

      function InstallCertIE (form)
      {
        // Explorer Installation
  
  
        if (form.cert.value == "") {
           document.all.result.innerText = "Nie znaleziono certyfikatu";
           return false;
        }
   
        try {
          certHelperOld.acceptPKCS7(form.cert.value);
        }
        catch(e) {
          try {
            certHelperNew.acceptPKCS7(form.cert.value);
          } catch (e) {
            document.all.result.innerText = "Przy próbie instalacji wystąpił błąd (sytuacja taka może też mieć miejsce jeśli certyfikat jest już zainstalowany)";
            return false;
          }
        }
        document.all.result.innerText = "Certyfikat został pomyślnie zainstalowany";
      }

//-->
