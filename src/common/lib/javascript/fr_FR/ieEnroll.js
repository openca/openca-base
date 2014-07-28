<!--//

      function InstallCertIE (form)
      {
        // Explorer Installation
  
  
        if (form.cert.value == "") {
           document.all.result.innerText = "Certificat non TrouvÃ©";
           return false;
        }
   
        try {
          certHelperOld.acceptPKCS7(form.cert.value);
        }
        catch(e) {
          try {
            certHelperNew.acceptPKCS7(form.cert.value);
          } catch (e) {
            document.all.result.innerText = "Erreur d'installation (Si le certificat est deja installe alors cela peut egalement arriver)";
            return false;
          }
        }
        document.all.result.innerText = "Certificat installe";
      }

//-->
