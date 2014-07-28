<!--//

      function InstallCertIE (form)
      {
        // Explorer Installation
  
  
        if (form.cert.value == "") {
           document.all.result.innerText = "Ne najdem certifikata";
           return false;
        }
   
        try {
          certHelperOld.acceptPKCS7(form.cert.value);
        }
        catch(e) {
          try {
            certHelperNew.acceptPKCS7(form.cert.value);
          } catch (e) {
            document.all.result.innerText = "Inštalacijska napaka (to se lahko zgodi tudi če je certifikat že inštaliran)";
            return false;
          }
        }
        document.all.result.innerText = "Certifikat je inštaliran";
      }

//-->
