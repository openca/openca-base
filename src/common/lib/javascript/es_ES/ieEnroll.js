<!--//

      function InstallCertIE (form)
      {
        // Explorer Installation
  
  
        if (form.cert.value == "") {
           document.all.result.innerText = "No se encontr\xf3 el certificado";
           return false;
        }
   
        try {
          certHelperOld.acceptPKCS7(form.cert.value);
        }
        catch(e) {
          try {
            certHelperNew.acceptPKCS7(form.cert.value);
          } catch (e) {
            document.all.result.innerText = "Error de instalaci\xf3n (quiz\xe1 ya estaba instalado el certificado)";
            return false;
          }
        }
        document.all.result.innerText = "Certificado instalado";
      }

//-->
