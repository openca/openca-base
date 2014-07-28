<!--//

      function InstallCertIE (form)
      {
        // Explorer Installation
  
  
        if (form.cert.value == "") {
           document.all.result.innerText = "Сертификат не найден";
           return false;
        }
   
        try {
          certHelperOld.acceptPKCS7(form.cert.value);
        }
        catch(e) {
          try {
            certHelperNew.acceptPKCS7(form.cert.value);
          } catch (e) {
            document.all.result.innerText = "Ошибка установки сертификата (это может быть вызвано в том числе и тем, что сертификат уже установлен)";
            return false;
          }
        }
        document.all.result.innerText = "Сертификат установлен";
      }

//-->

