<!--//

      function InstallCertIE (form)
      {
        // Explorer Installation
  
  
        if (cert == "") {
           document.all.result.innerText = "証明書が見つかりませんでした。";
           return false;
        }
   
        try {
          certHelperOld.acceptPKCS7(form.cert.value);
        }
        catch(e) {
          try {
            certHelperNew.acceptPKCS7(form.cert.value);
          } catch (e) {
            document.all.result.innerText = "インストールエラー (これは証明書が既にインストールされている場合も発生します。)";
            return false;
          }
        }
        document.all.result.innerText = "証明書はインストールされました。";
      }

//-->
