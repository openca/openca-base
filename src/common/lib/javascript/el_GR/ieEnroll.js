<!--//

      function InstallCertIE (form)
      {
        // Explorer Installation
  
  
        if (form.cert.value == "") {
           document.all.result.innerText = "Δεν βρέθηκε πιστοποιητικό";
           return false;
        }
   
        try {
          certHelperOld.acceptPKCS7(form.cert.value);
        }
        catch(e) {
          try {
            certHelperNew.acceptPKCS7(form.cert.value);
          } catch (e) {
            document.all.result.innerText = "Σφάλμα εγκατάστασης ή το πιστοποιητικό είναι ήδη εγκατεστημένο";
            return false;
          }
        }
        document.all.result.innerText = "Το πιστοποιητικό εγκαταστάθηκε";
      }

//-->
