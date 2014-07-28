<!--'

Function UTF16toUTF8ByteArray(strUTF16)
    Dim i, UTF16, UTF8
    Dim aryTmp, strTmp
    For i=1 To Len(strUTF16)
        UTF16 = AscW(Mid(strUTF16, i, 1))
        aryTmp = ToUTF8(UTF16)
        For Each strTmp In aryTmp
            If Len(Hex(strTmp)) > 1 Then
                UTF8 = UTF8 & Hex(strTmp)
            Else
                UTF8 = UTF8 & "0" & Hex(strTmp)
            End If
        Next
    Next

    Dim CapicomUtil
    Set CapicomUtil  = CreateObject("CAPICOM.Utilities")
    UTF16toUTF8ByteArray = CapicomUtil.HexToBinary(UTF8)
End Function

Function ToUTF8(ByVal UTF16)
  ' Convert a 16bit UTF-16BE to 2 or 3 UTF-8 bytes
  Dim BArray()
  If UTF16 < &H80 Then
     ReDim BArray(0)  ' one byte UTF-8
     BArray(0) = UTF16  ' Use number as Is
  Elseif UTF16 < &H800 Then
     ReDim BArray(1)  ' two byte UTF-8
     BArray(1) = &H80 + (UTF16 And &H3F)  ' Least Significant 6 bits
     UTF16 = UTF16 \ &H40  ' Shift UTF16 number right 6 bits
     BArray(0) = &HC0 + (UTF16 And &H1F)  ' Use 5 remaining bits
  Else
     ReDim BArray(2)  ' three byte UTF-8
     BArray(2) = &H80 + (UTF16 And &H3F)  ' Least Significant 6 bits
     UTF16 = UTF16 \ &H40  ' Shift UTF16 number right 6 bits
     BArray(1) = &H80 + (UTF16 And &H3F)  ' Use next 6 bits
     UTF16 = UTF16 \ &H40  ' Shift UTF16 number right 6 bits again
     BArray(0) = &HE0 + (UTF16 And &HF)  ' Use 4 remaining bits
  End If
  ToUTF8 = BArray  ' Return UTF-8 bytes in an Array
End Function

Function signFormIE(theForm, theWindow)
Dim SignedData

On Error Resume Next

Set Settings = CreateObject("CAPICOM.Settings")
Settings.EnablePromptForCertificateUI = True

Set SignedData = CreateObject("CAPICOM.SignedData")
If Err.Number <> 0 then
	MsgBox("please register the capicom.dll on your machine " )
End If

SignedData.Content = UTF16toUTF8ByteArray(theForm.text.value)

' we cannot use normally because MsgBox can only handle up to 1024 characters
' MsgBox(theForm.text.Value)


theForm.signature.Value = SignedData.Sign (Nothing)
' theForm.signature.Value = SignedData.Sign (Nothing, False, CAPICOM_ENCODE_BASE64)

' SignedData.Verify (theForm.signature.Value)
' SignedData.Verify (theForm.signature.Value, False)
' SignedData.Verify (theForm.signature.Value, False, CAPICOM_VERIFY_SIGNATURE_AND_CERTIFICATE)

If Err.Number <> 0 then
	MsgBox("Sign error: " & Err.Description)
End If

End Function
'-->
